//! libsystem_malloc's zones: the `malloc_zone_t` interface, the registry of
//! zones, and the C allocation entry points that dispatch through it.
//!
//! On Darwin every block belongs to a zone, and `malloc` is not an allocator so
//! much as a call through the first zone in `malloc_zones`. `free` asks each
//! registered zone in turn whether it owns the pointer (`zone->size`) and hands
//! it to the one that says yes. Programs depend on that structure, not just on
//! `malloc` working: Chromium's PartitionAlloc registers a zone of its own and
//! shuffles the zone array until it is first, relying on
//! `malloc_zone_unregister` moving the *last* zone into the hole it leaves. So
//! the registry here follows libmalloc's `malloc.c` closely, down to that
//! detail, and the zones it starts with are this host's allocator dressed as
//! Darwin zones.
//!
//! ## Where the memory comes from
//!
//! This process's `malloc` is mimalloc (the runtime links it with `override`),
//! and the zones this module creates are mimalloc heaps:
//!
//! * the default zone, `DefaultMallocZone`, is mimalloc's main heap - the one
//!   the host's own `malloc` allocates from. A block this runtime's frameworks
//!   allocate with the host's `malloc` and hand to the guest is therefore one the
//!   default zone owns, and the guest's `free` finds it.
//! * `malloc_default_purgeable_zone` and every `malloc_create_zone` get a heap of
//!   their own, so that `malloc_zone_from_ptr` can tell their blocks apart and
//!   `malloc_destroy_zone` can release everything a zone holds at once.
//!
//! Ownership is `mi_heap_of(p)`, a page-map lookup that is defined for any
//! address. That is what makes `zone->size` safe to call on a pointer from
//! another allocator, which `free` does to every zone before the right one.
//!
//! ## Differences from libmalloc
//!
//! * A zone's `size` answers for any address inside a live mimalloc block, not
//!   only its first byte, and for a block already freed. libmalloc's scalable
//!   zone answers zero for both.
//! * The purgeable zone never discards memory. `malloc_make_purgeable` changes
//!   nothing, and `malloc_make_nonpurgeable` reports the contents intact, which
//!   is always true.
//! * The zones report version 13 (`try_free_default`, no typed callbacks). The
//!   typed entry points (`malloc_type_*`) ignore the type and take the untyped
//!   path, which is what libmalloc does for a zone older than 16.
//! * `enumerator` reports `KERN_FAILURE`: mimalloc cannot be walked from outside
//!   while other threads allocate.
//!
//! ## Guest zones
//!
//! A zone the guest registers is a structure of guest function pointers. In the
//! native backend those are host-callable machine code, entered with the
//! Darwin thread pointer (see [`crate::call_as_darwin`]). The emulated backend
//! cannot call them, and refuses `malloc_zone_register` before it reaches here.
#![cfg(not(target_os = "macos"))]

use core::ffi::{c_char, c_int, c_uint, c_void};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use libmimalloc_sys as mi;

// ---------------------------------------------------------------------------
// The ABI: `malloc_zone_t`, `malloc_introspection_t` and friends.
// ---------------------------------------------------------------------------

/// `boolean_t`: a 32-bit integer on both Darwin architectures.
pub type Boolean = c_int;
/// `kern_return_t`.
pub type KernReturn = c_int;
/// `task_t`, a Mach port name.
pub type Task = c_uint;
/// `malloc_type_id_t`.
pub type TypeId = u64;

const KERN_SUCCESS: KernReturn = 0;
const KERN_FAILURE: KernReturn = 5;

pub type SizeFn = unsafe extern "C" fn(*mut MallocZone, *const c_void) -> usize;
pub type MallocFn = unsafe extern "C" fn(*mut MallocZone, usize) -> *mut c_void;
pub type CallocFn = unsafe extern "C" fn(*mut MallocZone, usize, usize) -> *mut c_void;
pub type FreeFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void);
pub type ReallocFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void, usize) -> *mut c_void;
pub type DestroyFn = unsafe extern "C" fn(*mut MallocZone);
pub type BatchMallocFn =
    unsafe extern "C" fn(*mut MallocZone, usize, *mut *mut c_void, c_uint) -> c_uint;
pub type BatchFreeFn = unsafe extern "C" fn(*mut MallocZone, *mut *mut c_void, c_uint);
pub type MemalignFn = unsafe extern "C" fn(*mut MallocZone, usize, usize) -> *mut c_void;
pub type FreeDefiniteSizeFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void, usize);
pub type PressureReliefFn = unsafe extern "C" fn(*mut MallocZone, usize) -> usize;
pub type ClaimedAddressFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void) -> Boolean;
pub type MallocWithOptionsFn =
    unsafe extern "C" fn(*mut MallocZone, usize, usize, u64) -> *mut c_void;
pub type TypedMallocFn = unsafe extern "C" fn(*mut MallocZone, usize, TypeId) -> *mut c_void;
pub type TypedCallocFn = unsafe extern "C" fn(*mut MallocZone, usize, usize, TypeId) -> *mut c_void;
pub type TypedReallocFn =
    unsafe extern "C" fn(*mut MallocZone, *mut c_void, usize, TypeId) -> *mut c_void;
pub type TypedMemalignFn =
    unsafe extern "C" fn(*mut MallocZone, usize, usize, TypeId) -> *mut c_void;
pub type TypedMallocWithOptionsFn =
    unsafe extern "C" fn(*mut MallocZone, usize, usize, u64, TypeId) -> *mut c_void;

/// `malloc_zone_t`. Every field past `introspect` exists only from the
/// version noted beside it, and a guest's zone may simply end before it - so
/// those fields are read through [`MallocZone`]'s accessors, never directly.
#[repr(C)]
pub struct MallocZone {
    pub reserved1: *mut c_void,
    pub reserved2: *mut c_void,
    pub size: Option<SizeFn>,
    pub malloc: Option<MallocFn>,
    pub calloc: Option<CallocFn>,
    pub valloc: Option<MallocFn>,
    pub free: Option<FreeFn>,
    pub realloc: Option<ReallocFn>,
    pub destroy: Option<DestroyFn>,
    pub zone_name: *const c_char,
    pub batch_malloc: Option<BatchMallocFn>,
    pub batch_free: Option<BatchFreeFn>,
    pub introspect: *mut Introspection,
    pub version: c_uint,
    /// Version 5.
    pub memalign: Option<MemalignFn>,
    /// Version 6.
    pub free_definite_size: Option<FreeDefiniteSizeFn>,
    /// Version 8.
    pub pressure_relief: Option<PressureReliefFn>,
    /// Version 10.
    pub claimed_address: Option<ClaimedAddressFn>,
    /// Version 13.
    pub try_free_default: Option<FreeFn>,
    /// Version 15.
    pub malloc_with_options: Option<MallocWithOptionsFn>,
    /// Version 16, all five.
    pub malloc_type_malloc: Option<TypedMallocFn>,
    pub malloc_type_calloc: Option<TypedCallocFn>,
    pub malloc_type_realloc: Option<TypedReallocFn>,
    pub malloc_type_memalign: Option<TypedMemalignFn>,
    pub malloc_type_malloc_with_options: Option<TypedMallocWithOptionsFn>,
}

pub type MemoryReaderFn = unsafe extern "C" fn(Task, usize, usize, *mut *mut c_void) -> KernReturn;
pub type RangeRecorderFn = unsafe extern "C" fn(Task, *mut c_void, c_uint, *mut VmRange, c_uint);
pub type EnumeratorFn = unsafe extern "C" fn(
    Task,
    *mut c_void,
    c_uint,
    usize,
    Option<MemoryReaderFn>,
    Option<RangeRecorderFn>,
) -> KernReturn;
pub type GoodSizeFn = unsafe extern "C" fn(*mut MallocZone, usize) -> usize;
pub type CheckFn = unsafe extern "C" fn(*mut MallocZone) -> Boolean;
pub type PrintFn = unsafe extern "C" fn(*mut MallocZone, Boolean);
pub type LogFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void);
pub type LockFn = unsafe extern "C" fn(*mut MallocZone);
pub type StatisticsFn = unsafe extern "C" fn(*mut MallocZone, *mut Statistics);
pub type LockedFn = unsafe extern "C" fn(*mut MallocZone) -> Boolean;
pub type DischargeFn = unsafe extern "C" fn(*mut MallocZone, *mut c_void);
pub type PrintTaskFn =
    unsafe extern "C" fn(Task, c_uint, usize, Option<MemoryReaderFn>, *mut c_void);
pub type TaskStatisticsFn =
    unsafe extern "C" fn(Task, usize, Option<MemoryReaderFn>, *mut Statistics);

/// `malloc_introspection_t`, with the same versioning as [`MallocZone`]: the
/// zone's version says how much of it exists.
#[repr(C)]
pub struct Introspection {
    pub enumerator: Option<EnumeratorFn>,
    pub good_size: Option<GoodSizeFn>,
    pub check: Option<CheckFn>,
    pub print: Option<PrintFn>,
    pub log: Option<LogFn>,
    pub force_lock: Option<LockFn>,
    pub force_unlock: Option<LockFn>,
    pub statistics: Option<StatisticsFn>,
    pub zone_locked: Option<LockedFn>,
    /// Version 7, these four. The last takes a block, which is a pointer.
    pub enable_discharge_checking: Option<LockedFn>,
    pub disable_discharge_checking: Option<LockFn>,
    pub discharge: Option<DischargeFn>,
    pub enumerate_discharged_pointers: Option<DischargeFn>,
    /// Version 9.
    pub reinit_lock: Option<LockFn>,
    /// Version 11.
    pub print_task: Option<PrintTaskFn>,
    /// Version 12.
    pub task_statistics: Option<TaskStatisticsFn>,
    /// Version 14.
    pub zone_type: c_uint,
}

// SAFETY: the tables are immutable function pointers once built.
unsafe impl Sync for Introspection {}

/// `vm_range_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VmRange {
    pub address: usize,
    pub size: usize,
}

/// Darwin's `malloc_statistics_t`. Four fields, and the layout is ABI: a guest
/// reads `size_in_use` out of a structure it allocated on its own stack.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Statistics {
    pub blocks_in_use: u32,
    _pad: u32,
    pub size_in_use: usize,
    pub max_size_in_use: usize,
    pub size_allocated: usize,
}

/// `struct mstats`, returned by value.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Mstats {
    pub bytes_total: usize,
    pub chunks_used: usize,
    pub bytes_used: usize,
    pub chunks_free: usize,
    pub bytes_free: usize,
}

const _: () = {
    use std::mem::offset_of;
    assert!(size_of::<Statistics>() == 32);
    assert!(offset_of!(Statistics, size_in_use) == 8);
    assert!(offset_of!(MallocZone, zone_name) == 72);
    assert!(offset_of!(MallocZone, introspect) == 96);
    assert!(offset_of!(MallocZone, version) == 104);
    assert!(offset_of!(MallocZone, memalign) == 112);
    assert!(offset_of!(MallocZone, claimed_address) == 136);
    assert!(offset_of!(MallocZone, try_free_default) == 144);
    assert!(size_of::<MallocZone>() == 200);
    assert!(offset_of!(Introspection, statistics) == 56);
    assert!(offset_of!(Introspection, reinit_lock) == 104);
    assert!(offset_of!(Introspection, zone_type) == 128);
    assert!(size_of::<Mstats>() == 40);
};

/// A field of a zone that exists from `version` on, or `None` for a zone too
/// old to have it. The version is checked before the field is touched: such a
/// zone may end before the field.
macro_rules! since {
    ($zone:expr, $version:expr, $field:ident) => {{
        let zone = $zone;
        // SAFETY: the caller's live zone, read past `version` only when its
        // version says the field is there.
        unsafe {
            if (*zone).version < $version {
                None
            } else {
                (*zone).$field
            }
        }
    }};
}

impl MallocZone {
    unsafe fn memalign_fn(zone: *mut MallocZone) -> Option<MemalignFn> {
        since!(zone, 5, memalign)
    }

    unsafe fn free_definite_size_fn(zone: *mut MallocZone) -> Option<FreeDefiniteSizeFn> {
        since!(zone, 6, free_definite_size)
    }

    unsafe fn pressure_relief_fn(zone: *mut MallocZone) -> Option<PressureReliefFn> {
        since!(zone, 8, pressure_relief)
    }

    unsafe fn claimed_address_fn(zone: *mut MallocZone) -> Option<ClaimedAddressFn> {
        since!(zone, 10, claimed_address)
    }

    unsafe fn try_free_default_fn(zone: *mut MallocZone) -> Option<FreeFn> {
        since!(zone, 13, try_free_default)
    }

    unsafe fn malloc_with_options_fn(zone: *mut MallocZone) -> Option<MallocWithOptionsFn> {
        since!(zone, 15, malloc_with_options)
    }

    /// The introspection table, or `None` if the zone has none.
    unsafe fn introspect<'a>(zone: *mut MallocZone) -> Option<&'a Introspection> {
        // SAFETY: the caller's live zone; a non-null table lives as long.
        unsafe { (*zone).introspect.as_ref() }
    }

    /// An introspection field that exists from `version` on.
    unsafe fn introspect_since<T: Copy>(
        zone: *mut MallocZone,
        version: c_uint,
        field: impl FnOnce(&Introspection) -> Option<T>,
    ) -> Option<T> {
        unsafe {
            if (*zone).version < version {
                return None;
            }
            Self::introspect(zone).and_then(field)
        }
    }
}

/// Call a zone function the way a guest would, entering the Darwin thread
/// pointer first - unless it is one of this module's own, which needs no
/// entering and is the common case.
macro_rules! zone_call {
    ($f:expr, $ours:expr, ($($arg:expr),* $(,)?)) => {{
        let f = $f;
        if f as usize == $ours as *const () as usize {
            f($($arg),*)
        } else {
            crate::call_as_darwin!(f($($arg),*))
        }
    }};
    ($f:expr, ($($arg:expr),* $(,)?)) => {{
        let f = $f;
        crate::call_as_darwin!(f($($arg),*))
    }};
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

/// `MALLOC_ZONE_MALLOC_DEFAULT_ALIGN`: `sizeof(void *)`.
const DEFAULT_ALIGN: usize = size_of::<usize>();

/// The quantum every Darwin block is a multiple of and aligned to. mimalloc
/// already aligns everything above eight bytes to sixteen; the smallest
/// requests are raised to it.
const QUANTUM: usize = 16;

/// `MALLOC_ZONE_MALLOC_OPTION_CLEAR` and `MALLOC_ZONE_MALLOC_OPTION_CANONICAL_TAG`.
const OPTION_CLEAR: u64 = 1 << 0;
const OPTION_CANONICAL_TAG: u64 = 1 << 1;

/// `malloc_zone_options_t`: whether a failure sets `errno`, and C11's rule for
/// `aligned_alloc`.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Mzo(u32);
impl Mzo {
    const NONE: Mzo = Mzo(0);
    const POSIX: Mzo = Mzo(1);
    const C11: Mzo = Mzo(2);
    fn posix(self) -> bool {
        self.0 & Self::POSIX.0 != 0
    }
    fn c11(self) -> bool {
        self.0 & Self::C11.0 != 0
    }
}

const DEFAULT_ZONE_NAME: &std::ffi::CStr = c"DefaultMallocZone";
const PURGEABLE_ZONE_NAME: &std::ffi::CStr = c"DefaultPurgeableMallocZone";

/// The page size a guest is told (`vm_page_size`), which `valloc` aligns to.
fn page_size() -> usize {
    // SAFETY: a plain query.
    (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as usize
}

/// `malloc_absolute_max_size`: the largest request worth passing on.
fn absolute_max_size() -> usize {
    usize::MAX - 2 * page_size()
}

fn set_errno_if(mzo: Mzo, error: c_int) {
    if mzo.posix() {
        crate::errno::set(error);
    }
}

// ---------------------------------------------------------------------------
// mimalloc heaps.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // Present in the mimalloc this links (v3) but not in `libmimalloc-sys`'s
    // bindings.
    fn mi_heap_of(p: *const c_void) -> *mut mi::mi_heap_t;
    fn mi_heap_main() -> *mut mi::mi_heap_t;
}

/// mimalloc's main heap, the one the host's own `malloc` uses.
static MAIN_HEAP: AtomicPtr<mi::mi_heap_t> = AtomicPtr::new(std::ptr::null_mut());

fn main_heap() -> *mut mi::mi_heap_t {
    MAIN_HEAP.load(Ordering::Relaxed)
}

/// A request too small to be a Darwin block, raised to one.
fn quantum(size: usize) -> usize {
    size.max(QUANTUM)
}

/// Whether `heap` (null for the main heap) made the block at `ptr`.
fn heap_owns(heap: *mut mi::mi_heap_t, ptr: *const c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    // SAFETY: a page-map lookup, defined for any address.
    let of = unsafe { mi_heap_of(ptr) };
    !of.is_null() && of == if heap.is_null() { main_heap() } else { heap }
}

/// Whether any mimalloc heap made the block at `ptr`.
fn mimalloc_owns(ptr: *const c_void) -> bool {
    // SAFETY: as [`heap_owns`].
    !ptr.is_null() && !unsafe { mi_heap_of(ptr) }.is_null()
}

// ---------------------------------------------------------------------------
// The zones this module provides.
// ---------------------------------------------------------------------------

/// A zone backed by a mimalloc heap. `zone` is first, so a `*mut MallocZone`
/// this module handed out is a `*mut HostZone`.
#[repr(C)]
struct HostZone {
    zone: MallocZone,
    /// The heap, or null for mimalloc's main heap.
    heap: *mut mi::mi_heap_t,
    /// Whether the counters below are kept. Not for the default zone, where an
    /// atomic on every `malloc` and `free` of every thread costs more than the
    /// numbers are worth; its statistics come from mimalloc's own.
    counted: bool,
    blocks: AtomicUsize,
    bytes: AtomicUsize,
    peak: AtomicUsize,
}

impl HostZone {
    const fn new(name: *const c_char, counted: bool) -> HostZone {
        HostZone {
            zone: MallocZone {
                reserved1: std::ptr::null_mut(),
                reserved2: std::ptr::null_mut(),
                size: Some(host_size),
                malloc: Some(host_malloc),
                calloc: Some(host_calloc),
                valloc: Some(host_valloc),
                free: Some(host_free),
                realloc: Some(host_realloc),
                destroy: Some(host_destroy),
                zone_name: name,
                batch_malloc: Some(host_batch_malloc),
                batch_free: Some(host_batch_free),
                introspect: &raw const HOST_INTROSPECT as *mut Introspection,
                version: 13,
                memalign: Some(host_memalign),
                free_definite_size: Some(host_free_definite_size),
                pressure_relief: Some(host_pressure_relief),
                claimed_address: Some(host_claimed_address),
                try_free_default: Some(host_try_free_default),
                malloc_with_options: None,
                malloc_type_malloc: None,
                malloc_type_calloc: None,
                malloc_type_realloc: None,
                malloc_type_memalign: None,
                malloc_type_malloc_with_options: None,
            },
            heap: std::ptr::null_mut(),
            counted,
            blocks: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// # Safety
    ///
    /// `zone` is one of this module's zones - which is what calling one of the
    /// `host_*` functions through it already asserts.
    unsafe fn of<'a>(zone: *mut MallocZone) -> &'a HostZone {
        unsafe { &*zone.cast::<HostZone>() }
    }

    fn allocated(&self, block: *mut c_void) -> *mut c_void {
        if self.counted && !block.is_null() {
            // SAFETY: a live block mimalloc just returned.
            let size = unsafe { mi::mi_usable_size(block) };
            self.blocks.fetch_add(1, Ordering::Relaxed);
            let now = self.bytes.fetch_add(size, Ordering::Relaxed) + size;
            self.peak.fetch_max(now, Ordering::Relaxed);
        }
        block
    }

    /// Account for `block` leaving the zone, if it is this zone's.
    fn releasing(&self, block: *const c_void) {
        if self.counted && heap_owns(self.heap, block) {
            // SAFETY: a live mimalloc block, about to be freed.
            let size = unsafe { mi::mi_usable_size(block) };
            self.blocks.fetch_sub(1, Ordering::Relaxed);
            self.bytes.fetch_sub(size, Ordering::Relaxed);
        }
    }
}

static HOST_INTROSPECT: Introspection = Introspection {
    enumerator: Some(host_enumerator),
    good_size: Some(host_good_size),
    check: Some(host_check),
    print: Some(host_print),
    log: Some(host_log),
    force_lock: Some(host_lock),
    force_unlock: Some(host_lock),
    statistics: Some(host_statistics),
    zone_locked: Some(host_zone_locked),
    enable_discharge_checking: Some(host_enable_discharge_checking),
    disable_discharge_checking: Some(host_lock),
    discharge: Some(host_log),
    enumerate_discharged_pointers: None,
    reinit_lock: Some(host_lock),
    print_task: Some(host_print_task),
    task_statistics: Some(host_task_statistics),
    zone_type: 0,
};

/// `DefaultMallocZone`: mimalloc's main heap. Writable, as a guest may patch
/// it (Chromium's allocator shim replaces function pointers in place).
static mut DEFAULT_ZONE: HostZone = HostZone::new(DEFAULT_ZONE_NAME.as_ptr(), false);

/// `DefaultPurgeableMallocZone`, made on first use.
static mut PURGEABLE_ZONE: HostZone = HostZone::new(PURGEABLE_ZONE_NAME.as_ptr(), true);

fn default_host_zone() -> *mut MallocZone {
    (&raw mut DEFAULT_ZONE).cast()
}

unsafe fn host_heap(zone: *mut MallocZone) -> *mut mi::mi_heap_t {
    unsafe { HostZone::of(zone) }.heap
}

/// `size`: the block's usable size if this zone made it, else zero.
unsafe extern "C" fn host_size(zone: *mut MallocZone, ptr: *const c_void) -> usize {
    // SAFETY: the zone is one of ours; the lookup is defined for any address.
    unsafe {
        if heap_owns(host_heap(zone), ptr) {
            mi::mi_usable_size(ptr)
        } else {
            0
        }
    }
}

unsafe fn heap_malloc(heap: *mut mi::mi_heap_t, size: usize) -> *mut c_void {
    // SAFETY: mimalloc's allocation calls, with a heap this module made.
    unsafe {
        if heap.is_null() {
            mi::mi_malloc(quantum(size))
        } else {
            mi::mi_heap_malloc(heap, quantum(size))
        }
    }
}

unsafe fn heap_memalign(heap: *mut mi::mi_heap_t, alignment: usize, size: usize) -> *mut c_void {
    // SAFETY: as [`heap_malloc`].
    unsafe {
        if heap.is_null() {
            mi::mi_malloc_aligned(quantum(size), alignment)
        } else {
            mi::mi_heap_malloc_aligned(heap, quantum(size), alignment)
        }
    }
}

unsafe extern "C" fn host_malloc(zone: *mut MallocZone, size: usize) -> *mut c_void {
    let host = unsafe { HostZone::of(zone) };
    host.allocated(unsafe { heap_malloc(host.heap, size) })
}

unsafe extern "C" fn host_calloc(zone: *mut MallocZone, count: usize, size: usize) -> *mut c_void {
    let host = unsafe { HostZone::of(zone) };
    let Some(total) = count.checked_mul(size) else {
        crate::errno::set(libc::ENOMEM);
        return std::ptr::null_mut();
    };
    // SAFETY: mimalloc's zeroing allocations.
    let block = unsafe {
        if host.heap.is_null() {
            mi::mi_zalloc(quantum(total))
        } else {
            mi::mi_heap_zalloc(host.heap, quantum(total))
        }
    };
    host.allocated(block)
}

unsafe extern "C" fn host_valloc(zone: *mut MallocZone, size: usize) -> *mut c_void {
    let host = unsafe { HostZone::of(zone) };
    host.allocated(unsafe { heap_memalign(host.heap, page_size(), size) })
}

unsafe extern "C" fn host_memalign(
    zone: *mut MallocZone,
    alignment: usize,
    size: usize,
) -> *mut c_void {
    let host = unsafe { HostZone::of(zone) };
    if alignment <= QUANTUM {
        return host.allocated(unsafe { heap_malloc(host.heap, size) });
    }
    host.allocated(unsafe { heap_memalign(host.heap, alignment, size) })
}

/// `free`. A block of another mimalloc heap is freed all the same, which costs
/// nothing and is what a program that passes the wrong zone meant. One that is
/// not mimalloc's at all goes to the zone that owns it, rather than into
/// mimalloc's free list.
unsafe extern "C" fn host_free(zone: *mut MallocZone, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    if mimalloc_owns(ptr) {
        unsafe { HostZone::of(zone) }.releasing(ptr);
        // SAFETY: a live mimalloc block.
        unsafe { mi::mi_free(ptr) };
        return;
    }
    // SAFETY: an address no mimalloc heap owns, offered to the registry.
    unsafe { find_zone_and_free(ptr, false) };
}

unsafe extern "C" fn host_free_definite_size(zone: *mut MallocZone, ptr: *mut c_void, _: usize) {
    unsafe { host_free(zone, ptr) }
}

/// `try_free_default`: free `ptr` if it is the default zone's, and otherwise
/// look for its owner among the rest - the promise the field makes.
unsafe extern "C" fn host_try_free_default(zone: *mut MallocZone, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: our zone; a live block if the heap claims it.
    unsafe {
        let host = HostZone::of(zone);
        if heap_owns(host.heap, ptr) {
            host.releasing(ptr);
            mi::mi_free(ptr);
        } else {
            find_zone_and_free(ptr, true);
        }
    }
}

unsafe extern "C" fn host_realloc(
    zone: *mut MallocZone,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    let host = unsafe { HostZone::of(zone) };
    if ptr.is_null() {
        return unsafe { host_malloc(zone, size) };
    }
    if mimalloc_owns(ptr) {
        host.releasing(ptr);
        // SAFETY: a live mimalloc block, resized by mimalloc.
        let grown = unsafe {
            if host.heap.is_null() {
                mi::mi_realloc(ptr, quantum(size))
            } else {
                mi::mi_heap_realloc(host.heap, ptr, quantum(size))
            }
        };
        if grown.is_null() {
            // The old block is still live and still this zone's.
            host.allocated_again(ptr);
            return grown;
        }
        return host.allocated(grown);
    }
    // Another zone's block: move it into this one. libmalloc's scalable zone
    // would refuse; the caller asked for this zone, and the data survives.
    // SAFETY: the registry's answer for an address mimalloc does not own.
    unsafe {
        let (owner, old) = find_registered_zone(ptr, false);
        if owner.is_null() {
            report_not_allocated(ptr, "pointer being reallocated was not allocated");
            return std::ptr::null_mut();
        }
        let fresh = host_malloc(zone, size);
        if !fresh.is_null() {
            std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), fresh.cast::<u8>(), old.min(size));
            zone_free(owner, ptr);
        }
        fresh
    }
}

impl HostZone {
    /// [`HostZone::allocated`] for a block that never left.
    fn allocated_again(&self, block: *mut c_void) {
        if heap_owns(self.heap, block) {
            self.allocated(block);
        }
    }
}

unsafe extern "C" fn host_destroy(zone: *mut MallocZone) {
    // The default and purgeable zones live as long as the process; libmalloc's
    // would unmap everything the program has, which nothing survives.
    if zone == default_host_zone() || zone == (&raw mut PURGEABLE_ZONE).cast() {
        return;
    }
    // SAFETY: a zone `malloc_create_zone` boxed, destroyed once, by contract.
    unsafe {
        let host = Box::from_raw(zone.cast::<HostZone>());
        mi::mi_heap_destroy(host.heap);
    }
}

unsafe extern "C" fn host_batch_malloc(
    zone: *mut MallocZone,
    size: usize,
    results: *mut *mut c_void,
    count: c_uint,
) -> c_uint {
    let mut made = 0;
    while made < count {
        let block = unsafe { host_malloc(zone, size) };
        if block.is_null() {
            break;
        }
        // SAFETY: the caller's array of `count` slots.
        unsafe { *results.add(made as usize) = block };
        made += 1;
    }
    made
}

unsafe extern "C" fn host_batch_free(
    zone: *mut MallocZone,
    blocks: *mut *mut c_void,
    count: c_uint,
) {
    for i in 0..count as usize {
        // SAFETY: the caller's array of `count` blocks.
        unsafe { host_free(zone, *blocks.add(i)) };
    }
}

unsafe extern "C" fn host_pressure_relief(zone: *mut MallocZone, _goal: usize) -> usize {
    // SAFETY: our zone's heap, collected; mimalloc does not say how much.
    unsafe {
        let heap = host_heap(zone);
        if heap.is_null() {
            mi::mi_collect(true);
        } else {
            mi::mi_heap_collect(heap, true);
        }
    }
    0
}

unsafe extern "C" fn host_claimed_address(zone: *mut MallocZone, ptr: *mut c_void) -> Boolean {
    heap_owns(unsafe { host_heap(zone) }, ptr) as Boolean
}

unsafe extern "C" fn host_enumerator(
    _task: Task,
    _context: *mut c_void,
    _type_mask: c_uint,
    _zone: usize,
    _reader: Option<MemoryReaderFn>,
    _recorder: Option<RangeRecorderFn>,
) -> KernReturn {
    KERN_FAILURE
}

unsafe extern "C" fn host_good_size(_zone: *mut MallocZone, size: usize) -> usize {
    // SAFETY: a pure size computation.
    unsafe { mi::mi_good_size(quantum(size)) }
}

unsafe extern "C" fn host_check(_zone: *mut MallocZone) -> Boolean {
    1
}

unsafe extern "C" fn host_print(zone: *mut MallocZone, _verbose: Boolean) {
    let mut stats = Statistics::default();
    unsafe { host_statistics(zone, &mut stats) };
    let name = unsafe { zone_name_lossy(zone) };
    write_fd(
        2,
        &format!(
            "{name} zone {zone:p}: mimalloc heap {:p}; {} bytes in use, {} allocated\n",
            unsafe { host_heap(zone) },
            stats.size_in_use,
            stats.size_allocated
        ),
    );
}

unsafe extern "C" fn host_log(_zone: *mut MallocZone, _address: *mut c_void) {}

/// `force_lock`, `force_unlock`, `reinit_lock`, `disable_discharge_checking`:
/// these zones hold no lock of their own across calls.
unsafe extern "C" fn host_lock(_zone: *mut MallocZone) {}

unsafe extern "C" fn host_zone_locked(_zone: *mut MallocZone) -> Boolean {
    0
}

unsafe extern "C" fn host_enable_discharge_checking(_zone: *mut MallocZone) -> Boolean {
    0
}

/// `statistics`. A counted zone reports what passed through it. The default
/// zone reports mimalloc's committed memory for both the in-use and the
/// allocated figure - an upper bound on what is in use, since mimalloc keeps
/// no live total in a release build - and no block count.
unsafe extern "C" fn host_statistics(zone: *mut MallocZone, stats: *mut Statistics) {
    if stats.is_null() {
        return;
    }
    let host = unsafe { HostZone::of(zone) };
    let out = if host.counted {
        let bytes = host.bytes.load(Ordering::Relaxed);
        Statistics {
            blocks_in_use: host.blocks.load(Ordering::Relaxed) as u32,
            _pad: 0,
            size_in_use: bytes,
            max_size_in_use: host.peak.load(Ordering::Relaxed),
            size_allocated: bytes,
        }
    } else {
        let (mut commit, mut peak_commit, mut unused) = (0usize, 0usize, 0usize);
        let (mut a, mut b, mut c, mut d) = (0usize, 0usize, 0usize, 0usize);
        // SAFETY: eight writable `size_t`s.
        unsafe {
            mi::mi_process_info(
                &mut a,
                &mut b,
                &mut c,
                &mut d,
                &mut unused,
                &mut commit,
                &mut peak_commit,
                &mut unused,
            )
        };
        Statistics {
            blocks_in_use: 0,
            _pad: 0,
            size_in_use: commit,
            max_size_in_use: peak_commit,
            size_allocated: commit,
        }
    };
    // SAFETY: the caller's writable structure.
    unsafe { *stats = out };
}

unsafe extern "C" fn host_print_task(
    _task: Task,
    _level: c_uint,
    zone: usize,
    _reader: Option<MemoryReaderFn>,
    _printer: *mut c_void,
) {
    unsafe { host_print(zone as *mut MallocZone, 0) }
}

/// `task_statistics`, for this task: the zone's address is a local one.
unsafe extern "C" fn host_task_statistics(
    _task: Task,
    zone: usize,
    _reader: Option<MemoryReaderFn>,
    stats: *mut Statistics,
) {
    unsafe { host_statistics(zone as *mut MallocZone, stats) }
}

// ---------------------------------------------------------------------------
// The virtual default zone: what `malloc_default_zone` returns.
// ---------------------------------------------------------------------------

/// libmalloc's `virtual_default_zone`. Every call goes to whichever zone is
/// first in the array *now*, so a program that holds the default zone keeps
/// allocating from the default after another zone is put in front.
static mut VIRTUAL_ZONE: MallocZone = MallocZone {
    reserved1: std::ptr::null_mut(),
    reserved2: std::ptr::null_mut(),
    size: Some(virtual_size),
    malloc: Some(virtual_malloc),
    calloc: Some(virtual_calloc),
    valloc: Some(virtual_valloc),
    free: Some(virtual_free),
    realloc: Some(virtual_realloc),
    destroy: Some(virtual_destroy),
    zone_name: DEFAULT_ZONE_NAME.as_ptr(),
    batch_malloc: Some(virtual_batch_malloc),
    batch_free: Some(virtual_batch_free),
    introspect: &raw const VIRTUAL_INTROSPECT as *mut Introspection,
    version: 10,
    memalign: Some(virtual_memalign),
    free_definite_size: Some(virtual_free_definite_size),
    pressure_relief: Some(virtual_pressure_relief),
    claimed_address: Some(virtual_claimed_address),
    try_free_default: None,
    malloc_with_options: None,
    malloc_type_malloc: None,
    malloc_type_calloc: None,
    malloc_type_realloc: None,
    malloc_type_memalign: None,
    malloc_type_malloc_with_options: None,
};

static VIRTUAL_INTROSPECT: Introspection = Introspection {
    enumerator: Some(virtual_enumerator),
    good_size: Some(virtual_good_size),
    check: Some(virtual_check),
    print: Some(virtual_print),
    log: Some(virtual_log),
    force_lock: Some(virtual_force_lock),
    force_unlock: Some(virtual_force_unlock),
    statistics: Some(virtual_statistics),
    zone_locked: Some(virtual_zone_locked),
    enable_discharge_checking: None,
    disable_discharge_checking: None,
    discharge: None,
    enumerate_discharged_pointers: None,
    reinit_lock: Some(virtual_reinit_lock),
    print_task: None,
    task_statistics: None,
    zone_type: 0,
};

fn virtual_zone() -> *mut MallocZone {
    &raw mut VIRTUAL_ZONE
}

/// The virtual zone resolved to the zone it stands for; any other unchanged.
/// Null - which libmalloc would crash on - is taken as the default too.
fn resolve(zone: *mut MallocZone) -> *mut MallocZone {
    if zone.is_null() || zone == virtual_zone() {
        zone0()
    } else {
        zone
    }
}

unsafe extern "C" fn virtual_size(_: *mut MallocZone, ptr: *const c_void) -> usize {
    unsafe { zone_size(zone0(), ptr) }
}

unsafe extern "C" fn virtual_malloc(_: *mut MallocZone, size: usize) -> *mut c_void {
    let zone = zone0();
    match unsafe { (*zone).malloc } {
        Some(f) => unsafe { zone_call!(f, host_malloc, (zone, size)) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn virtual_calloc(_: *mut MallocZone, count: usize, size: usize) -> *mut c_void {
    let zone = zone0();
    match unsafe { (*zone).calloc } {
        Some(f) => unsafe { zone_call!(f, host_calloc, (zone, count, size)) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn virtual_valloc(_: *mut MallocZone, size: usize) -> *mut c_void {
    let zone = zone0();
    match unsafe { (*zone).valloc } {
        Some(f) => unsafe { zone_call!(f, host_valloc, (zone, size)) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn virtual_free(_: *mut MallocZone, ptr: *mut c_void) {
    unsafe { zone_free(zone0(), ptr) }
}

unsafe extern "C" fn virtual_realloc(
    _: *mut MallocZone,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    let zone = zone0();
    match unsafe { (*zone).realloc } {
        Some(f) => unsafe { zone_call!(f, host_realloc, (zone, ptr, size)) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn virtual_destroy(_: *mut MallocZone) {
    let zone = zone0();
    if let Some(f) = unsafe { (*zone).destroy } {
        unsafe { zone_call!(f, host_destroy, (zone)) }
    }
}

unsafe extern "C" fn virtual_batch_malloc(
    _: *mut MallocZone,
    size: usize,
    results: *mut *mut c_void,
    count: c_uint,
) -> c_uint {
    unsafe { malloc_zone_batch_malloc(zone0(), size, results, count) }
}

unsafe extern "C" fn virtual_batch_free(
    _: *mut MallocZone,
    blocks: *mut *mut c_void,
    count: c_uint,
) {
    unsafe { malloc_zone_batch_free(zone0(), blocks, count) }
}

unsafe extern "C" fn virtual_memalign(
    _: *mut MallocZone,
    alignment: usize,
    size: usize,
) -> *mut c_void {
    let zone = zone0();
    match unsafe { MallocZone::memalign_fn(zone) } {
        Some(f) => unsafe { zone_call!(f, host_memalign, (zone, alignment, size)) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn virtual_free_definite_size(_: *mut MallocZone, ptr: *mut c_void, size: usize) {
    unsafe { zone_free_definite_size(zone0(), ptr, size) }
}

unsafe extern "C" fn virtual_pressure_relief(_: *mut MallocZone, goal: usize) -> usize {
    unsafe { malloc_zone_pressure_relief(zone0(), goal) }
}

unsafe extern "C" fn virtual_claimed_address(_: *mut MallocZone, ptr: *mut c_void) -> Boolean {
    unsafe { malloc_zone_claimed_address(zone0(), ptr) }
}

unsafe extern "C" fn virtual_enumerator(
    task: Task,
    context: *mut c_void,
    type_mask: c_uint,
    _zone: usize,
    reader: Option<MemoryReaderFn>,
    recorder: Option<RangeRecorderFn>,
) -> KernReturn {
    let zone = zone0();
    match unsafe { MallocZone::introspect(zone) }.and_then(|i| i.enumerator) {
        Some(f) => unsafe {
            zone_call!(
                f,
                host_enumerator,
                (task, context, type_mask, zone as usize, reader, recorder)
            )
        },
        None => KERN_FAILURE,
    }
}

unsafe extern "C" fn virtual_good_size(_: *mut MallocZone, size: usize) -> usize {
    unsafe { zone_good_size(zone0(), size) }
}

unsafe extern "C" fn virtual_check(_: *mut MallocZone) -> Boolean {
    unsafe { zone_check(zone0()) }
}

unsafe extern "C" fn virtual_print(_: *mut MallocZone, verbose: Boolean) {
    unsafe { zone_print(zone0(), verbose) }
}

unsafe extern "C" fn virtual_log(_: *mut MallocZone, address: *mut c_void) {
    unsafe { zone_log(zone0(), address) }
}

unsafe extern "C" fn virtual_force_lock(_: *mut MallocZone) {
    unsafe { zone_force_lock(zone0()) }
}

unsafe extern "C" fn virtual_force_unlock(_: *mut MallocZone) {
    unsafe { zone_force_unlock(zone0()) }
}

unsafe extern "C" fn virtual_statistics(_: *mut MallocZone, stats: *mut Statistics) {
    unsafe { zone_statistics(zone0(), stats) }
}

unsafe extern "C" fn virtual_zone_locked(_: *mut MallocZone) -> Boolean {
    let zone = zone0();
    match unsafe { MallocZone::introspect(zone) }.and_then(|i| i.zone_locked) {
        Some(f) => unsafe { zone_call!(f, host_zone_locked, (zone)) },
        None => 0,
    }
}

unsafe extern "C" fn virtual_reinit_lock(_: *mut MallocZone) {
    unsafe { zone_reinit_lock(zone0()) }
}

// ---------------------------------------------------------------------------
// Calls into any zone, with libmalloc's version guards.
// ---------------------------------------------------------------------------

unsafe fn zone_size(zone: *mut MallocZone, ptr: *const c_void) -> usize {
    match unsafe { (*zone).size } {
        Some(f) => unsafe { zone_call!(f, host_size, (zone, ptr)) },
        None => 0,
    }
}

unsafe fn zone_free(zone: *mut MallocZone, ptr: *mut c_void) {
    if let Some(f) = unsafe { (*zone).free } {
        unsafe { zone_call!(f, host_free, (zone, ptr)) }
    }
}

unsafe fn zone_free_definite_size(zone: *mut MallocZone, ptr: *mut c_void, size: usize) {
    match unsafe { MallocZone::free_definite_size_fn(zone) } {
        Some(f) => unsafe { zone_call!(f, host_free_definite_size, (zone, ptr, size)) },
        None => unsafe { zone_free(zone, ptr) },
    }
}

unsafe fn zone_good_size(zone: *mut MallocZone, size: usize) -> usize {
    match unsafe { MallocZone::introspect(zone) }.and_then(|i| i.good_size) {
        Some(f) => unsafe { zone_call!(f, host_good_size, (zone, size)) },
        None => size,
    }
}

unsafe fn zone_check(zone: *mut MallocZone) -> Boolean {
    match unsafe { MallocZone::introspect(zone) }.and_then(|i| i.check) {
        Some(f) => unsafe { zone_call!(f, host_check, (zone)) },
        None => 1,
    }
}

unsafe fn zone_print(zone: *mut MallocZone, verbose: Boolean) {
    if let Some(f) = unsafe { MallocZone::introspect(zone) }.and_then(|i| i.print) {
        unsafe { zone_call!(f, host_print, (zone, verbose)) }
    }
}

unsafe fn zone_log(zone: *mut MallocZone, address: *mut c_void) {
    if let Some(f) = unsafe { MallocZone::introspect(zone) }.and_then(|i| i.log) {
        unsafe { zone_call!(f, host_log, (zone, address)) }
    }
}

unsafe fn zone_force_lock(zone: *mut MallocZone) {
    if let Some(f) = unsafe { MallocZone::introspect(zone) }.and_then(|i| i.force_lock) {
        unsafe { zone_call!(f, host_lock, (zone)) }
    }
}

unsafe fn zone_force_unlock(zone: *mut MallocZone) {
    if let Some(f) = unsafe { MallocZone::introspect(zone) }.and_then(|i| i.force_unlock) {
        unsafe { zone_call!(f, host_lock, (zone)) }
    }
}

/// `reinit_lock` from version 9, `force_unlock` before it - as libmalloc's
/// fork child handler chooses.
unsafe fn zone_reinit_lock(zone: *mut MallocZone) {
    match unsafe { MallocZone::introspect_since(zone, 9, |i| i.reinit_lock) } {
        Some(f) => unsafe { zone_call!(f, host_lock, (zone)) },
        None => unsafe { zone_force_unlock(zone) },
    }
}

unsafe fn zone_statistics(zone: *mut MallocZone, stats: *mut Statistics) {
    match unsafe { MallocZone::introspect(zone) }.and_then(|i| i.statistics) {
        Some(f) => unsafe { zone_call!(f, host_statistics, (zone, stats)) },
        None => unsafe { *stats = Statistics::default() },
    }
}

unsafe fn zone_name_lossy(zone: *mut MallocZone) -> String {
    let name = unsafe { (*zone).zone_name };
    if name.is_null() {
        return "(unnamed)".into();
    }
    // SAFETY: a zone's name is a C string.
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------------

/// libmalloc's `MALLOC_LOCK`. A flag rather than a `Mutex` so that the fork
/// handlers can hold it across `fork` and the child can simply clear it.
struct RegistryLock(AtomicBool);

impl RegistryLock {
    fn lock(&self) -> RegistryGuard<'_> {
        self.acquire();
        RegistryGuard(self)
    }
    fn acquire(&self) {
        while self
            .0
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
    }
    fn release(&self) {
        self.0.store(false, Ordering::Release);
    }
}

struct RegistryGuard<'a>(&'a RegistryLock);

impl Drop for RegistryGuard<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

static LOCK: RegistryLock = RegistryLock(AtomicBool::new(false));

/// `malloc_zones`: a page-granular array of zone pointers, read-only except
/// while the lock holder changes it. Replaced arrays are leaked, so a reader
/// that loaded the old pointer keeps reading valid memory.
static ZONES: AtomicPtr<*mut MallocZone> = AtomicPtr::new(std::ptr::null_mut());
/// `malloc_num_zones`.
static NUM_ZONES: AtomicU32 = AtomicU32::new(0);
/// `malloc_num_zones_allocated`, written under the lock.
static ALLOCATED: AtomicU32 = AtomicU32::new(0);
/// `initial_num_zones`: the zones a lookup checks without the drain counters.
static INITIAL_NUM_ZONES: AtomicU32 = AtomicU32::new(0);
/// libmalloc's two FRZ counters and which one is live. A lookup past the
/// initial zones counts itself in on the live one; `malloc_zone_unregister`
/// swaps them and waits for the old one to drain, so that a zone it removed is
/// not in use by anyone when it returns.
static FRZ: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static FRZ_LIVE: AtomicUsize = AtomicUsize::new(0);

static INIT: Once = Once::new();

/// Register the default zone, as libmalloc does while libSystem initialises.
///
/// Also installs the fork handlers. libSystem's `fork` runs malloc's prepare
/// handler after every other one and its child handler before them, so that a
/// `pthread_atfork` handler may still allocate; registering ours ahead of the
/// guest's gives the same order, since prepare handlers run in reverse.
pub fn init() {
    INIT.call_once(|| {
        // SAFETY: mimalloc's own heap, which exists from its first use.
        MAIN_HEAP.store(unsafe { mi_heap_main() }, Ordering::Relaxed);
        {
            let _held = LOCK.lock();
            // SAFETY: the lock is held and the default zone lives forever.
            unsafe { register_while_locked(default_host_zone(), false) };
            INITIAL_NUM_ZONES.store(NUM_ZONES.load(Ordering::Relaxed), Ordering::Release);
        }
        // SAFETY: three `void (void)` functions that live forever.
        unsafe {
            libc::pthread_atfork(
                Some(_malloc_fork_prepare as unsafe extern "C" fn()),
                Some(_malloc_fork_parent as unsafe extern "C" fn()),
                Some(_malloc_fork_child as unsafe extern "C" fn()),
            )
        };
    });
}

/// The array and how many of its entries are live.
fn zones() -> (*const *mut MallocZone, u32) {
    init();
    (
        ZONES.load(Ordering::Acquire),
        NUM_ZONES.load(Ordering::Acquire),
    )
}

/// `malloc_zones[0]`, the zone `malloc` allocates from.
fn zone0() -> *mut MallocZone {
    let (zones, count) = zones();
    if count == 0 {
        // Every zone has been unregistered. libmalloc would read a stale slot;
        // the default zone is the one answer that cannot fault.
        return default_host_zone();
    }
    // SAFETY: a live array with at least one entry.
    unsafe { *zones }
}

/// Every registered zone, as of now.
fn snapshot() -> Vec<*mut MallocZone> {
    let (zones, count) = zones();
    // SAFETY: `count` live entries of a live array.
    (0..count as usize)
        .map(|i| unsafe { *zones.add(i) })
        .collect()
}

fn protect(array: *mut *mut MallocZone, bytes: usize, prot: c_int) {
    // SAFETY: a page-aligned mapping of `bytes` this module made.
    unsafe { libc::mprotect(array.cast(), bytes, prot) };
}

/// `malloc_zone_register_while_locked`.
///
/// # Safety
///
/// [`LOCK`] is held, and `zone` stays valid while it is registered.
unsafe fn register_while_locked(zone: *mut MallocZone, make_default: bool) {
    let count = NUM_ZONES.load(Ordering::Relaxed) as usize;
    let mut array = ZONES.load(Ordering::Relaxed);
    for i in 0..count {
        // SAFETY: a live entry.
        if unsafe { *array.add(i) } == zone {
            report(&format!(
                "Attempted to register zone more than once: {zone:p}\n"
            ));
            return;
        }
    }
    let allocated = ALLOCATED.load(Ordering::Relaxed) as usize;
    let page = page_size();
    let protect_size;
    if count == allocated {
        let wanted = match allocated {
            0 => page / size_of::<*mut MallocZone>(),
            n if n < 1 << 17 => n * 2,
            n => n + (1 << 17),
        };
        let bytes = (wanted * size_of::<*mut MallocZone>()).next_multiple_of(page);
        // SAFETY: a fresh anonymous mapping.
        let fresh = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if fresh == libc::MAP_FAILED {
            report("malloc_zone_register allocation failed\n");
            return;
        }
        let fresh = fresh.cast::<*mut MallocZone>();
        if !array.is_null() {
            // SAFETY: `count` live entries into a larger new array.
            unsafe { std::ptr::copy_nonoverlapping(array, fresh, count) };
        }
        array = fresh;
        ZONES.store(fresh, Ordering::Release);
        ALLOCATED.store(
            (bytes / size_of::<*mut MallocZone>()) as u32,
            Ordering::Relaxed,
        );
        protect_size = bytes;
    } else {
        protect_size = allocated * size_of::<*mut MallocZone>();
        protect(array, protect_size, libc::PROT_READ | libc::PROT_WRITE);
    }
    // SAFETY: the array has room for one more, and is writable.
    unsafe {
        if make_default {
            std::ptr::copy(array, array.add(1), count);
            *array = zone;
        } else {
            *array.add(count) = zone;
        }
    }
    // The pointer must be visible before the count that covers it.
    NUM_ZONES.fetch_add(1, Ordering::SeqCst);
    protect(array, protect_size, libc::PROT_READ);
}

/// `find_registered_zone`: the zone that owns `ptr`, and the size it reports.
///
/// A hit on the first zone answers the virtual default zone, as libmalloc does
/// when nothing was injected in front of it.
///
/// # Safety
///
/// Every registered zone is callable, which registering one promises.
unsafe fn find_registered_zone(
    ptr: *const c_void,
    known_non_default: bool,
) -> (*mut MallocZone, usize) {
    let (zones, count) = zones();
    if count == 0 {
        return (std::ptr::null_mut(), 0);
    }
    let initial = INITIAL_NUM_ZONES.load(Ordering::Acquire);
    for i in u32::from(known_non_default)..initial {
        // SAFETY: the initial zones are never removed while others run, which
        // is the bargain libmalloc's fast path makes as well.
        let zone = unsafe { *zones.add(i as usize) };
        let size = unsafe { zone_size(zone, ptr) };
        if size != 0 {
            return (if i == 0 { virtual_zone() } else { zone }, size);
        }
    }

    let live = FRZ_LIVE.load(Ordering::SeqCst);
    FRZ[live].fetch_add(1, Ordering::SeqCst);
    // Reloaded inside the counted region, so that an unregister either waits
    // for this walk or happened before it.
    let zones = ZONES.load(Ordering::Acquire);
    let limit = NUM_ZONES.load(Ordering::Acquire);
    let mut found = (std::ptr::null_mut(), 0);
    for i in initial..limit {
        // SAFETY: entries below the count are live until this walk drains.
        let zone = unsafe { *zones.add(i as usize) };
        let size = unsafe { zone_size(zone, ptr) };
        if size != 0 {
            found = (zone, size);
            break;
        }
    }
    FRZ[live].fetch_sub(1, Ordering::SeqCst);
    found
}

/// `find_zone_and_free`.
unsafe fn find_zone_and_free(ptr: *mut c_void, known_non_default: bool) {
    if ptr.is_null() {
        return;
    }
    let (zone, size) = unsafe { find_registered_zone(ptr, known_non_default) };
    if zone.is_null() {
        report_not_allocated(ptr, "pointer being freed was not allocated");
    } else {
        unsafe { zone_free_definite_size(zone, ptr, size) };
    }
}

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

fn write_fd(fd: c_int, text: &str) {
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        // SAFETY: a live buffer of the given length.
        let n = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if n <= 0 {
            return;
        }
        rest = &rest[n as usize..];
    }
}

/// `malloc_report`: `prog(pid,thread) malloc: message`, on standard error.
fn report(message: &str) {
    // SAFETY: a static C string.
    let name = unsafe { std::ffi::CStr::from_ptr(crate::progname::getprogname()) };
    // SAFETY: plain queries.
    let (pid, thread) = unsafe { (libc::getpid(), libc::pthread_self()) };
    write_fd(
        2,
        &format!(
            "{}({pid},{thread:#x}) malloc: {message}",
            name.to_string_lossy()
        ),
    );
}

/// `MallocErrorAbort` in the guest's environment: an error is fatal rather
/// than reported.
fn abort_on_error() -> bool {
    static ABORT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ABORT.get_or_init(|| {
        ["MallocErrorAbort", "MallocCorruptionAbort"]
            .iter()
            .any(|name| crate::guest_env_var(name).is_some())
    })
}

/// `malloc_error_break`: where libmalloc tells a developer to stop.
#[inline(never)]
pub extern "C" fn malloc_error_break() {
    std::hint::black_box(());
}

/// The report for a pointer no zone owns.
fn report_not_allocated(ptr: *const c_void, what: &str) {
    report(&format!(
        "*** error for object {ptr:p}: {what}\n*** set a breakpoint in malloc_error_break to debug\n"
    ));
    malloc_error_break();
    if abort_on_error() {
        // SAFETY: ends the process.
        unsafe { libc::abort() };
    }
}

// ---------------------------------------------------------------------------
// Allocation through a zone, with libmalloc's checks.
// ---------------------------------------------------------------------------

unsafe fn zone_malloc(zone: *mut MallocZone, size: usize, mzo: Mzo) -> *mut c_void {
    let zone = resolve(zone);
    if size > absolute_max_size() {
        set_errno_if(mzo, libc::ENOMEM);
        return std::ptr::null_mut();
    }
    let block = match unsafe { (*zone).malloc } {
        Some(f) => unsafe { zone_call!(f, host_malloc, (zone, size)) },
        None => std::ptr::null_mut(),
    };
    if block.is_null() {
        set_errno_if(mzo, libc::ENOMEM);
    }
    block
}

unsafe fn zone_calloc(zone: *mut MallocZone, count: usize, size: usize, mzo: Mzo) -> *mut c_void {
    let zone = resolve(zone);
    let block = match unsafe { (*zone).calloc } {
        Some(f) => unsafe { zone_call!(f, host_calloc, (zone, count, size)) },
        None => std::ptr::null_mut(),
    };
    if block.is_null() {
        set_errno_if(mzo, libc::ENOMEM);
    }
    block
}

unsafe fn zone_valloc(zone: *mut MallocZone, size: usize, mzo: Mzo) -> *mut c_void {
    let zone = resolve(zone);
    if size > absolute_max_size() {
        set_errno_if(mzo, libc::ENOMEM);
        return std::ptr::null_mut();
    }
    let block = match unsafe { (*zone).valloc } {
        Some(f) => unsafe { zone_call!(f, host_valloc, (zone, size)) },
        None => std::ptr::null_mut(),
    };
    if block.is_null() {
        set_errno_if(mzo, libc::ENOMEM);
    }
    block
}

unsafe fn zone_realloc(zone: *mut MallocZone, ptr: *mut c_void, size: usize) -> *mut c_void {
    let zone = resolve(zone);
    if size > absolute_max_size() {
        return std::ptr::null_mut();
    }
    match unsafe { (*zone).realloc } {
        Some(f) => unsafe { zone_call!(f, host_realloc, (zone, ptr, size)) },
        None => std::ptr::null_mut(),
    }
}

/// `_malloc_zone_memalign`.
unsafe fn zone_memalign(
    zone: *mut MallocZone,
    alignment: usize,
    size: usize,
    mzo: Mzo,
) -> *mut c_void {
    let zone = resolve(zone);
    let failed = |error| {
        if mzo.posix() {
            crate::errno::set(error);
        }
        std::ptr::null_mut()
    };
    let Some(memalign) = (unsafe { MallocZone::memalign_fn(zone) }) else {
        return failed(libc::ENOMEM);
    };
    if size > absolute_max_size() {
        return failed(libc::ENOMEM);
    }
    if alignment < DEFAULT_ALIGN || !alignment.is_power_of_two() {
        return failed(libc::EINVAL);
    }
    // C11's `aligned_alloc` wants a multiple of the alignment; POSIX does not.
    if mzo.c11() && size & (alignment - 1) != 0 {
        return failed(libc::EINVAL);
    }
    let block = unsafe { zone_call!(memalign, host_memalign, (zone, alignment, size)) };
    if block.is_null() {
        return failed(libc::ENOMEM);
    }
    block
}

// ---------------------------------------------------------------------------
// The C entry points.
// ---------------------------------------------------------------------------

/// `void *malloc(size_t size)`
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    unsafe { zone_malloc(zone0(), size, Mzo::POSIX) }
}

/// `void *calloc(size_t count, size_t size)`
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { zone_calloc(zone0(), count, size, Mzo::POSIX) }
}

/// `void *valloc(size_t size)`
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    unsafe { zone_valloc(zone0(), size, Mzo::POSIX) }
}

/// `void *aligned_alloc(size_t alignment, size_t size)`
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    unsafe { zone_memalign(zone0(), alignment, size, Mzo(Mzo::POSIX.0 | Mzo::C11.0)) }
}

/// `int posix_memalign(void **memptr, size_t alignment, size_t size)`
///
/// The error is returned rather than put in `errno`. `EINVAL` and `ENOMEM`
/// have the same numbers on Darwin and on every host this runs on.
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    let block = unsafe { zone_memalign(zone0(), alignment, size, Mzo::NONE) };
    if block.is_null() {
        if alignment < DEFAULT_ALIGN || !alignment.is_power_of_two() {
            return libc::EINVAL;
        }
        return libc::ENOMEM;
    }
    // SAFETY: the caller's slot, written only on success.
    unsafe { *memptr = block };
    0
}

/// `void free(void *ptr)`
///
/// The first zone's `try_free_default` when it has one - which is how the
/// default zone, or PartitionAlloc's in Chromium, frees its own blocks without
/// a walk - and the walk otherwise.
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let zone = zone0();
    match unsafe { MallocZone::try_free_default_fn(zone) } {
        Some(f) => unsafe { zone_call!(f, host_try_free_default, (zone, ptr)) },
        None => unsafe { find_zone_and_free(ptr, false) },
    }
}

/// `void vfree(void *ptr)`, libsystem_malloc's private partner to `valloc`.
pub unsafe extern "C" fn vfree(ptr: *mut c_void) {
    unsafe { free(ptr) }
}

/// `void *realloc(void *ptr, size_t size)`
///
/// libmalloc's rules: a null pointer is `malloc`; a zero size allocates a
/// minimal block from the default zone and frees the old one only if that
/// worked; anything else is resized by the zone that owns it.
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { zone_malloc(zone0(), size, Mzo::POSIX) };
    }
    let resized = if size == 0 {
        unsafe { zone_malloc(zone0(), 0, Mzo::NONE) }
    } else {
        let (zone, _) = unsafe { find_registered_zone(ptr, false) };
        if zone.is_null() {
            report_not_allocated(ptr, "pointer being realloc'd was not allocated");
            std::ptr::null_mut()
        } else {
            unsafe { zone_realloc(zone, ptr, size) }
        }
    };
    if resized.is_null() {
        crate::errno::set(libc::ENOMEM);
    } else if size == 0 {
        unsafe { free(ptr) };
    }
    resized
}

/// `void *reallocf(void *ptr, size_t size)`
///
/// `realloc`, but the old block is freed when it fails, so that
/// `p = reallocf(p, n)` does not leak it. `errno` is kept across that `free`.
pub unsafe extern "C" fn reallocf(ptr: *mut c_void, size: usize) -> *mut c_void {
    let resized = unsafe { realloc(ptr, size) };
    if resized.is_null() && !ptr.is_null() && size != 0 {
        let _errno = crate::errno::Held::now();
        unsafe { free(ptr) };
    }
    resized
}

/// `void *reallocarray(void *ptr, size_t count, size_t size)`
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, count: usize, size: usize) -> *mut c_void {
    match count.checked_mul(size) {
        Some(total) => unsafe { realloc(ptr, total) },
        None => {
            crate::errno::set(libc::ENOMEM);
            std::ptr::null_mut()
        }
    }
}

/// `void *reallocarrayf(void *ptr, size_t count, size_t size)`
pub unsafe extern "C" fn reallocarrayf(ptr: *mut c_void, count: usize, size: usize) -> *mut c_void {
    match count.checked_mul(size) {
        Some(total) => unsafe { reallocf(ptr, total) },
        None => {
            crate::errno::set(libc::ENOMEM);
            std::ptr::null_mut()
        }
    }
}

/// `size_t malloc_size(const void *ptr)`: the usable size of a block, or zero
/// for a pointer no zone owns.
pub unsafe extern "C" fn malloc_size(ptr: *const c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { find_registered_zone(ptr, false) }.1
}

/// `size_t malloc_good_size(size_t size)`
pub unsafe extern "C" fn malloc_good_size(size: usize) -> usize {
    unsafe { zone_good_size(virtual_zone(), size) }
}

// ---------------------------------------------------------------------------
// The zone API.
// ---------------------------------------------------------------------------

/// `malloc_zone_t *malloc_default_zone(void)`: the virtual default zone.
pub extern "C" fn malloc_default_zone() -> *mut MallocZone {
    init();
    virtual_zone()
}

/// `malloc_zone_t *malloc_default_purgeable_zone(void)`
pub extern "C" fn malloc_default_purgeable_zone() -> *mut MallocZone {
    static ONCE: Once = Once::new();
    init();
    let zone: *mut MallocZone = (&raw mut PURGEABLE_ZONE).cast();
    ONCE.call_once(|| {
        // SAFETY: written once, before the zone is published.
        unsafe { (*zone.cast::<HostZone>()).heap = mi::mi_heap_new() };
        // SAFETY: a zone that lives for the rest of the process.
        unsafe { malloc_zone_register(zone) };
    });
    zone
}

/// `malloc_zone_t *malloc_create_zone(vm_size_t start_size, unsigned flags)`
pub unsafe extern "C" fn malloc_create_zone(start_size: usize, _flags: c_uint) -> *mut MallocZone {
    if start_size > absolute_max_size() {
        return std::ptr::null_mut();
    }
    init();
    // SAFETY: a heap of its own, owned by the zone until it is destroyed.
    let heap = unsafe { mi::mi_heap_new() };
    if heap.is_null() {
        return std::ptr::null_mut();
    }
    let mut host = Box::new(HostZone::new(std::ptr::null(), true));
    host.heap = heap;
    let zone = Box::into_raw(host).cast::<MallocZone>();
    unsafe { malloc_zone_register(zone) };
    zone
}

/// `void malloc_destroy_zone(malloc_zone_t *zone)`
pub unsafe extern "C" fn malloc_destroy_zone(zone: *mut MallocZone) {
    if zone.is_null() {
        return;
    }
    unsafe {
        malloc_set_zone_name(zone, std::ptr::null());
        malloc_zone_unregister(zone);
        if let Some(f) = (*zone).destroy {
            zone_call!(f, host_destroy, (zone));
        }
    }
}

/// `malloc_zone_t *malloc_zone_from_ptr(const void *ptr)`
pub unsafe extern "C" fn malloc_zone_from_ptr(ptr: *const c_void) -> *mut MallocZone {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { find_registered_zone(ptr, false) }.0
}

/// `void *malloc_zone_malloc(malloc_zone_t *zone, size_t size)`
pub unsafe extern "C" fn malloc_zone_malloc(zone: *mut MallocZone, size: usize) -> *mut c_void {
    unsafe { zone_malloc(zone, size, Mzo::NONE) }
}

/// `void *malloc_zone_calloc(malloc_zone_t *zone, size_t count, size_t size)`
pub unsafe extern "C" fn malloc_zone_calloc(
    zone: *mut MallocZone,
    count: usize,
    size: usize,
) -> *mut c_void {
    unsafe { zone_calloc(zone, count, size, Mzo::NONE) }
}

/// `void *malloc_zone_valloc(malloc_zone_t *zone, size_t size)`
pub unsafe extern "C" fn malloc_zone_valloc(zone: *mut MallocZone, size: usize) -> *mut c_void {
    unsafe { zone_valloc(zone, size, Mzo::NONE) }
}

/// `void *malloc_zone_realloc(malloc_zone_t *zone, void *ptr, size_t size)`
pub unsafe extern "C" fn malloc_zone_realloc(
    zone: *mut MallocZone,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { zone_realloc(zone, ptr, size) }
}

/// `void malloc_zone_free(malloc_zone_t *zone, void *ptr)`
pub unsafe extern "C" fn malloc_zone_free(zone: *mut MallocZone, ptr: *mut c_void) {
    unsafe { zone_free(resolve(zone), ptr) }
}

/// `void *malloc_zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size)`
pub unsafe extern "C" fn malloc_zone_memalign(
    zone: *mut MallocZone,
    alignment: usize,
    size: usize,
) -> *mut c_void {
    unsafe { zone_memalign(zone, alignment, size, Mzo::NONE) }
}

/// `void *malloc_zone_malloc_with_options(malloc_zone_t *zone, size_t align,
/// size_t size, malloc_zone_malloc_options_t options)`
pub unsafe extern "C" fn malloc_zone_malloc_with_options(
    zone: *mut MallocZone,
    align: usize,
    size: usize,
    options: u64,
) -> *mut c_void {
    if align != DEFAULT_ALIGN && align != 0 && (!align.is_power_of_two() || size & (align - 1) != 0)
    {
        return std::ptr::null_mut();
    }
    let zone = resolve(zone);
    if let Some(f) = unsafe { MallocZone::malloc_with_options_fn(zone) } {
        return unsafe { zone_call!(f, (zone, align, size, options)) };
    }
    if options & !(OPTION_CLEAR | OPTION_CANONICAL_TAG) != 0 {
        report(&format!(
            "malloc_zone_malloc_with_options: unsupported options {options:#x}\n"
        ));
        // SAFETY: libmalloc traps here.
        unsafe { libc::abort() };
    }
    unsafe {
        if align > DEFAULT_ALIGN {
            let block = zone_memalign(zone, align, size, Mzo::NONE);
            if !block.is_null() && options & OPTION_CLEAR != 0 {
                std::ptr::write_bytes(block.cast::<u8>(), 0, size);
            }
            block
        } else if options & OPTION_CLEAR != 0 {
            zone_calloc(zone, 1, size, Mzo::NONE)
        } else {
            zone_malloc(zone, size, Mzo::NONE)
        }
    }
}

/// `unsigned malloc_zone_batch_malloc(malloc_zone_t *zone, size_t size,
/// void **results, unsigned num_requested)`
pub unsafe extern "C" fn malloc_zone_batch_malloc(
    zone: *mut MallocZone,
    size: usize,
    results: *mut *mut c_void,
    count: c_uint,
) -> c_uint {
    let zone = resolve(zone);
    match unsafe { (*zone).batch_malloc } {
        Some(f) => unsafe { zone_call!(f, host_batch_malloc, (zone, size, results, count)) },
        None => 0,
    }
}

/// `void malloc_zone_batch_free(malloc_zone_t *zone, void **to_be_freed, unsigned num)`
pub unsafe extern "C" fn malloc_zone_batch_free(
    zone: *mut MallocZone,
    blocks: *mut *mut c_void,
    count: c_uint,
) {
    let zone = resolve(zone);
    match unsafe { (*zone).batch_free } {
        Some(f) => unsafe { zone_call!(f, host_batch_free, (zone, blocks, count)) },
        None => {
            for i in 0..count as usize {
                // SAFETY: the caller's array of `count` blocks.
                unsafe { zone_free(zone, *blocks.add(i)) };
            }
        }
    }
}

/// `void malloc_zone_register(malloc_zone_t *zone)`: append a zone.
pub unsafe extern "C" fn malloc_zone_register(zone: *mut MallocZone) {
    if zone.is_null() {
        return;
    }
    init();
    let _held = LOCK.lock();
    unsafe { register_while_locked(zone, false) };
}

/// `void malloc_zone_unregister(malloc_zone_t *zone)`
///
/// The last zone moves into the removed one's place - which is the property
/// programs use to choose which zone is first.
pub unsafe extern "C" fn malloc_zone_unregister(zone: *mut MallocZone) {
    init();
    if NUM_ZONES.load(Ordering::Acquire) == 0 {
        return;
    }
    let held = LOCK.lock();
    let array = ZONES.load(Ordering::Relaxed);
    let count = NUM_ZONES.load(Ordering::Relaxed);
    for index in 0..count as usize {
        // SAFETY: a live entry.
        if unsafe { *array.add(index) } != zone {
            continue;
        }
        let protect_size =
            ALLOCATED.load(Ordering::Relaxed) as usize * size_of::<*mut MallocZone>();
        protect(array, protect_size, libc::PROT_READ | libc::PROT_WRITE);
        // The end of the array is left as it was, for a lookup still reading it.
        // SAFETY: both indices are live entries of a writable array.
        unsafe { *array.add(index) = *array.add(count as usize - 1) };
        NUM_ZONES.store(count - 1, Ordering::SeqCst);
        protect(array, protect_size, libc::PROT_READ);
        let initial = INITIAL_NUM_ZONES.load(Ordering::Relaxed);
        INITIAL_NUM_ZONES.store((count - 1).min(initial).max(1), Ordering::SeqCst);

        // Swap the counters, then wait for every lookup that started before
        // the swap - and may hold `zone` - to finish.
        let draining = FRZ_LIVE.load(Ordering::SeqCst);
        FRZ_LIVE.store(1 - draining, Ordering::SeqCst);
        std::sync::atomic::fence(Ordering::SeqCst);
        while FRZ[draining].load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
        drop(held);
        return;
    }
    drop(held);
    report(&format!(
        "*** malloc_zone_unregister() failed for {zone:p}\n"
    ));
}

/// `void malloc_set_zone_name(malloc_zone_t *zone, const char *name)`
///
/// The old name is freed if a zone owns it, and the new one is copied into the
/// zone itself, as libmalloc does with a name that is not in an image.
pub unsafe extern "C" fn malloc_set_zone_name(zone: *mut MallocZone, name: *const c_char) {
    if zone.is_null() {
        return;
    }
    unsafe {
        let old = (*zone).zone_name;
        if !old.is_null() {
            let (owner, _) = find_registered_zone(old.cast(), false);
            if !owner.is_null() {
                zone_free(owner, old.cast_mut().cast());
            }
            (*zone).zone_name = std::ptr::null();
        }
        if name.is_null() {
            return;
        }
        let len = libc::strlen(name) + 1;
        let copy = zone_malloc(zone, len, Mzo::NONE).cast::<c_char>();
        if !copy.is_null() {
            std::ptr::copy_nonoverlapping(name, copy, len);
            (*zone).zone_name = copy;
        }
    }
}

/// `const char *malloc_get_zone_name(malloc_zone_t *zone)`
pub unsafe extern "C" fn malloc_get_zone_name(zone: *mut MallocZone) -> *const c_char {
    if zone.is_null() {
        return std::ptr::null();
    }
    unsafe { (*zone).zone_name }
}

/// `kern_return_t malloc_get_all_zones(task_t task, memory_reader_t reader,
/// vm_address_t **addresses, unsigned *count)`
///
/// Without a reader, the zone array itself: Chromium reads the first entry to
/// learn which zone `malloc` uses. With one, the three reads libmalloc makes,
/// through it, of this process's own variables.
pub unsafe extern "C" fn malloc_get_all_zones(
    task: Task,
    reader: Option<MemoryReaderFn>,
    addresses: *mut *mut usize,
    count: *mut c_uint,
) -> KernReturn {
    let (zones, num) = zones();
    let Some(reader) = reader else {
        // SAFETY: the caller's two out-parameters.
        unsafe {
            if !addresses.is_null() {
                *addresses = zones.cast_mut().cast();
            }
            if !count.is_null() {
                *count = num;
            }
        }
        return KERN_SUCCESS;
    };
    unsafe {
        let mut local: *mut c_void = std::ptr::null_mut();
        let err = zone_call!(
            reader,
            (
                task,
                (&raw const ZONES) as usize,
                size_of::<usize>(),
                &mut local
            )
        );
        if err != KERN_SUCCESS {
            report(&format!(
                "*** malloc_get_all_zones: error reading zones_address at {:p}\n",
                &raw const ZONES
            ));
            return err;
        }
        let zones_address = *local.cast::<usize>();
        let err = zone_call!(
            reader,
            (
                task,
                (&raw const NUM_ZONES) as usize,
                size_of::<c_uint>(),
                &mut local
            )
        );
        if err != KERN_SUCCESS {
            report(&format!(
                "*** malloc_get_all_zones: error reading num_zones at {:p}\n",
                &raw const NUM_ZONES
            ));
            return err;
        }
        let num = *local.cast::<c_uint>();
        *count = num;
        let err = zone_call!(
            reader,
            (
                task,
                zones_address,
                size_of::<usize>() * num as usize,
                addresses.cast::<*mut c_void>()
            )
        );
        if err != KERN_SUCCESS {
            report("*** malloc_get_all_zones: error reading zones\n");
        }
        err
    }
}

/// `void malloc_zone_print_ptr_info(void *ptr)`
pub unsafe extern "C" fn malloc_zone_print_ptr_info(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let zone = unsafe { malloc_zone_from_ptr(ptr) };
    if zone.is_null() {
        write_fd(1, &format!("ptr {ptr:p} not in heap\n"));
    } else {
        write_fd(1, &format!("ptr {ptr:p} in registered zone {zone:p}\n"));
    }
}

/// `boolean_t malloc_zone_check(malloc_zone_t *zone)`: every zone for null.
pub unsafe extern "C" fn malloc_zone_check(zone: *mut MallocZone) -> Boolean {
    if !zone.is_null() {
        return unsafe { zone_check(zone) };
    }
    let mut ok = 1;
    for zone in snapshot() {
        if unsafe { zone_check(zone) } == 0 {
            ok = 0;
        }
    }
    ok
}

/// `void malloc_zone_print(malloc_zone_t *zone, boolean_t verbose)`
pub unsafe extern "C" fn malloc_zone_print(zone: *mut MallocZone, verbose: Boolean) {
    if !zone.is_null() {
        return unsafe { zone_print(zone, verbose) };
    }
    for zone in snapshot() {
        unsafe { zone_print(zone, verbose) };
    }
}

/// `void malloc_zone_statistics(malloc_zone_t *zone, malloc_statistics_t *stats)`:
/// every zone's, summed, for null.
///
/// # Safety
///
/// `stats` is null or a writable Darwin `malloc_statistics_t`.
pub unsafe extern "C" fn malloc_zone_statistics(zone: *mut MallocZone, stats: *mut Statistics) {
    if stats.is_null() {
        return;
    }
    if !zone.is_null() {
        return unsafe { zone_statistics(zone, stats) };
    }
    let mut total = Statistics::default();
    for zone in snapshot() {
        let mut one = Statistics::default();
        unsafe { zone_statistics(zone, &mut one) };
        total.blocks_in_use = total.blocks_in_use.wrapping_add(one.blocks_in_use);
        total.size_in_use += one.size_in_use;
        total.max_size_in_use += one.max_size_in_use;
        total.size_allocated += one.size_allocated;
    }
    // SAFETY: the caller's writable structure.
    unsafe { *stats = total };
}

/// `void malloc_zone_log(malloc_zone_t *zone, void *address)`
pub unsafe extern "C" fn malloc_zone_log(zone: *mut MallocZone, address: *mut c_void) {
    if !zone.is_null() {
        return unsafe { zone_log(zone, address) };
    }
    for zone in snapshot() {
        unsafe { zone_log(zone, address) };
    }
}

/// `size_t malloc_zone_pressure_relief(malloc_zone_t *zone, size_t goal)`
///
/// For null, every zone until `goal` is met (zero is greedy). The zones are
/// called outside the registry lock, which libmalloc holds: a zone that
/// registers another while relieving pressure would otherwise deadlock.
pub unsafe extern "C" fn malloc_zone_pressure_relief(zone: *mut MallocZone, goal: usize) -> usize {
    let relieve = |zone: *mut MallocZone, goal: usize| match unsafe {
        MallocZone::pressure_relief_fn(zone)
    } {
        Some(f) => unsafe { zone_call!(f, host_pressure_relief, (zone, goal)) },
        None => 0,
    };
    if !zone.is_null() {
        return relieve(zone, goal);
    }
    let mut total = 0usize;
    for zone in snapshot() {
        if goal == 0 {
            total += relieve(zone, 0);
        } else if goal > total {
            total += relieve(zone, goal - total);
        } else {
            break;
        }
    }
    total
}

/// `boolean_t malloc_zone_claimed_address(malloc_zone_t *zone, void *ptr)`
///
/// A zone that cannot say has to be assumed to claim it: a false negative is
/// the one wrong answer this function may not give.
pub unsafe extern "C" fn malloc_zone_claimed_address(
    zone: *mut MallocZone,
    ptr: *mut c_void,
) -> Boolean {
    if ptr.is_null() {
        return 0;
    }
    let zone = resolve(zone);
    match unsafe { MallocZone::claimed_address_fn(zone) } {
        Some(f) => unsafe { zone_call!(f, host_claimed_address, (zone, ptr)) },
        None => 1,
    }
}

/// `boolean_t malloc_claimed_address(void *ptr)`
pub unsafe extern "C" fn malloc_claimed_address(ptr: *mut c_void) -> Boolean {
    for zone in snapshot() {
        if unsafe { malloc_zone_claimed_address(zone, ptr) } != 0 {
            return 1;
        }
    }
    0
}

/// `void malloc_make_purgeable(void *ptr)`: nothing on this host is ever
/// discarded.
pub unsafe extern "C" fn malloc_make_purgeable(_ptr: *mut c_void) {}

/// `int malloc_make_nonpurgeable(void *ptr)`: zero, the contents are intact.
pub unsafe extern "C" fn malloc_make_nonpurgeable(_ptr: *mut c_void) -> c_int {
    0
}

/// `struct mstats mstats(void)`
pub extern "C" fn mstats() -> Mstats {
    let mut stats = Statistics::default();
    // SAFETY: a local structure.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    Mstats {
        bytes_total: stats.size_allocated,
        chunks_used: stats.blocks_in_use as usize,
        bytes_used: stats.size_in_use,
        chunks_free: 0,
        bytes_free: stats.size_allocated.saturating_sub(stats.size_in_use),
    }
}

/// `boolean_t malloc_zone_enable_discharge_checking(malloc_zone_t *zone)`
pub unsafe extern "C" fn malloc_zone_enable_discharge_checking(zone: *mut MallocZone) -> Boolean {
    let zone = resolve(zone);
    match unsafe { MallocZone::introspect_since(zone, 7, |i| i.enable_discharge_checking) } {
        Some(f) => unsafe { zone_call!(f, host_enable_discharge_checking, (zone)) },
        None => 0,
    }
}

/// `void malloc_zone_disable_discharge_checking(malloc_zone_t *zone)`
pub unsafe extern "C" fn malloc_zone_disable_discharge_checking(zone: *mut MallocZone) {
    let zone = resolve(zone);
    if let Some(f) =
        unsafe { MallocZone::introspect_since(zone, 7, |i| i.disable_discharge_checking) }
    {
        unsafe { zone_call!(f, host_lock, (zone)) }
    }
}

/// `void malloc_zone_discharge(malloc_zone_t *zone, void *memory)`
pub unsafe extern "C" fn malloc_zone_discharge(zone: *mut MallocZone, memory: *mut c_void) {
    let zone = resolve(zone);
    if let Some(f) = unsafe { MallocZone::introspect_since(zone, 7, |i| i.discharge) } {
        unsafe { zone_call!(f, host_log, (zone, memory)) }
    }
}

/// `void malloc_zone_enumerate_discharged_pointers(malloc_zone_t *zone,
/// void (^report)(void *, void *))`
pub unsafe extern "C" fn malloc_zone_enumerate_discharged_pointers(
    zone: *mut MallocZone,
    block: *mut c_void,
) {
    let zone = resolve(zone);
    if let Some(f) =
        unsafe { MallocZone::introspect_since(zone, 7, |i| i.enumerate_discharged_pointers) }
    {
        unsafe { zone_call!(f, (zone, block)) }
    }
}

/// `int malloc_engaged_nano(void)`: there is no nano zone here.
pub extern "C" fn malloc_engaged_nano() -> c_int {
    0
}

/// `int malloc_jumpstart(int cookie)`: start-up work this module does lazily.
pub extern "C" fn malloc_jumpstart(_cookie: c_int) -> c_int {
    init();
    0
}

/// `void malloc_enter_process_memory_limit_warn_mode(void)`
pub extern "C" fn malloc_enter_process_memory_limit_warn_mode() {}

/// `void malloc_memory_event_handler(unsigned long event)`: pressure relief
/// for every zone, whatever the event.
pub extern "C" fn malloc_memory_event_handler(_event: std::ffi::c_ulong) {
    // SAFETY: every registered zone, greedily.
    unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
}

/// `_malloc_fork_prepare`: the registry lock, then every zone's, held across
/// `fork`.
pub extern "C" fn _malloc_fork_prepare() {
    init();
    LOCK.acquire();
    let (zones, count) = (
        ZONES.load(Ordering::Acquire),
        NUM_ZONES.load(Ordering::Acquire),
    );
    for i in 0..count as usize {
        // SAFETY: live entries, stable while the lock is held.
        unsafe { zone_force_lock(*zones.add(i)) };
    }
}

/// `_malloc_fork_parent`: everything [`_malloc_fork_prepare`] took, given back.
pub extern "C" fn _malloc_fork_parent() {
    let (zones, count) = (
        ZONES.load(Ordering::Acquire),
        NUM_ZONES.load(Ordering::Acquire),
    );
    for i in 0..count as usize {
        // SAFETY: as above.
        unsafe { zone_force_unlock(*zones.add(i)) };
    }
    LOCK.release();
}

/// `_malloc_fork_child`: the zones' locks reinitialised, in the only thread
/// the child has.
pub extern "C" fn _malloc_fork_child() {
    let (zones, count) = (
        ZONES.load(Ordering::Acquire),
        NUM_ZONES.load(Ordering::Acquire),
    );
    for i in 0..count as usize {
        // SAFETY: as above.
        unsafe { zone_reinit_lock(*zones.add(i)) };
    }
    LOCK.release();
}

// ---------------------------------------------------------------------------
// Typed allocation (macOS 14): the type is advice no zone here takes.
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn malloc_type_malloc(size: usize, _: TypeId) -> *mut c_void {
    unsafe { malloc(size) }
}

pub unsafe extern "C" fn malloc_type_calloc(count: usize, size: usize, _: TypeId) -> *mut c_void {
    unsafe { calloc(count, size) }
}

pub unsafe extern "C" fn malloc_type_free(ptr: *mut c_void, _: TypeId) {
    unsafe { free(ptr) }
}

pub unsafe extern "C" fn malloc_type_realloc(
    ptr: *mut c_void,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { realloc(ptr, size) }
}

pub unsafe extern "C" fn malloc_type_valloc(size: usize, _: TypeId) -> *mut c_void {
    unsafe { valloc(size) }
}

pub unsafe extern "C" fn malloc_type_aligned_alloc(
    alignment: usize,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { aligned_alloc(alignment, size) }
}

pub unsafe extern "C" fn malloc_type_posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
    _: TypeId,
) -> c_int {
    unsafe { posix_memalign(memptr, alignment, size) }
}

pub unsafe extern "C" fn malloc_type_zone_malloc(
    zone: *mut MallocZone,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_malloc(zone, size) }
}

pub unsafe extern "C" fn malloc_type_zone_calloc(
    zone: *mut MallocZone,
    count: usize,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_calloc(zone, count, size) }
}

pub unsafe extern "C" fn malloc_type_zone_free(zone: *mut MallocZone, ptr: *mut c_void, _: TypeId) {
    unsafe { malloc_zone_free(zone, ptr) }
}

pub unsafe extern "C" fn malloc_type_zone_realloc(
    zone: *mut MallocZone,
    ptr: *mut c_void,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_realloc(zone, ptr, size) }
}

pub unsafe extern "C" fn malloc_type_zone_valloc(
    zone: *mut MallocZone,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_valloc(zone, size) }
}

pub unsafe extern "C" fn malloc_type_zone_memalign(
    zone: *mut MallocZone,
    alignment: usize,
    size: usize,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_memalign(zone, alignment, size) }
}

pub unsafe extern "C" fn malloc_type_zone_malloc_with_options(
    zone: *mut MallocZone,
    align: usize,
    size: usize,
    options: u64,
    _: TypeId,
) -> *mut c_void {
    unsafe { malloc_zone_malloc_with_options(zone, align, size, options) }
}

exports::exports! {
    functions {
        "malloc" => malloc,
        "calloc" => calloc,
        "valloc" => valloc,
        "aligned_alloc" => aligned_alloc,
        "posix_memalign" => posix_memalign,
        "free" => free,
        "vfree" => vfree,
        "realloc" => realloc,
        "reallocf" => reallocf,
        "reallocarray" => reallocarray,
        "reallocarrayf" => reallocarrayf,
        "malloc_size" => malloc_size,
        "malloc_good_size" => malloc_good_size,
        "malloc_default_zone" => malloc_default_zone,
        "malloc_default_purgeable_zone" => malloc_default_purgeable_zone,
        "malloc_create_zone" => malloc_create_zone,
        "malloc_destroy_zone" => malloc_destroy_zone,
        "malloc_zone_from_ptr" => malloc_zone_from_ptr,
        "malloc_zone_malloc" => malloc_zone_malloc,
        "malloc_zone_calloc" => malloc_zone_calloc,
        "malloc_zone_valloc" => malloc_zone_valloc,
        "malloc_zone_realloc" => malloc_zone_realloc,
        "malloc_zone_free" => malloc_zone_free,
        "malloc_zone_memalign" => malloc_zone_memalign,
        "malloc_zone_malloc_with_options" | "malloc_zone_malloc_with_options_np"
            => malloc_zone_malloc_with_options,
        "malloc_zone_batch_malloc" => malloc_zone_batch_malloc,
        "malloc_zone_batch_free" => malloc_zone_batch_free,
        "malloc_zone_register" => malloc_zone_register,
        "malloc_zone_unregister" => malloc_zone_unregister,
        "malloc_set_zone_name" => malloc_set_zone_name,
        "malloc_get_zone_name" => malloc_get_zone_name,
        "malloc_get_all_zones" => malloc_get_all_zones,
        "malloc_zone_print_ptr_info" => malloc_zone_print_ptr_info,
        "malloc_zone_check" => malloc_zone_check,
        "malloc_zone_print" => malloc_zone_print,
        "malloc_zone_statistics" => malloc_zone_statistics,
        "malloc_zone_log" => malloc_zone_log,
        "malloc_zone_pressure_relief" => malloc_zone_pressure_relief,
        "malloc_zone_claimed_address" => malloc_zone_claimed_address,
        "malloc_claimed_address" => malloc_claimed_address,
        "malloc_make_purgeable" => malloc_make_purgeable,
        "malloc_make_nonpurgeable" => malloc_make_nonpurgeable,
        "mstats" => mstats,
        "malloc_zone_enable_discharge_checking" => malloc_zone_enable_discharge_checking,
        "malloc_zone_disable_discharge_checking" => malloc_zone_disable_discharge_checking,
        "malloc_zone_discharge" => malloc_zone_discharge,
        "malloc_zone_enumerate_discharged_pointers" => malloc_zone_enumerate_discharged_pointers,
        "malloc_error_break" => malloc_error_break,
        "malloc_engaged_nano" => malloc_engaged_nano,
        "malloc_jumpstart" => malloc_jumpstart,
        "malloc_enter_process_memory_limit_warn_mode" => malloc_enter_process_memory_limit_warn_mode,
        "malloc_memory_event_handler" => malloc_memory_event_handler,
        "_malloc_fork_prepare" => _malloc_fork_prepare,
        "_malloc_fork_parent" => _malloc_fork_parent,
        "_malloc_fork_child" => _malloc_fork_child,
        "malloc_type_malloc" => malloc_type_malloc,
        "malloc_type_calloc" => malloc_type_calloc,
        "malloc_type_free" => malloc_type_free,
        "malloc_type_realloc" => malloc_type_realloc,
        "malloc_type_valloc" => malloc_type_valloc,
        "malloc_type_aligned_alloc" => malloc_type_aligned_alloc,
        "malloc_type_posix_memalign" => malloc_type_posix_memalign,
        "malloc_type_zone_malloc" => malloc_type_zone_malloc,
        "malloc_type_zone_calloc" => malloc_type_zone_calloc,
        "malloc_type_zone_free" => malloc_type_zone_free,
        "malloc_type_zone_realloc" => malloc_type_zone_realloc,
        "malloc_type_zone_valloc" => malloc_type_zone_valloc,
        "malloc_type_zone_memalign" => malloc_type_zone_memalign,
        "malloc_type_zone_malloc_with_options" => malloc_type_zone_malloc_with_options,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set in the child process the zone-order tests run in, since they change
    /// which zone every `malloc` in the process goes to.
    const CHILD: &str = "ROSEMARY_MALLOC_ZONE_TEST_CHILD";

    /// Run `test` (this module's test of that name) alone in a child process.
    fn in_child(test: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("malloc::tests::{test}"), "--nocapture"])
            .env(CHILD, test)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{test} failed in its child:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{test} did not run in its child"
        );
    }

    fn is_child(test: &str) -> bool {
        std::env::var(CHILD).is_ok_and(|name| name == test)
    }

    fn registered() -> Vec<*mut MallocZone> {
        let mut zones: *mut usize = std::ptr::null_mut();
        let mut count = 0;
        // SAFETY: two writable out-parameters and no reader.
        let kr = unsafe { malloc_get_all_zones(0, None, &mut zones, &mut count) };
        assert_eq!(kr, KERN_SUCCESS);
        // SAFETY: `count` live entries.
        (0..count as usize)
            .map(|i| unsafe { *zones.add(i) } as *mut MallocZone)
            .collect()
    }

    fn name(zone: *mut MallocZone) -> String {
        unsafe { zone_name_lossy(zone) }
    }

    #[test]
    fn blocks_are_sixteen_byte_aligned_and_sized() {
        for size in [0, 1, 7, 8, 9, 24, 40, 100, 4096, 1 << 20] {
            // SAFETY: allocated, measured and freed here.
            unsafe {
                let block = malloc(size);
                assert!(!block.is_null(), "{size}");
                assert_eq!(
                    block as usize % QUANTUM,
                    0,
                    "malloc({size}) is not 16-byte aligned"
                );
                assert!(
                    malloc_size(block) >= size.max(QUANTUM),
                    "malloc_size of a {size}-byte block"
                );
                assert!(malloc_good_size(size) >= size, "malloc_good_size({size})");
                free(block);
            }
        }
    }

    #[test]
    fn calloc_zeroes_and_refuses_an_overflow() {
        // SAFETY: allocated, read and freed here.
        unsafe {
            let block = calloc(100, 41).cast::<u8>();
            assert!(!block.is_null());
            assert!(
                std::slice::from_raw_parts(block, 4100)
                    .iter()
                    .all(|&b| b == 0)
            );
            free(block.cast());
            assert!(calloc(usize::MAX / 2, 3).is_null());
            assert_eq!(crate::errno::get(), libc::ENOMEM);
        }
    }

    #[test]
    fn realloc_keeps_the_contents_and_follows_libmalloc_at_the_edges() {
        // SAFETY: blocks allocated, resized and freed here.
        unsafe {
            let block = realloc(std::ptr::null_mut(), 16).cast::<u8>();
            assert!(!block.is_null(), "realloc(NULL, n) is malloc");
            for i in 0..16 {
                *block.add(i) = i as u8;
            }
            let grown = realloc(block.cast(), 1 << 16).cast::<u8>();
            assert!(!grown.is_null());
            assert!(
                (0..16).all(|i| *grown.add(i) == i as u8),
                "the contents moved with it"
            );
            let minimal = realloc(grown.cast(), 0);
            assert!(
                !minimal.is_null(),
                "realloc(p, 0) is a minimal block, and p is freed"
            );
            free(minimal);

            let kept = malloc(32);
            assert!(reallocarray(kept, usize::MAX, 2).is_null());
            assert_eq!(crate::errno::get(), libc::ENOMEM);
            free(kept);
            let freed = malloc(32);
            assert!(
                reallocf(freed, usize::MAX - 1).is_null(),
                "too big to satisfy"
            );
        }
    }

    #[test]
    fn alignment_requests_follow_darwin_rules() {
        // SAFETY: allocated, checked and freed here.
        unsafe {
            let page = valloc(10);
            assert!(!page.is_null());
            assert_eq!(page as usize % page_size(), 0);
            vfree(page);

            let mut slot: *mut c_void = std::ptr::null_mut();
            assert_eq!(posix_memalign(&mut slot, 4096, 100), 0);
            assert_eq!(slot as usize % 4096, 0);
            free(slot);
            assert_eq!(
                posix_memalign(&mut slot, 4, 100),
                libc::EINVAL,
                "below sizeof(void *)"
            );
            assert_eq!(
                posix_memalign(&mut slot, 48, 100),
                libc::EINVAL,
                "not a power of two"
            );

            let block = aligned_alloc(64, 128);
            assert_eq!(block as usize % 64, 0);
            free(block);
            assert!(
                aligned_alloc(64, 100).is_null(),
                "C11: a size the alignment does not divide"
            );
            assert_eq!(crate::errno::get(), libc::EINVAL);
        }
    }

    #[test]
    fn a_pointer_no_zone_owns_is_answered_not_crashed_on() {
        let local = 0u64;
        static STATIC: u64 = 0;
        // SAFETY: the registry only asks zones about these addresses.
        unsafe {
            assert_eq!(malloc_size(std::ptr::null()), 0);
            assert_eq!(malloc_size((&raw const local).cast()), 0);
            assert_eq!(malloc_size((&raw const STATIC).cast()), 0);
            assert!(malloc_zone_from_ptr((&raw const local).cast()).is_null());
            // Reported on standard error and otherwise ignored, as libmalloc does
            // without `MallocErrorAbort`.
            free((&raw const STATIC).cast_mut().cast());
        }
    }

    #[test]
    fn the_default_zone_is_virtual_and_answers_for_the_first() {
        let default = malloc_default_zone();
        assert_eq!(name(default), "DefaultMallocZone");
        assert_eq!(unsafe { (*default).version }, 10);
        // SAFETY: a block of the default zone, asked about and freed.
        unsafe {
            let block = malloc_zone_malloc(default, 64);
            assert_eq!(
                malloc_zone_from_ptr(block),
                default,
                "a hit on zone 0 is the virtual zone"
            );
            assert!(malloc_zone_claimed_address(default, block) != 0);
            malloc_zone_free(default, block);
        }
        let zones = registered();
        assert!(!zones.is_empty());
        assert_eq!(name(zones[0]), "DefaultMallocZone");
    }

    /// The default zone is mimalloc's main heap, so a block another thread made
    /// - with the host's own allocator, as this runtime's frameworks do - is one
    /// the guest's `free` can find.
    #[test]
    fn a_block_from_another_thread_belongs_to_the_default_zone() {
        // SAFETY: mimalloc's own allocation, made on another thread.
        let block = std::thread::spawn(|| unsafe { mi::mi_malloc(200) } as usize)
            .join()
            .unwrap() as *mut c_void;
        // SAFETY: a live block, measured and freed through the registry.
        unsafe {
            assert!(malloc_size(block) >= 200);
            free(block);
        }
    }

    #[test]
    fn a_created_zone_owns_its_blocks_until_it_is_destroyed() {
        // SAFETY: a zone made, used and destroyed here.
        unsafe {
            let zone = malloc_create_zone(0, 0);
            assert!(!zone.is_null());
            assert!(registered().contains(&zone));
            malloc_set_zone_name(zone, c"TestZone".as_ptr());
            assert_eq!(name(zone), "TestZone");
            let named = (*zone).zone_name;
            assert_eq!(
                malloc_zone_from_ptr(named.cast()),
                zone,
                "the name is copied into the zone"
            );

            let blocks: Vec<*mut c_void> =
                (0..10).map(|i| malloc_zone_malloc(zone, 100 + i)).collect();
            assert!(blocks.iter().all(|b| malloc_zone_from_ptr(*b) == zone));
            assert!(blocks.iter().all(|b| malloc_size(*b) >= 100));
            let mut stats = Statistics::default();
            malloc_zone_statistics(zone, &mut stats);
            assert_eq!(stats.blocks_in_use, 11, "ten blocks and the name");

            // The top-level `free` finds the zone without being told.
            free(blocks[0]);
            malloc_zone_statistics(zone, &mut stats);
            assert_eq!(stats.blocks_in_use, 10);

            let mut batch = [std::ptr::null_mut(); 4];
            assert_eq!(malloc_zone_batch_malloc(zone, 48, batch.as_mut_ptr(), 4), 4);
            malloc_zone_batch_free(zone, batch.as_mut_ptr(), 4);

            // Destroying it releases the rest at once.
            malloc_destroy_zone(zone);
            assert!(!registered().contains(&zone));
        }
    }

    #[test]
    fn the_purgeable_zone_is_registered_once_and_never_discards() {
        let zone = malloc_default_purgeable_zone();
        assert_eq!(zone, malloc_default_purgeable_zone());
        assert_eq!(name(zone), "DefaultPurgeableMallocZone");
        assert!(registered().contains(&zone));
        // SAFETY: a block of the purgeable zone.
        unsafe {
            let block = malloc_zone_malloc(zone, 1 << 16);
            malloc_make_purgeable(block);
            assert_eq!(malloc_make_nonpurgeable(block), 0, "the contents survive");
            assert_eq!(malloc_zone_from_ptr(block), zone);
            free(block);
        }
    }

    #[test]
    fn statistics_cover_what_the_default_zone_holds() {
        // SAFETY: a block allocated, measured and freed here.
        unsafe {
            let block = malloc(4 << 20);
            std::ptr::write_bytes(block.cast::<u8>(), 1, 4 << 20);
            let mut stats = Statistics::default();
            malloc_zone_statistics(std::ptr::null_mut(), &mut stats);
            assert!(stats.size_in_use >= 4 << 20, "{stats:?}");
            assert!(stats.size_allocated >= stats.size_in_use);
            let summary = mstats();
            assert_eq!(summary.bytes_used, stats.size_in_use);
            free(block);
        }
    }

    #[test]
    fn unregistering_a_zone_that_is_not_registered_changes_nothing() {
        let before = registered();
        let mut stray = HostZone::new(c"Stray".as_ptr(), true);
        // SAFETY: a zone that is not in the array, which is only compared against.
        unsafe { malloc_zone_unregister((&raw mut stray).cast()) };
        assert_eq!(registered(), before);
    }

    #[test]
    fn a_reader_is_used_to_find_the_zones() {
        static READS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn reader(
            _: Task,
            address: usize,
            _: usize,
            out: *mut *mut c_void,
        ) -> KernReturn {
            READS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: this process's own memory, which the reader "reads" in place.
            unsafe { *out = address as *mut c_void };
            KERN_SUCCESS
        }
        let mut zones: *mut usize = std::ptr::null_mut();
        let mut count = 0;
        // SAFETY: two writable out-parameters and a reader for this process.
        let kr = unsafe { malloc_get_all_zones(0, Some(reader), &mut zones, &mut count) };
        assert_eq!(kr, KERN_SUCCESS);
        assert_eq!(READS.load(Ordering::Relaxed), 3);
        assert!(count >= 1);
        assert!(registered().contains(&unsafe { *zones as *mut MallocZone }));
    }

    // -----------------------------------------------------------------------
    // Chromium's zone shuffle, with stand-ins for its two zones.
    // -----------------------------------------------------------------------

    static mut REAL_DEFAULT: *mut MallocZone = std::ptr::null_mut();

    unsafe extern "C" fn delegating_size(_: *mut MallocZone, _: *const c_void) -> usize {
        0
    }
    unsafe extern "C" fn delegating_malloc(_: *mut MallocZone, size: usize) -> *mut c_void {
        unsafe { ((*REAL_DEFAULT).malloc.unwrap())(REAL_DEFAULT, size) }
    }
    unsafe extern "C" fn delegating_free(_: *mut MallocZone, ptr: *mut c_void) {
        unsafe { ((*REAL_DEFAULT).free.unwrap())(REAL_DEFAULT, ptr) }
    }
    unsafe extern "C" fn delegating_try_free_default(_: *mut MallocZone, ptr: *mut c_void) {
        unsafe { ((*REAL_DEFAULT).try_free_default.unwrap())(REAL_DEFAULT, ptr) }
    }

    /// PartitionAlloc's stand-in: blocks from a private zone that is not
    /// registered, counted so the test can see which zone `malloc` reached.
    static mut BACKING: *mut MallocZone = std::ptr::null_mut();
    static PA_MALLOCS: AtomicUsize = AtomicUsize::new(0);
    static PA_FREES: AtomicUsize = AtomicUsize::new(0);
    static PA_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn pa_size(_: *mut MallocZone, ptr: *const c_void) -> usize {
        unsafe { host_size(BACKING, ptr) }
    }
    unsafe extern "C" fn pa_malloc(_: *mut MallocZone, size: usize) -> *mut c_void {
        PA_MALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { host_malloc(BACKING, size) }
    }
    unsafe extern "C" fn pa_calloc(_: *mut MallocZone, count: usize, size: usize) -> *mut c_void {
        PA_MALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { host_calloc(BACKING, count, size) }
    }
    unsafe extern "C" fn pa_realloc(
        _: *mut MallocZone,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        unsafe { host_realloc(BACKING, ptr, size) }
    }
    unsafe extern "C" fn pa_free(_: *mut MallocZone, ptr: *mut c_void) {
        PA_FREES.fetch_add(1, Ordering::Relaxed);
        unsafe { host_free(BACKING, ptr) }
    }
    /// What PartitionAlloc's `TryFreeDefaultFallbackToFindZoneAndFree` does: its
    /// own blocks, and otherwise a walk of `malloc_get_all_zones`.
    unsafe extern "C" fn pa_try_free_default(zone: *mut MallocZone, ptr: *mut c_void) {
        unsafe {
            if pa_size(zone, ptr) != 0 {
                return pa_free(zone, ptr);
            }
            PA_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            for other in registered() {
                let size = ((*other).size.unwrap())(other, ptr);
                if size != 0 {
                    return ((*other).free_definite_size.unwrap())(other, ptr, size);
                }
            }
            panic!("no zone owns {ptr:p}");
        }
    }

    fn guest_zone(name: &'static std::ffi::CStr) -> MallocZone {
        let mut zone = unsafe { std::ptr::read(&raw const DEFAULT_ZONE.zone) };
        zone.zone_name = name.as_ptr();
        zone
    }

    #[test]
    fn chromium_zone_shuffle() {
        in_child("chromium_zone_shuffle_child");
    }

    #[test]
    fn chromium_zone_shuffle_child() {
        if !is_child("chromium_zone_shuffle_child") {
            return;
        }
        // SAFETY: zones that live for the rest of this child process.
        unsafe {
            // `EarlyMallocZoneRegistration`, in the executable.
            let purgeable = malloc_default_purgeable_zone();
            REAL_DEFAULT = registered()[0];
            let real_default = REAL_DEFAULT;
            assert_eq!(name(real_default), "DefaultMallocZone");
            let early = malloc(24);
            assert!(!early.is_null());

            let delegating: &'static mut MallocZone = Box::leak(Box::new(guest_zone(
                c"DelegatingDefaultZoneForPartitionAlloc",
            )));
            delegating.size = Some(delegating_size);
            delegating.malloc = Some(delegating_malloc);
            delegating.free = Some(delegating_free);
            delegating.try_free_default = Some(delegating_try_free_default);
            let delegating: *mut MallocZone = delegating;

            malloc_zone_register(delegating);
            malloc_zone_unregister(real_default);
            malloc_zone_register(real_default);
            malloc_zone_unregister(purgeable);
            malloc_zone_register(purgeable);
            assert_eq!(registered(), [delegating, real_default, purgeable]);

            // A block made through the delegating zone is the real default
            // zone's, and freed through the delegating zone's forwarding.
            let delegated = malloc(40);
            assert_eq!(malloc_zone_from_ptr(delegated), real_default);
            free(delegated);

            // `InitializeDefaultMallocZoneWithPartitionAlloc`, in the framework.
            BACKING = malloc_create_zone(0, 0);
            malloc_zone_unregister(BACKING);
            let pa: &'static mut MallocZone = Box::leak(Box::new(guest_zone(c"PartitionAlloc")));
            pa.size = Some(pa_size);
            pa.malloc = Some(pa_malloc);
            pa.calloc = Some(pa_calloc);
            pa.realloc = Some(pa_realloc);
            pa.free = Some(pa_free);
            pa.free_definite_size = None;
            pa.version = 9;
            let pa: *mut MallocZone = pa;
            (*pa).version = 13;
            (*pa).try_free_default = Some(pa_try_free_default);
            assert_eq!(
                name(registered()[0]),
                "DelegatingDefaultZoneForPartitionAlloc"
            );
            malloc_zone_register(pa);
            malloc_zone_unregister(delegating);
            assert_eq!(registered(), [pa, real_default, purgeable]);

            // `malloc` now reaches PartitionAlloc, and its blocks are its own.
            let block = malloc(100);
            assert_eq!(PA_MALLOCS.load(Ordering::Relaxed), 1);
            assert!(malloc_size(block) >= 100);
            assert_eq!(malloc_zone_from_ptr(block), malloc_default_zone());
            let zeroed = calloc(4, 4);
            assert_eq!(PA_MALLOCS.load(Ordering::Relaxed), 2);
            let block = realloc(block, 5000);
            assert!(pa_size(pa, block) != 0, "resized by the zone that owns it");
            free(block);
            free(zeroed);
            assert_eq!(PA_FREES.load(Ordering::Relaxed), 2);
            assert_eq!(PA_FALLBACKS.load(Ordering::Relaxed), 0);

            // A block from before the switch - or one the host made - goes back
            // to the default zone through PartitionAlloc's fallback walk.
            free(early);
            assert_eq!(PA_FALLBACKS.load(Ordering::Relaxed), 1);
            let host = mi::mi_malloc(64);
            assert_eq!(malloc_zone_from_ptr(host), real_default);
            free(host);
            assert_eq!(PA_FALLBACKS.load(Ordering::Relaxed), 2);
            assert_eq!(PA_FREES.load(Ordering::Relaxed), 2);

            // The virtual default zone follows the first zone.
            let through_default = malloc_zone_malloc(malloc_default_zone(), 8);
            assert_eq!(PA_MALLOCS.load(Ordering::Relaxed), 3);
            malloc_zone_free(malloc_default_zone(), through_default);
            assert_eq!(PA_FREES.load(Ordering::Relaxed), 3);
        }
    }

    /// The fork handlers take the registry lock and every zone's, and give
    /// them back on both sides.
    #[test]
    fn fork_handlers_lock_and_release_every_zone() {
        in_child("fork_handlers_child");
    }

    #[test]
    fn fork_handlers_child() {
        if !is_child("fork_handlers_child") {
            return;
        }
        static LOCKS: AtomicUsize = AtomicUsize::new(0);
        static UNLOCKS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn lock(_: *mut MallocZone) {
            LOCKS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn unlock(_: *mut MallocZone) {
            UNLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        static mut INTROSPECT: Introspection = Introspection {
            enumerator: None,
            good_size: None,
            check: None,
            print: None,
            log: None,
            force_lock: Some(lock),
            force_unlock: Some(unlock),
            statistics: None,
            zone_locked: None,
            enable_discharge_checking: None,
            disable_discharge_checking: None,
            discharge: None,
            enumerate_discharged_pointers: None,
            reinit_lock: Some(unlock),
            print_task: None,
            task_statistics: None,
            zone_type: 0,
        };
        unsafe {
            let zone: &'static mut MallocZone = Box::leak(Box::new(guest_zone(c"Locking")));
            zone.size = Some(delegating_size);
            zone.introspect = &raw mut INTROSPECT;
            malloc_zone_register(zone);

            let child = libc::fork();
            if child == 0 {
                // The child's handlers ran, and allocating works.
                let ok = UNLOCKS.load(Ordering::Relaxed) == 1 && !malloc(10).is_null();
                libc::_exit(if ok { 0 } else { 1 });
            }
            assert_eq!(LOCKS.load(Ordering::Relaxed), 1);
            assert_eq!(UNLOCKS.load(Ordering::Relaxed), 1);
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "{status:#x}"
            );
            // The parent's registry lock was given back.
            let zone = malloc_create_zone(0, 0);
            malloc_destroy_zone(zone);
        }
    }
}
