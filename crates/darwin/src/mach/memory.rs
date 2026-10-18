//! Named memory entries, and the calls that map memory by them or by address:
//! `mach_make_memory_entry_64`, `mach_vm_map`, `mach_vm_remap` and
//! `mach_vm_read`.
//!
//! XNU's named entry (`osfmk/vm/vm_memory_entry.c`) is a port standing for a
//! range of a VM object. `mach_vm_map` maps that range, and the port can be
//! sent to another task, which maps the same pages: it is how a Mach program
//! shares memory. Here the object is a memfd. That is what lets a range cross
//! to another process - the descriptor travels with the right (see
//! [`super::msg`]) and both sides map the same file.
//!
//! Memory this runtime did not make has no file behind it to share. An entry
//! asked for over private memory moves that range into one first: the contents
//! are copied into a fresh memfd, which is then mapped shared over the range in
//! place. To the task nothing has changed except that the pages can now be
//! shared, which is what it asked for. A store another thread makes to the
//! range while it is being copied can be lost; XNU has no such window, and no
//! host call closes it. A *shared* mapping of something else - a file, another
//! library's memfd - is refused rather than moved, since moving it would
//! quietly stop it being shared with whatever it is shared with.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};

use starnix::process::{FileId, Region};

use super::kern::*;
use super::space::{self, MACH_PORT_DEAD, MACH_PORT_NULL, Name, TaskFlavor};

/// `VM_PROT_*`, which are also the host's `PROT_*` bits.
pub const VM_PROT_READ: i32 = 0x1;
pub const VM_PROT_WRITE: i32 = 0x2;
pub const VM_PROT_EXECUTE: i32 = 0x4;
const VM_PROT_ALL: i32 = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
/// `VM_PROT_IS_MASK`: "whichever of these the memory allows".
const VM_PROT_IS_MASK: i32 = 0x40;

/// `<mach/memory_object_types.h>`: the permission word of
/// `mach_make_memory_entry_64` is protections in the low byte, these flags in
/// the middle two, and a caching mode in the top one.
const MAP_MEM_PROT_MASK: i32 = 0xff;
const MAP_MEM_FLAGS_MASK: i32 = 0x00ff_ff00;
const MAP_MEM_LEDGER_TAGGED: i32 = 0x0000_2000;
const MAP_MEM_PURGABLE_KERNEL_ONLY: i32 = 0x0000_4000;
const MAP_MEM_GRAB_SECLUDED: i32 = 0x0000_8000;
const MAP_MEM_ONLY: i32 = 0x0001_0000;
const MAP_MEM_NAMED_CREATE: i32 = 0x0002_0000;
const MAP_MEM_PURGABLE: i32 = 0x0004_0000;
const MAP_MEM_NAMED_REUSE: i32 = 0x0008_0000;
const MAP_MEM_USE_DATA_ADDR: i32 = 0x0010_0000;
const MAP_MEM_VM_COPY: i32 = 0x0020_0000;
const MAP_MEM_VM_SHARE: i32 = 0x0040_0000;
const MAP_MEM_4K_DATA_ADDR: i32 = 0x0080_0000;
const MAP_MEM_FLAGS_USER: i32 = MAP_MEM_PURGABLE_KERNEL_ONLY
    | MAP_MEM_GRAB_SECLUDED
    | MAP_MEM_ONLY
    | MAP_MEM_NAMED_CREATE
    | MAP_MEM_PURGABLE
    | MAP_MEM_NAMED_REUSE
    | MAP_MEM_USE_DATA_ADDR
    | MAP_MEM_VM_COPY
    | MAP_MEM_VM_SHARE
    | MAP_MEM_LEDGER_TAGGED
    | MAP_MEM_4K_DATA_ADDR;

/// `<mach/vm_statistics.h>`.
const VM_FLAGS_ANYWHERE: i32 = 0x0000_0001;
const VM_FLAGS_PURGABLE: i32 = 0x0000_0002;
const VM_FLAGS_4GB_CHUNK: i32 = 0x0000_0004;
const VM_FLAGS_RANDOM_ADDR: i32 = 0x0000_0008;
const VM_FLAGS_NO_CACHE: i32 = 0x0000_0010;
const VM_FLAGS_RESILIENT_CODESIGN: i32 = 0x0000_0020;
const VM_FLAGS_RESILIENT_MEDIA: i32 = 0x0000_0040;
const VM_FLAGS_PERMANENT: i32 = 0x0000_0080;
const VM_FLAGS_TPRO: i32 = 0x0000_1000;
const VM_FLAGS_OVERWRITE: i32 = 0x0000_4000;
const VM_FLAGS_SUPERPAGE_MASK: i32 = 0x0007_0000;
const VM_FLAGS_RETURN_DATA_ADDR: i32 = 0x0010_0000;
const VM_FLAGS_RETURN_4K_DATA_ADDR: i32 = 0x0080_0000;
const VM_FLAGS_ALIAS_MASK: i32 = 0xff00_0000_u32 as i32;
/// `VM_FLAGS_USER_MAP`: what `mach_vm_map` accepts from user space.
const VM_FLAGS_USER_MAP: i32 = VM_FLAGS_ANYWHERE
    | VM_FLAGS_PURGABLE
    | VM_FLAGS_4GB_CHUNK
    | VM_FLAGS_RANDOM_ADDR
    | VM_FLAGS_NO_CACHE
    | VM_FLAGS_PERMANENT
    | VM_FLAGS_OVERWRITE
    | VM_FLAGS_SUPERPAGE_MASK
    | VM_FLAGS_TPRO
    | VM_FLAGS_ALIAS_MASK
    | VM_FLAGS_RETURN_4K_DATA_ADDR
    | VM_FLAGS_RETURN_DATA_ADDR;
/// `VM_FLAGS_USER_REMAP`: what `mach_vm_remap` accepts.
const VM_FLAGS_USER_REMAP: i32 = VM_FLAGS_ANYWHERE
    | VM_FLAGS_RANDOM_ADDR
    | VM_FLAGS_OVERWRITE
    | VM_FLAGS_RETURN_DATA_ADDR
    | VM_FLAGS_RESILIENT_CODESIGN
    | VM_FLAGS_RESILIENT_MEDIA;

/// `VM_INHERIT_NONE`, which is also `VM_INHERIT_LAST_VALID`.
const VM_INHERIT_NONE: u32 = 2;

fn page() -> u64 {
    super::info::page_size()
}

fn page_mask() -> u64 {
    page() - 1
}

fn trunc_page(value: u64) -> u64 {
    value & !page_mask()
}

/// `vm_map_round_page`, which wraps to zero where this answers `None`.
fn round_page(value: u64) -> Option<u64> {
    Some(value.checked_add(page_mask())? & !page_mask())
}

/// A VM object: a memfd, and the file it is as `fstat` names it.
pub struct Object {
    fd: OwnedFd,
    id: FileId,
    /// Its length when it was made or arrived, which nothing here changes.
    size: u64,
}

impl Object {
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Every object this process knows the descriptor of, by its file.
///
/// A mapping does not hold the descriptor - the host does that through the
/// mapping - so an entry made later over mapped memory has to find the object
/// from the file `/proc/self/maps` names. An object stays here while an entry
/// holds it or something maps it; [`sweep`] lets the rest go.
struct Registry {
    objects: HashMap<FileId, Arc<Object>>,
    /// How many there were after the last sweep, so that sweeping - which
    /// reads the whole map - happens as the table doubles rather than on every
    /// object.
    swept: usize,
}

fn registry() -> MutexGuard<'static, Registry> {
    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
        Mutex::new(Registry {
            objects: HashMap::new(),
            swept: 0,
        })
    });
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Drop the objects nothing holds and nothing maps.
fn sweep(registry: &mut Registry) {
    if registry.objects.len() < (2 * registry.swept).max(64) {
        return;
    }
    let mapped: HashSet<FileId> = starnix::process::regions()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|region| region.file)
        .collect();
    registry
        .objects
        .retain(|id, object| Arc::strong_count(object) > 1 || mapped.contains(id));
    registry.swept = registry.objects.len();
}

/// The object for `fd`: the one already known for its file, or a new one.
fn register(fd: OwnedFd) -> Result<Arc<Object>, i32> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live descriptor and a writable `stat`.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(KERN_FAILURE);
    }
    let id = (stat.st_dev as u64, stat.st_ino as u64);
    let mut registry = registry();
    if let Some(object) = registry.objects.get(&id) {
        return Ok(object.clone());
    }
    sweep(&mut registry);
    let object = Arc::new(Object {
        fd,
        id,
        size: stat.st_size as u64,
    });
    registry.objects.insert(id, object.clone());
    Ok(object)
}

fn lookup(id: FileId) -> Option<Arc<Object>> {
    registry().objects.get(&id).cloned()
}

/// A new zero-filled object of `size` bytes.
fn create(size: u64) -> Result<Arc<Object>, i32> {
    let length = libc::off_t::try_from(size).map_err(|_| KERN_RESOURCE_SHORTAGE)?;
    let fd = anonymous_file().ok_or(KERN_RESOURCE_SHORTAGE)?;
    // SAFETY: a live descriptor.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), length) } != 0 {
        return Err(KERN_RESOURCE_SHORTAGE);
    }
    register(fd)
}

/// A file with no name, for an object's pages.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(super) fn anonymous_file() -> Option<OwnedFd> {
    // SAFETY: a NUL-terminated name and a flag word.
    let raw = unsafe { libc::memfd_create(c"mach memory entry".as_ptr(), libc::MFD_CLOEXEC) };
    // SAFETY: a descriptor just made and owned by nothing else.
    (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) })
}

/// A file with no name, for an object's pages: a POSIX shared memory object
/// unlinked as soon as it is open.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub(super) fn anonymous_file() -> Option<OwnedFd> {
    let name = format!("/rosemary-{:016x}\0", fresh_id());
    // SAFETY: a NUL-terminated name.
    let raw = unsafe {
        libc::shm_open(
            name.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: the name just made.
    unsafe { libc::shm_unlink(name.as_ptr().cast()) };
    // SAFETY: a descriptor just made and owned by nothing else.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `MAP_FIXED` that fails where something is mapped already, where the host
/// has one; elsewhere a hint, which [`reserve`] checks.
#[cfg(target_os = "linux")]
const MAP_FIXED_NOREPLACE: libc::c_int = libc::MAP_FIXED_NOREPLACE;
#[cfg(target_os = "freebsd")]
const MAP_FIXED_NOREPLACE: libc::c_int = libc::MAP_FIXED | libc::MAP_EXCL;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
const MAP_FIXED_NOREPLACE: libc::c_int = 0;

/// Address space without memory behind it yet.
#[cfg(target_os = "linux")]
const MAP_NORESERVE: libc::c_int = libc::MAP_NORESERVE;
#[cfg(not(target_os = "linux"))]
const MAP_NORESERVE: libc::c_int = 0;

/// A named entry: a range of an object, and what may be done with it.
pub struct Entry {
    /// Which port this is, the same in every task it reaches, so that the same
    /// entry sent twice arrives under one name as XNU's does.
    pub id: u64,
    pub object: Arc<Object>,
    /// Where the range starts in the object, page-aligned.
    pub offset: u64,
    /// Its length, page-aligned.
    pub size: u64,
    /// `data_offset`: where the caller's data starts in the first page, for
    /// `MAP_MEM_USE_DATA_ADDR` and `VM_FLAGS_RETURN_DATA_ADDR`.
    pub data_offset: u64,
    pub protection: i32,
    /// `is_copy`: made by `MAP_MEM_VM_COPY` or `MAP_MEM_VM_SHARE`, and so
    /// mapped whole whatever offset a mapping asks for, as XNU maps a
    /// `vm_map_copy_t`.
    pub copy: bool,
    /// The copy is copy-on-write - `MAP_MEM_VM_COPY` - so every mapping of it
    /// is a private copy of what was there when the entry was made.
    pub private: bool,
}

impl Entry {
    /// An entry that arrived from another task, its object's descriptor with
    /// it.
    pub fn adopt(fd: OwnedFd, fields: Fields) -> Result<Arc<Entry>, i32> {
        let object = register(fd)?;
        Ok(Arc::new(Entry {
            id: fields.id,
            object,
            offset: fields.offset,
            size: fields.size,
            data_offset: fields.data_offset,
            protection: fields.protection,
            copy: fields.copy,
            private: fields.private,
        }))
    }

    /// Everything but the object, as it crosses to another task.
    pub fn fields(&self) -> Fields {
        Fields {
            id: self.id,
            offset: self.offset,
            size: self.size,
            data_offset: self.data_offset,
            protection: self.protection,
            copy: self.copy,
            private: self.private,
        }
    }
}

/// An [`Entry`] without its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub id: u64,
    pub offset: u64,
    pub size: u64,
    pub data_offset: u64,
    pub protection: i32,
    pub copy: bool,
    pub private: bool,
}

fn fresh_id() -> u64 {
    super::wire::fresh_address()
}

/// Whether `task` is this task, under any name that can change its memory.
fn own_task(task: Name) -> bool {
    space::task_pid_as(task, TaskFlavor::Control) == Some(starnix::process::me())
}

/// One mapping's share of a range: where, with what protection, and what is
/// behind it.
#[derive(Clone, Copy, Debug)]
struct Piece {
    start: u64,
    end: u64,
    protection: i32,
    shared: bool,
    file: Option<FileId>,
    /// The object offset at `start`.
    offset: u64,
}

fn protection_of(region: &Region) -> i32 {
    (if region.read { VM_PROT_READ } else { 0 })
        | (if region.write { VM_PROT_WRITE } else { 0 })
        | (if region.execute { VM_PROT_EXECUTE } else { 0 })
}

/// The mappings that make up `[start, end)`, clipped to it, or
/// `KERN_INVALID_ADDRESS` if any of it is unmapped - or, with `leading`, if
/// `start` is: the run up to the first hole is then enough.
fn pieces(start: u64, end: u64, leading: bool) -> Result<Vec<Piece>, i32> {
    let regions = starnix::process::regions().map_err(|_| KERN_FAILURE)?;
    let mut out = Vec::new();
    let mut cursor = start;
    for region in regions.iter().filter(|r| r.end > start && r.start < end) {
        if region.start > cursor {
            if leading && !out.is_empty() {
                return Ok(out);
            }
            return Err(KERN_INVALID_ADDRESS);
        }
        let from = region.start.max(start);
        out.push(Piece {
            start: from,
            end: region.end.min(end),
            protection: protection_of(region),
            shared: region.shared,
            file: region.file,
            offset: region.offset + (from - region.start),
        });
        cursor = region.end;
    }
    if out.is_empty() || (cursor < end && !leading) {
        return Err(KERN_INVALID_ADDRESS);
    }
    Ok(out)
}

/// Copy `[address, address + length)` of this process into `fd` at `offset`.
///
/// Through `pwrite` first, which reads the memory as the kernel and so fails
/// rather than faulting on a page that is not readable; such a page is then
/// read through `/proc/self/mem`, which can.
fn copy_out(address: u64, length: u64, fd: RawFd, offset: u64) -> Result<(), i32> {
    let mut done = 0u64;
    while done < length {
        // SAFETY: the kernel reads the source as this process; an unreadable
        // page is `EFAULT`, not a fault.
        let wrote = unsafe {
            libc::pwrite(
                fd,
                (address + done) as *const c_void,
                (length - done) as usize,
                (offset + done) as libc::off_t,
            )
        };
        if wrote > 0 {
            done += wrote as u64;
            continue;
        }
        if wrote < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return copy_out_forced(address + done, length - done, fd, offset + done);
    }
    Ok(())
}

/// [`copy_out`] for memory the process cannot read as itself.
fn copy_out_forced(address: u64, length: u64, fd: RawFd, offset: u64) -> Result<(), i32> {
    use std::os::unix::fs::FileExt;
    let memory = std::fs::File::open("/proc/self/mem").map_err(|_| KERN_PROTECTION_FAILURE)?;
    let mut buffer = vec![0u8; length.min(1 << 20) as usize];
    let mut done = 0u64;
    while done < length {
        let chunk = (length - done).min(buffer.len() as u64) as usize;
        memory
            .read_exact_at(&mut buffer[..chunk], address + done)
            .map_err(|_| KERN_PROTECTION_FAILURE)?;
        // SAFETY: a live descriptor and `chunk` initialized bytes.
        let wrote = unsafe {
            libc::pwrite(
                fd,
                buffer.as_ptr().cast(),
                chunk,
                (offset + done) as libc::off_t,
            )
        };
        if wrote <= 0 {
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        done += wrote as u64;
    }
    Ok(())
}

/// Fill `[address, address + length)`, which is writable, from `fd` at
/// `offset`.
fn copy_in(address: u64, length: u64, fd: RawFd, offset: u64) -> Result<(), i32> {
    let mut done = 0u64;
    while done < length {
        // SAFETY: the caller's writable range.
        let read = unsafe {
            libc::pread(
                fd,
                (address + done) as *mut c_void,
                (length - done) as usize,
                (offset + done) as libc::off_t,
            )
        };
        if read > 0 {
            done += read as u64;
        } else if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return Err(KERN_FAILURE);
        }
    }
    Ok(())
}

/// Move the private memory `[start, end)` into a fresh object, mapped shared
/// over the same range with the same protections.
fn share_in_place(pieces: &[Piece]) -> Result<Arc<Object>, i32> {
    let start = pieces[0].start;
    let end = pieces[pieces.len() - 1].end;
    let object = create(end - start)?;
    for piece in pieces {
        copy_out(
            piece.start,
            piece.end - piece.start,
            object.fd(),
            piece.start - start,
        )?;
    }
    for piece in pieces {
        // SAFETY: replaces memory the caller named with a mapping of a copy
        // of the same bytes.
        let mapped = unsafe {
            libc::mmap(
                piece.start as *mut c_void,
                (piece.end - piece.start) as usize,
                piece.protection,
                libc::MAP_SHARED | libc::MAP_FIXED,
                object.fd(),
                (piece.start - start) as libc::off_t,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(KERN_RESOURCE_SHORTAGE);
        }
    }
    Ok(object)
}

/// Say once that a range could not be shared, and why.
fn cannot_share(why: &str) {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| eprintln!("rosemary: a memory entry over this range is refused: {why}"));
}

/// The object a known shared piece maps, if this runtime made it.
fn known(piece: &Piece) -> Option<Arc<Object>> {
    piece
        .shared
        .then_some(piece.file)
        .flatten()
        .and_then(lookup)
}

/// XNU's single-object extraction: the first map entry of a range, or here
/// the run of one object the first piece starts.
fn first_object(mut pieces: Vec<Piece>) -> Vec<Piece> {
    let keep = match known(&pieces[0]) {
        Some(object) => {
            let delta = pieces[0].offset.wrapping_sub(pieces[0].start);
            pieces
                .iter()
                .take_while(|piece| {
                    piece.shared
                        && piece.file == Some(object.id)
                        && piece.offset.wrapping_sub(piece.start) == delta
                })
                .count()
        }
        None => 1,
    };
    pieces.truncate(keep);
    pieces
}

/// The one object behind `pieces`, which are contiguous, and the offset of
/// the first in it - moving them into a new object first if they are
/// private memory.
fn backing(pieces: &[Piece]) -> Result<(Arc<Object>, u64), i32> {
    let first = &pieces[0];
    if let Some(object) = known(first) {
        let delta = first.offset.wrapping_sub(first.start);
        let one = pieces.iter().all(|piece| {
            piece.shared
                && piece.file == Some(object.id)
                && piece.offset.wrapping_sub(piece.start) == delta
        });
        if !one {
            cannot_share(
                "it spans more than one object, which this runtime cannot name as one entry",
            );
            return Err(KERN_INVALID_ARGUMENT);
        }
        return Ok((object, first.offset));
    }
    if pieces.iter().any(|piece| piece.shared) {
        cannot_share("it is, or takes in, a shared mapping this runtime did not make");
        return Err(KERN_INVALID_ARGUMENT);
    }
    Ok((share_in_place(pieces)?, 0))
}

/// `vm_sanitize_addr_size` with page-aligned results: the pages `[offset,
/// offset + size)` touches, or `KERN_INVALID_ARGUMENT` for a range that
/// overflows or rounds to nothing.
fn aligned_range(offset: u64, size: u64) -> Result<(u64, u64), i32> {
    let start = trunc_page(offset);
    let end = offset
        .checked_add(size)
        .and_then(round_page)
        .ok_or(KERN_INVALID_ARGUMENT)?;
    if end <= start {
        return Err(KERN_INVALID_ARGUMENT);
    }
    Ok((start, end))
}

/// What a successful `mach_make_memory_entry_64` hands back.
struct Made {
    size: u64,
    name: Name,
}

/// `kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
/// memory_object_size_t *size, memory_object_offset_t offset, vm_prot_t
/// permission, mach_port_t *object_handle, mem_entry_name_port_t
/// parent_entry)`, and `mach_make_memory_entry`, its LP64 twin.
///
/// # Safety
///
/// `size` and `object_handle` are writable.
pub unsafe extern "C" fn mach_make_memory_entry_64(
    task: Name,
    size: *mut u64,
    offset: u64,
    permission: i32,
    object_handle: *mut Name,
    parent: Name,
) -> i32 {
    if size.is_null() || object_handle.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    // SAFETY: the caller's word.
    let requested = unsafe { size.read() };
    match make_entry(task, requested, offset, permission, parent) {
        Ok(Some(made)) => {
            // SAFETY: the caller's two words.
            unsafe {
                size.write(made.size);
                object_handle.write(made.name);
            }
            KERN_SUCCESS
        }
        // `MAP_MEM_ONLY`, which changes the parent and makes nothing.
        Ok(None) => {
            // SAFETY: as above.
            unsafe { object_handle.write(MACH_PORT_NULL) };
            KERN_SUCCESS
        }
        // `mach_make_memory_entry_cleanup` zeroes the kernel's copies, but a
        // failed MIG reply carries nothing back: the caller's two words are
        // as they were.
        Err(code) => code,
    }
}

/// `mach_make_memory_entry_internal`'s dispatch on the permission word.
fn make_entry(
    task: Name,
    size: u64,
    offset: u64,
    permission: i32,
    parent: Name,
) -> Result<Option<Made>, i32> {
    // `vm_sanitize_memory_entry_perm`: an unknown flag is refused, and stray
    // protection bits are dropped.
    if permission & MAP_MEM_FLAGS_MASK & !MAP_MEM_FLAGS_USER != 0 {
        return Err(KERN_INVALID_VALUE);
    }
    let permission =
        (permission & !MAP_MEM_PROT_MASK) | (permission & (VM_PROT_ALL | VM_PROT_IS_MASK));
    if space::task_of(task).is_none() {
        return Err(KERN_INVALID_TASK);
    }
    let parent = match parent {
        MACH_PORT_NULL | MACH_PORT_DEAD => None,
        name => match space::with_right(name, |_| ()) {
            None => return Err(MACH_SEND_INVALID_RIGHT),
            Some(()) => space::memory_entry(name),
        },
    };
    if parent.as_ref().is_some_and(|parent| parent.copy) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let data_addr = permission & (MAP_MEM_USE_DATA_ADDR | MAP_MEM_4K_DATA_ADDR) != 0;
    if permission & MAP_MEM_ONLY != 0 {
        // A change of caching mode, which this host has no say over; what is
        // checked is what XNU checks before making it.
        return match parent {
            Some(_) if !data_addr => Ok(None),
            _ => Err(KERN_INVALID_ARGUMENT),
        };
    }
    if permission & MAP_MEM_NAMED_CREATE != 0 {
        return named_create(size, offset, permission);
    }
    // Every other kind reads this task's own memory, which is the only memory
    // here this runtime can turn into an object.
    if !own_task(task) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if permission & MAP_MEM_VM_COPY != 0 {
        return copy_entry(size, offset, permission).map(Some);
    }
    match parent {
        Some(parent) if permission & (MAP_MEM_VM_SHARE | MAP_MEM_NAMED_REUSE) == 0 => {
            from_parent(size, offset, permission, &parent).map(Some)
        }
        parent => share_entry(size, offset, permission, parent).map(Some),
    }
}

/// `mach_make_memory_entry_named_create`: a new object of `size` bytes.
fn named_create(size: u64, offset: u64, permission: i32) -> Result<Option<Made>, i32> {
    // Nothing asked for, nothing made, and that is a success.
    if size == 0 {
        return Ok(Some(Made {
            size: 0,
            name: MACH_PORT_NULL,
        }));
    }
    let (start, end) = aligned_range(offset, size)?;
    if permission & (MAP_MEM_USE_DATA_ADDR | MAP_MEM_4K_DATA_ADDR) != 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // What cannot be written cannot be purged.
    if permission & MAP_MEM_PURGABLE != 0 && permission & VM_PROT_WRITE == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let length = end - start;
    let object = create(length).map_err(|_| KERN_FAILURE)?;
    let entry = Arc::new(Entry {
        id: fresh_id(),
        object,
        offset: 0,
        size: length,
        data_offset: 0,
        protection: permission & VM_PROT_ALL,
        copy: false,
        private: false,
    });
    Ok(Some(Made {
        size: length,
        name: space::insert_memory(entry),
    }))
}

/// The in-page offset `MAP_MEM_USE_DATA_ADDR` keeps, and the 4K-aligned one
/// `MAP_MEM_4K_DATA_ADDR` keeps.
fn offset_in_page(offset: u64, start: u64, permission: i32) -> u64 {
    if permission & MAP_MEM_4K_DATA_ADDR != 0 {
        (offset - start) & !0xfff
    } else if permission & MAP_MEM_USE_DATA_ADDR != 0 {
        offset - start
    } else {
        0
    }
}

/// `mach_make_memory_entry_copy`: a copy-on-write snapshot of a range of
/// this task.
fn copy_entry(size: u64, offset: u64, permission: i32) -> Result<Made, i32> {
    if size == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let (start, end) = aligned_range(offset, size)?;
    let data_offset = offset_in_page(offset, start, permission);
    let pieces = pieces(start, end, false)?;
    let object = create(end - start)?;
    for piece in &pieces {
        copy_out(
            piece.start,
            piece.end - piece.start,
            object.fd(),
            piece.start - start,
        )?;
    }
    let entry = Arc::new(Entry {
        id: fresh_id(),
        object,
        offset: 0,
        size: end - start,
        data_offset,
        protection: permission & VM_PROT_ALL,
        copy: true,
        private: true,
    });
    Ok(Made {
        size: end - start - data_offset,
        name: space::insert_memory(entry),
    })
}

/// `mach_make_memory_entry_share`: the memory at a range of this task, the
/// same pages and not a copy of them.
fn share_entry(
    size: u64,
    offset: u64,
    permission: i32,
    parent: Option<Arc<Entry>>,
) -> Result<Made, i32> {
    if size == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let (start, end) = aligned_range(offset, size)?;
    let data_offset = offset_in_page(offset, start, permission);
    // `MAP_MEM_VM_SHARE` extracts the whole range; anything else stops at
    // the first change of object, and the entry is only as long as that.
    let whole = permission & MAP_MEM_VM_SHARE != 0;
    let pieces = match whole {
        true => pieces(start, end, false)?,
        false => first_object(pieces(start, end, true)?),
    };
    let mut protections = permission & VM_PROT_ALL;
    let available = pieces
        .iter()
        .fold(VM_PROT_ALL, |all, piece| all & piece.protection);
    if permission & VM_PROT_IS_MASK != 0 {
        protections &= available;
        if protections == 0 {
            return Err(KERN_PROTECTION_FAILURE);
        }
    } else if available & protections != protections {
        return Err(KERN_PROTECTION_FAILURE);
    }
    let (object, object_offset) = backing(&pieces)?;
    let length = pieces[pieces.len() - 1].end - start;
    // `MAP_MEM_NAMED_REUSE`: the parent, if it is this very range.
    if permission & MAP_MEM_NAMED_REUSE != 0
        && !whole
        && let Some(parent) = parent
        && Arc::ptr_eq(&parent.object, &object)
        && parent.offset == object_offset
        && parent.size == length
        && parent.data_offset == data_offset
    {
        return Ok(Made {
            size: parent.size - parent.data_offset,
            name: space::insert_memory(parent),
        });
    }
    let entry = Arc::new(Entry {
        id: fresh_id(),
        object,
        offset: object_offset,
        size: length,
        data_offset,
        protection: protections,
        copy: whole,
        private: false,
    });
    Ok(Made {
        size: length - data_offset,
        name: space::insert_memory(entry),
    })
}

/// `mach_make_memory_entry_from_parent_entry`: a sub-range of an entry.
fn from_parent(size: u64, offset: u64, permission: i32, parent: &Entry) -> Result<Made, i32> {
    let data_addr = permission & (MAP_MEM_USE_DATA_ADDR | MAP_MEM_4K_DATA_ADDR) != 0;
    let offset = match data_addr {
        true => offset
            .checked_add(parent.data_offset)
            .ok_or(KERN_INVALID_ARGUMENT)?,
        false => offset,
    };
    let unaligned_end = offset.checked_add(size).ok_or(KERN_INVALID_ARGUMENT)?;
    let start = trunc_page(offset);
    let end = round_page(unaligned_end).ok_or(KERN_INVALID_ARGUMENT)?;
    if end <= start || end > parent.size {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let object_offset = parent
        .offset
        .checked_add(start)
        .ok_or(KERN_INVALID_ARGUMENT)?;
    let mut protections = permission & VM_PROT_ALL;
    if permission & VM_PROT_IS_MASK != 0 {
        protections &= parent.protection;
    }
    if protections & parent.protection != protections {
        return Err(KERN_PROTECTION_FAILURE);
    }
    let data_offset = offset_in_page(offset, start, permission);
    let entry = Arc::new(Entry {
        id: fresh_id(),
        object: parent.object.clone(),
        offset: object_offset,
        size: end - start,
        data_offset,
        protection: protections,
        copy: parent.copy,
        private: parent.private,
    });
    Ok(Made {
        size: end - start - data_offset,
        name: space::insert_memory(entry),
    })
}

/// `kern_return_t mach_memory_object_memory_entry_64(host_t host, boolean_t
/// internal, memory_object_size_t size, vm_prot_t permission, memory_object_t
/// pager, mach_port_t *entry_handle)`, and `mach_memory_object_memory_entry`.
///
/// An entry for a new internal object. Pagers - external objects - are a
/// kernel interface no program here can have one of, so any is refused.
///
/// # Safety
///
/// `entry_handle` is writable.
pub unsafe extern "C" fn mach_memory_object_memory_entry_64(
    host: Name,
    internal: i32,
    size: u64,
    permission: i32,
    pager: Name,
    entry_handle: *mut Name,
) -> i32 {
    if entry_handle.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    if host != space::HOST_SELF {
        return KERN_INVALID_HOST;
    }
    // `vm_sanitize_object_size`, zero failing.
    let Some(size) = round_page(size).filter(|&rounded| size != 0 && rounded != 0) else {
        return KERN_INVALID_ARGUMENT;
    };
    if pager != MACH_PORT_NULL || internal == 0 {
        return KERN_INVALID_ARGUMENT;
    }
    let object = match create(size) {
        Ok(object) => object,
        Err(code) => return code,
    };
    let entry = Arc::new(Entry {
        id: fresh_id(),
        object,
        offset: 0,
        size,
        data_offset: 0,
        protection: permission & VM_PROT_ALL,
        copy: false,
        private: false,
    });
    // SAFETY: the caller's word.
    unsafe { entry_handle.write(space::insert_memory(entry)) };
    KERN_SUCCESS
}

/// `kern_return_t mach_memory_entry_get_page_counts(mach_port_t entry_port,
/// uint64_t *resident_page_count, uint64_t *dirty_page_count, uint64_t
/// *swapped_page_count)`
///
/// Resident is what `mincore` finds in memory, and swapped what the file
/// holds that is not in memory. Dirty is the resident count: a page of an
/// anonymous object has nowhere to be clean against but swap, and one back
/// from swap is counted resident.
///
/// # Safety
///
/// The three counts are writable.
pub unsafe extern "C" fn mach_memory_entry_get_page_counts(
    entry: Name,
    resident: *mut u64,
    dirty: *mut u64,
    swapped: *mut u64,
) -> i32 {
    let Some(entry) = space::memory_entry(entry) else {
        return KERN_INVALID_ARGUMENT;
    };
    if entry.copy || resident.is_null() || dirty.is_null() || swapped.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    let start = trunc_page(entry.offset);
    let Some(end) = entry.offset.checked_add(entry.size).and_then(round_page) else {
        return KERN_INVALID_ARGUMENT;
    };
    let end = end.min(round_page(entry.object.size).unwrap_or(entry.object.size));
    let Some((in_memory, stored)) = page_counts(&entry.object, start, end) else {
        return KERN_FAILURE;
    };
    // SAFETY: the caller's three words.
    unsafe {
        resident.write(in_memory);
        dirty.write(in_memory);
        swapped.write(stored.saturating_sub(in_memory));
    }
    KERN_SUCCESS
}

/// How many pages of `[start, end)` of `object` are in memory, and how many
/// the file holds at all.
fn page_counts(object: &Object, start: u64, end: u64) -> Option<(u64, u64)> {
    if end <= start {
        return Some((0, 0));
    }
    let length = (end - start) as usize;
    // SAFETY: a fresh read-only view of the object, which faults nothing in.
    let view = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            object.fd(),
            start as libc::off_t,
        )
    };
    if view == libc::MAP_FAILED {
        return None;
    }
    let pages = length / page() as usize;
    let mut vector = vec![0u8; pages];
    // SAFETY: the view just made, and a byte per page of it.
    let status = unsafe { libc::mincore(view, length, vector.as_mut_ptr().cast()) };
    // SAFETY: the view just made.
    unsafe { libc::munmap(view, length) };
    if status != 0 {
        return None;
    }
    let in_memory = vector.iter().filter(|byte| *byte & 1 != 0).count() as u64;
    Some((in_memory, stored_pages(object.fd(), start, end)))
}

/// The pages of `[start, end)` a file holds data for, by `SEEK_DATA` and
/// `SEEK_HOLE` - which count a swapped-out page of an anonymous file as data.
fn stored_pages(fd: RawFd, start: u64, end: u64) -> u64 {
    let mut total = 0u64;
    let mut at = start;
    while at < end {
        // SAFETY: a live descriptor; the offset is only read.
        let data = unsafe { libc::lseek(fd, at as libc::off_t, libc::SEEK_DATA) };
        if data < 0 || data as u64 >= end {
            break;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        let hole = match hole < 0 {
            true => end,
            false => (hole as u64).min(end),
        };
        total +=
            round_page(hole).unwrap_or(hole).min(end) / page() - trunc_page(data as u64) / page();
        at = round_page(hole).unwrap_or(end).max(at + page());
    }
    total
}

/// Reserve `size` bytes of address space for a mapping: at `address` for a
/// fixed request, anywhere aligned to `mask` otherwise. Answers with the
/// start of a `PROT_NONE` reservation the caller maps over.
fn reserve(address: u64, size: u64, mask: u64, flags: i32) -> Result<u64, i32> {
    let length = usize::try_from(size).map_err(|_| KERN_NO_SPACE)?;
    if flags & VM_FLAGS_ANYWHERE == 0 {
        let fixed = match flags & VM_FLAGS_OVERWRITE != 0 {
            true => libc::MAP_FIXED,
            false => MAP_FIXED_NOREPLACE,
        };
        // SAFETY: an anonymous reservation, replacing what is there only for
        // `VM_FLAGS_OVERWRITE`, which asks for exactly that.
        let mapped = unsafe {
            libc::mmap(
                address as *mut c_void,
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_NORESERVE | fixed,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(KERN_NO_SPACE);
        }
        if mapped as u64 != address {
            // A kernel that does not know `MAP_FIXED_NOREPLACE` took it as a
            // hint.
            // SAFETY: the reservation just made, which nothing else has seen.
            unsafe { libc::munmap(mapped, length) };
            return Err(KERN_NO_SPACE);
        }
        return Ok(address);
    }
    let mask = mask | page_mask();
    let slack = usize::try_from(mask).map_err(|_| KERN_NO_SPACE)?;
    let over = length.checked_add(slack).ok_or(KERN_NO_SPACE)?;
    // SAFETY: a fresh anonymous reservation.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            over,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(KERN_NO_SPACE);
    }
    let base = base as u64;
    // `vm_map_locate_space`'s own rounding.
    let start = (base + mask) & !mask;
    let start = match start >= base && start + size <= base + over as u64 {
        true => start,
        false => base,
    };
    // SAFETY: the two ends of the reservation just made, outside the part
    // kept.
    unsafe {
        if start > base {
            libc::munmap(base as *mut c_void, (start - base) as usize);
        }
        let tail = start + size;
        if tail < base + over as u64 {
            libc::munmap(tail as *mut c_void, (base + over as u64 - tail) as usize);
        }
    }
    Ok(start)
}

/// Give back a reservation a failed mapping did not use.
fn unreserve(address: u64, size: u64) {
    // SAFETY: a reservation [`reserve`] made for this call.
    unsafe { libc::munmap(address as *mut c_void, size as usize) };
}

/// `VM_INHERIT_NONE`: the range is not in a child at all.
fn inherit(address: u64, size: u64, inheritance: u32) {
    #[cfg(target_os = "linux")]
    if inheritance == VM_INHERIT_NONE {
        // SAFETY: a range this call just mapped.
        unsafe { libc::madvise(address as *mut c_void, size as usize, libc::MADV_DONTFORK) };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (address, size, inheritance);
}

/// Told of each range this module maps with `VM_PROT_EXECUTE`; see
/// [`on_executable`].
static EXECUTABLE: OnceLock<fn(u64, u64, i32)> = OnceLock::new();

/// Have `hook` told of each range a `mach_vm_map` or `mach_vm_remap` maps
/// with `VM_PROT_EXECUTE` - its address, length and `VM_PROT_*` bits - and
/// map such a range readable in its place, for a host that does not execute
/// the guest's pages itself. As `mmap` is, under the same arrangement.
pub fn on_executable(hook: fn(u64, u64, i32)) {
    let _ = EXECUTABLE.set(hook);
}

/// The protection the host is asked for, for `protection`.
fn host_protection(protection: i32) -> i32 {
    match EXECUTABLE.get() {
        Some(_) if protection & VM_PROT_EXECUTE != 0 => {
            (protection & !VM_PROT_EXECUTE) | VM_PROT_READ
        }
        _ => protection,
    }
}

/// Tell [`on_executable`]'s hook that `[address, address + length)` was
/// just mapped with `protection`, if that includes `VM_PROT_EXECUTE`.
fn mapped(address: u64, length: u64, protection: i32) {
    if protection & VM_PROT_EXECUTE != 0
        && let Some(hook) = EXECUTABLE.get()
    {
        hook(address, length, protection);
    }
}

/// Map `[offset, offset + size)` of `object` at `address`, which is
/// reserved: shared, or with `private` a copy of what is there now.
fn map_object(
    address: u64,
    size: u64,
    protection: i32,
    object: &Object,
    offset: u64,
    private: bool,
) -> Result<(), i32> {
    let length = size as usize;
    let host = host_protection(protection);
    if !private {
        // SAFETY: over a reservation this call owns.
        let done = unsafe {
            libc::mmap(
                address as *mut c_void,
                length,
                host,
                libc::MAP_SHARED | libc::MAP_FIXED,
                object.fd(),
                offset as libc::off_t,
            )
        };
        if done == libc::MAP_FAILED {
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        mapped(address, size, protection);
        return Ok(());
    }
    // A copy is what XNU's copy-on-write gives, taken now rather than at the
    // first store: a private file mapping here would go on seeing the pages
    // nobody has written yet change under it.
    // SAFETY: over a reservation this call owns.
    let done = unsafe {
        libc::mmap(
            address as *mut c_void,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if done == libc::MAP_FAILED {
        return Err(KERN_RESOURCE_SHORTAGE);
    }
    copy_in(address, size, object.fd(), offset)?;
    // SAFETY: the mapping just made.
    if unsafe { libc::mprotect(address as *mut c_void, length, host) } != 0 {
        return Err(KERN_PROTECTION_FAILURE);
    }
    mapped(address, size, protection);
    Ok(())
}

/// `vm_sanitize_cur_and_max_prots`: neither has a bit outside `VM_PROT_ALL`
/// and `extra`, and the current is no more than the maximum.
fn sane_protections(current: i32, maximum: i32, extra: i32) -> Result<(), i32> {
    if current & !(VM_PROT_ALL | extra) != 0 || maximum & !(VM_PROT_ALL | extra) != 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if current & maximum & VM_PROT_ALL != current & VM_PROT_ALL {
        return Err(KERN_INVALID_ARGUMENT);
    }
    Ok(())
}

/// The flags of an anonymous `mach_vm_map` this host can honour. The rest
/// change what the memory is - superpages, TPRO - and pretending to grant
/// them would hand back something else.
fn anonymous_flags_supported(flags: i32) -> bool {
    if flags & (VM_FLAGS_SUPERPAGE_MASK | VM_FLAGS_TPRO) != 0 {
        static SAID: std::sync::Once = std::sync::Once::new();
        SAID.call_once(|| {
            eprintln!("rosemary: mach_vm_map: superpage and TPRO mappings are refused")
        });
        return false;
    }
    true
}

/// `kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t
/// *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags,
/// mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t
/// copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t
/// inheritance)`, and `vm_map`, which is the same call on LP64.
///
/// XNU's `vm_map_enter_mem_object`. The maximum protection is checked and
/// otherwise not kept: the host has no ceiling on what `mprotect` may grant.
///
/// # Safety
///
/// `address` is readable and writable.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mach_vm_map(
    task: Name,
    address: *mut u64,
    size: u64,
    mask: u64,
    flags: i32,
    object: Name,
    offset: u64,
    copy: i32,
    current: i32,
    maximum: i32,
    inheritance: u32,
) -> i32 {
    if address.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    if !own_task(task) {
        return KERN_INVALID_ARGUMENT;
    }
    // SAFETY: the caller's word.
    let requested = unsafe { address.read() };
    match map(
        requested,
        size,
        mask,
        flags,
        object,
        offset,
        copy != 0,
        current,
        maximum,
        inheritance,
    ) {
        Ok(mapped) => {
            // SAFETY: as above.
            unsafe { address.write(mapped) };
            KERN_SUCCESS
        }
        Err(code) => code,
    }
}

#[allow(clippy::too_many_arguments)]
fn map(
    requested: u64,
    size: u64,
    mask: u64,
    flags: i32,
    object: Name,
    offset: u64,
    copy: bool,
    current: i32,
    maximum: i32,
    inheritance: u32,
) -> Result<u64, i32> {
    if flags & !VM_FLAGS_USER_MAP != 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    sane_protections(current, maximum, VM_PROT_IS_MASK)?;
    if inheritance > VM_INHERIT_NONE {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let fixed = flags & VM_FLAGS_ANYWHERE == 0;
    if size == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let (map_address, mut map_size) = match fixed {
        // `VM_SANITIZE_FLAGS_REALIGN_START`: the start is truncated before
        // the size is added to it.
        true => {
            let (start, end) = aligned_range(trunc_page(requested), size)?;
            (start, end - start)
        }
        false => (requested, round_page(size).ok_or(KERN_INVALID_ARGUMENT)?),
    };
    let mut object_size = map_size;
    let data_return = flags & (VM_FLAGS_RETURN_DATA_ADDR | VM_FLAGS_RETURN_4K_DATA_ADDR) != 0;
    let mask_current = current & VM_PROT_IS_MASK != 0;
    let mask_maximum = maximum & VM_PROT_IS_MASK != 0;
    let mut current = current & !VM_PROT_IS_MASK;
    let mut maximum = maximum & !VM_PROT_IS_MASK;

    let entry = match object {
        MACH_PORT_NULL | MACH_PORT_DEAD => None,
        name => match space::with_right(name, |_| ()) {
            None => return Err(MACH_SEND_INVALID_RIGHT),
            Some(()) => Some(space::memory_entry(name).ok_or(KERN_INVALID_OBJECT)?),
        },
    };
    let Some(entry) = entry else {
        if !anonymous_flags_supported(flags) {
            return Err(KERN_INVALID_ARGUMENT);
        }
        let at = reserve(map_address, map_size, mask, flags)?;
        // SAFETY: the reservation just made.
        let done = unsafe {
            libc::mmap(
                at as *mut c_void,
                map_size as usize,
                host_protection(current),
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if done == libc::MAP_FAILED {
            unreserve(at, map_size);
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        mapped(at, map_size, current);
        inherit(at, map_size, inheritance);
        return Ok(at);
    };

    // `vm_sanitize_addr_size` on the object's range.
    let mut object_offset = offset;
    let mut object_end = offset
        .checked_add(object_size)
        .ok_or(KERN_INVALID_ARGUMENT)?;
    if round_page(object_end).is_none_or(|end| end <= trunc_page(offset)) {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // `vm_map_enter_adjust_offset`.
    let adjust = |offset: &mut u64, end: &mut u64, by: u64| -> Result<(), i32> {
        *offset = offset.checked_add(by).ok_or(KERN_INVALID_ARGUMENT)?;
        *end = end.checked_add(by).ok_or(KERN_INVALID_ARGUMENT)?;
        if round_page(*end).is_none_or(|end| end == 0) {
            return Err(KERN_INVALID_ARGUMENT);
        }
        Ok(())
    };
    if data_return {
        adjust(&mut object_offset, &mut object_end, entry.data_offset)?;
    }
    if mask_maximum {
        maximum &= entry.protection;
    }
    if mask_current {
        current &= entry.protection;
    }
    if entry.protection & maximum != maximum || entry.protection & current != current {
        return Err(KERN_INVALID_RIGHT);
    }
    if entry.size
        < object_offset
            .checked_add(size)
            .ok_or(KERN_INVALID_ARGUMENT)?
    {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // A copy can only be mapped whole.
    if entry.copy && object_size != entry.size && round_page(object_size) == Some(entry.size) {
        object_end += entry.size - object_size;
        object_size = entry.size;
    }
    if entry.offset != 0 {
        adjust(&mut object_offset, &mut object_end, entry.offset)?;
    }
    if object_size & page_mask() != 0 {
        map_size = object_size;
    }

    if entry.copy {
        let allowed = VM_FLAGS_ANYWHERE
            | VM_FLAGS_OVERWRITE
            | VM_FLAGS_RETURN_4K_DATA_ADDR
            | VM_FLAGS_RETURN_DATA_ADDR
            | VM_FLAGS_ALIAS_MASK;
        if flags & !allowed != 0 {
            return Err(KERN_INVALID_ARGUMENT);
        }
        let mut in_mapping = 0;
        if data_return {
            in_mapping = object_offset & page_mask();
            if flags & VM_FLAGS_RETURN_4K_DATA_ADDR != 0 {
                in_mapping &= !0xfff;
            }
        }
        let whole = entry.size;
        let at = reserve(map_address, whole, mask, flags)?;
        if let Err(code) = map_object(
            at,
            whole,
            current,
            &entry.object,
            entry.offset,
            copy || entry.private,
        ) {
            unreserve(at, whole);
            return Err(code);
        }
        inherit(at, whole, inheritance);
        return Ok(at + in_mapping);
    }

    let mut in_mapping = 0;
    if data_return {
        in_mapping = object_offset & page_mask();
        if flags & VM_FLAGS_RETURN_4K_DATA_ADDR != 0 {
            in_mapping &= !0xfff;
        }
        object_offset -= in_mapping;
        map_size = size
            .checked_add(in_mapping)
            .and_then(round_page)
            .ok_or(KERN_INVALID_ARGUMENT)?;
    }
    // `vm_map_enter` maps whole pages of the object.
    if object_offset & page_mask() != 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    // Past the end of the file is a bus error at the first touch rather
    // than memory, so it is refused here.
    if object_offset.saturating_add(map_size) > entry.object.size {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let at = reserve(map_address, map_size, mask, flags)?;
    if let Err(code) = map_object(at, map_size, current, &entry.object, object_offset, copy) {
        unreserve(at, map_size);
        return Err(code);
    }
    inherit(at, map_size, inheritance);
    Ok(at + in_mapping)
}

/// `kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t
/// *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags,
/// vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy,
/// vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t
/// inheritance)`, and `vm_remap`, which is the same call on LP64.
///
/// The legacy form, whose protections are only answered: the new mapping
/// keeps the source's, range by range. The maximum is reported as all, since
/// the host keeps none.
///
/// # Safety
///
/// `target_address` is readable and writable, and the two protections
/// writable.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mach_vm_remap(
    task: Name,
    target_address: *mut u64,
    size: u64,
    mask: u64,
    flags: i32,
    source_task: Name,
    source_address: u64,
    copy: i32,
    current: *mut i32,
    maximum: *mut i32,
    inheritance: u32,
) -> i32 {
    if target_address.is_null() || current.is_null() || maximum.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    if flags & !VM_FLAGS_USER_REMAP != 0 {
        return KERN_INVALID_ARGUMENT;
    }
    if !own_task(task) || !own_task(source_task) {
        return KERN_INVALID_ARGUMENT;
    }
    // SAFETY: as above.
    let requested = unsafe { target_address.read() };
    match remap(
        requested,
        size,
        mask,
        flags,
        source_address,
        copy != 0,
        inheritance,
    ) {
        Ok((mapped, protection)) => {
            // SAFETY: as above.
            unsafe {
                target_address.write(mapped);
                current.write(protection);
                maximum.write(VM_PROT_ALL);
            }
            KERN_SUCCESS
        }
        Err(code) => code,
    }
}

fn remap(
    requested: u64,
    size: u64,
    mask: u64,
    flags: i32,
    source: u64,
    copy: bool,
    inheritance: u32,
) -> Result<(u64, i32), i32> {
    if inheritance > VM_INHERIT_NONE {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if size == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let data_return = flags & VM_FLAGS_RETURN_DATA_ADDR != 0;
    // Without `VM_FLAGS_RETURN_DATA_ADDR` the start is truncated before the
    // size is added, which is XNU's legacy rounding and what callers of it
    // depend on.
    let (start, end) = match data_return {
        true => aligned_range(source, size)?,
        false => aligned_range(trunc_page(source), size)?,
    };
    let in_mapping = match data_return {
        true => source & page_mask(),
        false => 0,
    };
    if flags & VM_FLAGS_RESILIENT_MEDIA != 0 && !copy {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let length = end - start;
    let pieces = pieces(start, end, false)?;
    let mut protection = pieces
        .iter()
        .fold(VM_PROT_ALL, |all, piece| all & piece.protection);
    let codesign = flags & VM_FLAGS_RESILIENT_CODESIGN != 0;
    if codesign {
        protection = VM_PROT_READ;
    }
    let target = match flags & VM_FLAGS_ANYWHERE != 0 {
        true => requested,
        false => trunc_page(requested),
    };
    let at = reserve(target, length, mask, flags)?;
    let done = match copy {
        true => remap_copy(at, start, &pieces, codesign),
        false => remap_share(at, start, &pieces, codesign),
    };
    if let Err(code) = done {
        unreserve(at, length);
        return Err(code);
    }
    inherit(at, length, inheritance);
    Ok((at + in_mapping, protection))
}

/// A copy of each piece at the same offset from `at`, with its protection.
fn remap_copy(at: u64, start: u64, pieces: &[Piece], codesign: bool) -> Result<(), i32> {
    let length = pieces[pieces.len() - 1].end - start;
    // SAFETY: over the reservation the caller made.
    let done = unsafe {
        libc::mmap(
            at as *mut c_void,
            length as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if done == libc::MAP_FAILED {
        return Err(KERN_RESOURCE_SHORTAGE);
    }
    for piece in pieces {
        // SAFETY: the target is the writable copy just made.
        let copied = unsafe {
            read_own(
                at + (piece.start - start),
                piece.start,
                piece.end - piece.start,
                piece.protection,
            )
        };
        if !copied {
            return Err(KERN_PROTECTION_FAILURE);
        }
    }
    for piece in pieces {
        let protection = match codesign {
            true => VM_PROT_READ,
            false => piece.protection,
        };
        let (into, length) = (at + (piece.start - start), piece.end - piece.start);
        // SAFETY: part of the copy just made.
        unsafe {
            libc::mprotect(
                into as *mut c_void,
                length as usize,
                host_protection(protection),
            )
        };
        mapped(into, length, protection);
    }
    Ok(())
}

/// Copy `length` bytes of this process from `from` to `into`, which is
/// writable, whatever `from`'s protection - which is `protection`.
///
/// # Safety
///
/// `into` is writable for `length` bytes and does not overlap `from`.
#[cfg(target_os = "linux")]
unsafe fn read_own(into: u64, from: u64, length: u64, _protection: i32) -> bool {
    // Through the kernel, so that a page unmapped meanwhile is an error
    // rather than a fault.
    // SAFETY: two single-element vectors over the caller's ranges.
    let read = unsafe {
        libc::process_vm_readv(
            libc::getpid(),
            &libc::iovec {
                iov_base: into as *mut c_void,
                iov_len: length as usize,
            },
            1,
            &libc::iovec {
                iov_base: from as *mut c_void,
                iov_len: length as usize,
            },
            1,
            0,
        )
    };
    if read as i64 == length as i64 {
        return true;
    }
    // An unreadable page, which `/proc/self/mem` reads regardless.
    use std::os::unix::fs::FileExt;
    let Ok(memory) = std::fs::File::open("/proc/self/mem") else {
        return false;
    };
    // SAFETY: the caller's writable range.
    let into = unsafe { std::slice::from_raw_parts_mut(into as *mut u8, length as usize) };
    memory.read_exact_at(into, from).is_ok()
}

/// [`read_own`] where the host has no way to read a page this process may
/// not: such a page is refused.
///
/// # Safety
///
/// As the Linux one.
#[cfg(not(target_os = "linux"))]
unsafe fn read_own(into: u64, from: u64, length: u64, protection: i32) -> bool {
    if protection & VM_PROT_READ == 0 {
        return false;
    }
    // SAFETY: a readable mapped range and the caller's writable one.
    unsafe { std::ptr::copy_nonoverlapping(from as *const u8, into as *mut u8, length as usize) };
    true
}

/// The same pages as each piece, at the same offset from `at`.
fn remap_share(at: u64, start: u64, pieces: &[Piece], codesign: bool) -> Result<(), i32> {
    let (object, offset) = backing(pieces)?;
    for piece in pieces {
        let protection = match codesign {
            true => VM_PROT_READ,
            false => piece.protection,
        };
        map_object(
            at + (piece.start - start),
            piece.end - piece.start,
            protection,
            &object,
            offset + (piece.start - start),
            false,
        )?;
    }
    Ok(())
}

/// `kern_return_t mach_vm_read(vm_map_read_t target_task, mach_vm_address_t
/// address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t
/// *dataCnt)`, and `vm_read`.
///
/// The copy arrives as fresh memory in this task, as the out-of-line reply
/// would put it, at the same offset into its first page as the source.
///
/// # Safety
///
/// `data` and `count` are writable.
pub unsafe extern "C" fn mach_vm_read(
    task: Name,
    address: u64,
    size: u64,
    data: *mut u64,
    count: *mut u32,
) -> i32 {
    if data.is_null() || count.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    if !own_task(task) {
        return KERN_INVALID_ARGUMENT;
    }
    let Ok(wanted) = u32::try_from(size) else {
        return KERN_INVALID_ARGUMENT;
    };
    if size == 0 {
        // SAFETY: the caller's words.
        unsafe {
            data.write(0);
            count.write(0);
        }
        return KERN_SUCCESS;
    }
    let Ok((start, end)) = aligned_range(address, size) else {
        return KERN_INVALID_ADDRESS;
    };
    let pieces = match pieces(start, end, false) {
        Ok(pieces) => pieces,
        Err(code) => return code,
    };
    if pieces
        .iter()
        .any(|piece| piece.protection & VM_PROT_READ == 0)
    {
        return KERN_PROTECTION_FAILURE;
    }
    let at = match reserve(0, end - start, 0, VM_FLAGS_ANYWHERE) {
        Ok(at) => at,
        Err(code) => return code,
    };
    if let Err(code) = remap_copy(at, start, &pieces, false) {
        unreserve(at, end - start);
        return code;
    }
    // SAFETY: the copy just made.
    unsafe {
        libc::mprotect(
            at as *mut c_void,
            (end - start) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        data.write(at + (address - start));
        count.write(wanted);
    }
    KERN_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use space::TASK_SELF;

    fn entry(size: u64, permission: i32) -> (Name, u64) {
        let mut size = size;
        let mut name = 0;
        // SAFETY: two writable locals.
        let kr =
            unsafe { mach_make_memory_entry_64(TASK_SELF, &mut size, 0, permission, &mut name, 0) };
        assert_eq!(kr, KERN_SUCCESS);
        assert_ne!(name, MACH_PORT_NULL);
        (name, size)
    }

    fn map_entry(name: Name, size: u64, protection: i32) -> Result<u64, i32> {
        let mut address = 0;
        // SAFETY: a writable local.
        match unsafe {
            mach_vm_map(
                TASK_SELF,
                &mut address,
                size,
                0,
                VM_FLAGS_ANYWHERE,
                name,
                0,
                0,
                protection,
                protection,
                VM_INHERIT_NONE,
            )
        } {
            KERN_SUCCESS => Ok(address),
            code => Err(code),
        }
    }

    /// Chromium's `PlatformSharedMemoryRegion::Create`, then two mappings of
    /// the region, which see each other's stores.
    #[test]
    fn two_mappings_of_a_named_entry_share_their_pages() {
        let (name, size) = entry(100, MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE);
        assert_eq!(size, page());
        let first = map_entry(name, 100, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        let second = map_entry(name, 100, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        assert_ne!(first, second);
        // SAFETY: two mappings of the same page.
        unsafe {
            (first as *mut u32).write(0xfeed_f00d);
            assert_eq!((second as *const u32).read(), 0xfeed_f00d);
        }
        // SAFETY: the two mappings above.
        unsafe {
            super::super::vm::vm_deallocate(TASK_SELF, first, size);
            super::super::vm::vm_deallocate(TASK_SELF, second, size);
        }
        assert_eq!(space::mach_port_deallocate(TASK_SELF, name), KERN_SUCCESS);
    }

    /// `ConvertToReadOnly`: an entry made over a read-only mapping of a region
    /// is read-only, and mapping it writable is `KERN_INVALID_RIGHT` - which is
    /// how Chromium tells the two apart.
    #[test]
    fn a_read_only_entry_refuses_a_writable_mapping() {
        let (name, size) = entry(page(), MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE);
        let writable = map_entry(name, size, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        let readable = map_entry(name, size, VM_PROT_READ).unwrap();
        let mut length = size;
        let mut read_only = 0;
        // SAFETY: two writable locals.
        let kr = unsafe {
            mach_make_memory_entry_64(
                TASK_SELF,
                &mut length,
                readable,
                VM_PROT_READ,
                &mut read_only,
                0,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        assert_eq!(length, size);
        assert_eq!(
            map_entry(read_only, size, VM_PROT_READ | VM_PROT_WRITE),
            Err(KERN_INVALID_RIGHT)
        );
        let again = map_entry(read_only, size, VM_PROT_READ).unwrap();
        // SAFETY: the writable mapping and a read-only one of the same page.
        unsafe {
            (writable as *mut u8).write(7);
            assert_eq!((again as *const u8).read(), 7);
        }
        for address in [writable, readable, again] {
            // SAFETY: mappings made above.
            unsafe { super::super::vm::vm_deallocate(TASK_SELF, address, size) };
        }
        space::mach_port_deallocate(TASK_SELF, read_only);
        space::mach_port_deallocate(TASK_SELF, name);
    }

    /// An entry over ordinary private memory shares it from then on.
    #[test]
    fn an_entry_over_private_memory_shares_it_in_place() {
        let mut address = 0u64;
        // SAFETY: a writable local.
        assert_eq!(
            unsafe { super::super::vm::vm_allocate(TASK_SELF, &mut address, 2 * page(), 1) },
            KERN_SUCCESS
        );
        // SAFETY: the allocation above.
        unsafe { (address as *mut u64).write(42) };
        let mut size = 2 * page();
        let mut name = 0;
        // SAFETY: two writable locals.
        let kr = unsafe {
            mach_make_memory_entry_64(
                TASK_SELF,
                &mut size,
                address,
                VM_PROT_READ | VM_PROT_WRITE,
                &mut name,
                0,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        let view = map_entry(name, size, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        // SAFETY: the original range and a mapping of the same pages.
        unsafe {
            assert_eq!((view as *const u64).read(), 42);
            (address as *mut u64).add(1).write(43);
            assert_eq!((view as *const u64).add(1).read(), 43);
            super::super::vm::vm_deallocate(TASK_SELF, view, size);
            super::super::vm::vm_deallocate(TASK_SELF, address, size);
        }
        space::mach_port_deallocate(TASK_SELF, name);
    }

    #[test]
    fn a_copy_mapping_does_not_see_later_stores() {
        let (name, size) = entry(page(), MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE);
        let shared = map_entry(name, size, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        // SAFETY: the mapping above.
        unsafe { (shared as *mut u8).write(1) };
        let mut copied = 0;
        // SAFETY: a writable local.
        let kr = unsafe {
            mach_vm_map(
                TASK_SELF,
                &mut copied,
                size,
                0,
                VM_FLAGS_ANYWHERE,
                name,
                0,
                1,
                VM_PROT_READ,
                VM_PROT_READ,
                1,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        // SAFETY: both mappings.
        unsafe {
            (shared as *mut u8).write(2);
            assert_eq!((copied as *const u8).read(), 1);
            super::super::vm::vm_deallocate(TASK_SELF, shared, size);
            super::super::vm::vm_deallocate(TASK_SELF, copied, size);
        }
        space::mach_port_deallocate(TASK_SELF, name);
    }

    #[test]
    fn an_unknown_flag_is_an_invalid_value_and_changes_nothing() {
        let mut size = page();
        let mut name = 99;
        // SAFETY: two writable locals.
        let kr = unsafe {
            mach_make_memory_entry_64(TASK_SELF, &mut size, 0, 0x0000_0100 | 3, &mut name, 0)
        };
        assert_eq!(kr, KERN_INVALID_VALUE);
        assert_eq!((size, name), (page(), 99));
    }

    #[test]
    fn a_read_copies_into_fresh_memory_at_the_same_page_offset() {
        let source = [5u8; 64];
        let mut data = 0u64;
        let mut count = 0u32;
        // SAFETY: two writable locals and a live buffer.
        let kr = unsafe {
            mach_vm_read(
                TASK_SELF,
                source.as_ptr() as u64 + 3,
                40,
                &mut data,
                &mut count,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        assert_eq!(count, 40);
        assert_eq!(
            data & page_mask(),
            (source.as_ptr() as u64 + 3) & page_mask()
        );
        // SAFETY: the copy `mach_vm_read` made.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data as *const u8, 40) },
            &[5u8; 40]
        );
        let pages = round_page(data + 40).unwrap() - trunc_page(data);
        // SAFETY: as above.
        unsafe { super::super::vm::vm_deallocate(TASK_SELF, trunc_page(data), pages) };
    }
}
