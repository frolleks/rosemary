//! Dispatch sources, after Apple's libdispatch: `src/source.c` for the object
//! and its handlers, `src/event/event.c` for the types and the timers, and
//! `src/event/event_kevent.c` for how a kernel event becomes pending data.
//!
//! A source watches one thing - a descriptor, a process, a signal, a Mach
//! port, a clock, or nothing but `dispatch_source_merge_data` - and runs its
//! event handler on its target queue with what accumulated since the last
//! run. As in Apple's, everything a source does happens in one invoke at a
//! time on its target queue, in Apple's order: the timer's new configuration,
//! the registration handler, the event handler, unregistering once cancelled
//! or released, the cancel handler, and arming the event again. Kernel events
//! and timers are watched by one manager thread, which only merges what
//! fired into the source's pending data and wakes it.
//!
//! Lock order: a source's `state`, then `TIMERS`, then a source's `config`;
//! `state`, then `KNOTES`. The manager takes `TIMERS` or `KNOTES` and never a
//! source's `state` under either, and nothing runs guest code - a handler,
//! or a block's dispose helper - under any of them.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use super::block;
use super::object::{self, Header, Kind};
use super::queue;
use super::time::{self, Clock};
use crate::kqueue::{self, Kevent64};

const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;
const EVFILT_VNODE: i16 = -4;
const EVFILT_PROC: i16 = -5;
const EVFILT_SIGNAL: i16 = -6;
const EVFILT_MACHPORT: i16 = -8;
const EVFILT_USER: i16 = -10;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
const EV_RECEIPT: u16 = 0x0040;
const EV_DISPATCH: u16 = 0x0080;
const EV_ERROR: u16 = 0x4000;

const NOTE_TRIGGER: u32 = 0x0100_0000;
const NOTE_EXIT: u64 = 0x8000_0000;
const NOTE_FORK: u64 = 0x4000_0000;
const NOTE_EXEC: u64 = 0x2000_0000;
const NOTE_REAP: u64 = 0x1000_0000;
const NOTE_SIGNAL: u64 = 0x0800_0000;
const NOTE_EXITSTATUS: u64 = 0x0400_0000;

/// Darwin's, which is also the host's.
const ESRCH: i64 = 3;
const EBADF: i64 = 9;
/// Darwin's `NSIG`.
const NSIG: u64 = 32;
const MACH_PORT_DEAD: u64 = 0xffff_ffff;
const MACH_RCV_SYNC_PEEK: u64 = 0x0000_8000;

/// What a Mach receive source's data reads once a message is waiting.
const DISPATCH_MACH_RECV_MESSAGE: u64 = 0x2;
const DISPATCH_MACH_SEND_DEAD: u64 = 0x1;
const DISPATCH_MACH_SEND_POSSIBLE: u64 = 0x8;
/// `DISPATCH_VNODE_*`, `NOTE_NONE` included.
const VNODE_MASK: u64 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100;
/// `DISPATCH_MEMORYPRESSURE_*`, public and private.
const MEMORYPRESSURE_MASK: u64 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0xf000_0000;
const PROC_MASK: u64 =
    NOTE_EXIT | NOTE_FORK | NOTE_EXEC | NOTE_EXITSTATUS | NOTE_SIGNAL | NOTE_REAP;

/// `DISPATCH_TIMER_STRICT` and `DISPATCH_TIMER_BACKGROUND`.
const TIMER_STRICT: u64 = 0x1;
const TIMER_BACKGROUND: u64 = 0x2;
/// Where a timer's flags keep its clock: `DISPATCH_TIMER_CLOCK_*`.
const TIMER_CLOCK_SHIFT: u32 = 2;
/// `DISPATCH_TIMER_QOS_COUNT`: normal, critical and background.
const TIMER_QOS_COUNT: u64 = 3;
/// `DISPATCH_TIMER_DISARMED_MARKER`, the low bit of a timer's pending data:
/// the timer left the heap and the fire count is the invoke's to finish.
const DISARMED_MARKER: u64 = 1;
const INT64_MAX: u64 = i64::MAX as u64;

/// `dispatch_source_type_t`: the public `DISPATCH_SOURCE_TYPE_*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Type {
    DataAdd,
    DataOr,
    DataReplace,
    MachSend,
    MachRecv,
    MemoryPressure,
    Proc,
    Read,
    Signal,
    Timer,
    Vnode,
    Write,
}

const TYPES: [Type; 12] = [
    Type::DataAdd,
    Type::DataOr,
    Type::DataReplace,
    Type::MachSend,
    Type::MachRecv,
    Type::MemoryPressure,
    Type::Proc,
    Type::Read,
    Type::Signal,
    Type::Timer,
    Type::Vnode,
    Type::Write,
];

/// The objects `DISPATCH_SOURCE_TYPE_*` take the address of. A guest only
/// passes the address back, so the address is the whole of each one.
#[repr(C)]
struct Tag([u64; 4]);
static TAGS: [Tag; 12] = [const { Tag([0; 4]) }; 12];

/// `&_dispatch_source_type_*` for `ty`.
pub fn type_address(ty: Type) -> u64 {
    let index = TYPES.iter().position(|&t| t == ty).unwrap_or(0);
    &raw const TAGS[index] as u64
}

fn type_at(address: u64) -> Option<Type> {
    TYPES.into_iter().find(|&ty| type_address(ty) == address)
}

/// `dispatch_unote_action_t`: how what fired becomes pending data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    /// `dispatch_source_merge_data` adds, ORs or replaces.
    PassData,
    /// The kernel's count, stored complemented so that zero still fires.
    SetData,
    /// The kernel's count, added.
    AddData,
    /// The kernel's flags within the source's mask, ORed.
    OrFflags,
    Timer,
}

impl Type {
    fn action(self) -> Action {
        match self {
            Type::DataAdd | Type::DataOr | Type::DataReplace => Action::PassData,
            Type::Read | Type::Write => Action::SetData,
            Type::Signal => Action::AddData,
            Type::Timer => Action::Timer,
            _ => Action::OrFflags,
        }
    }

    /// The kernel filter and the flags its registration takes, for a type
    /// whose events come from a kqueue.
    fn knote(self) -> Option<(i16, u16)> {
        match self {
            Type::Read => Some((EVFILT_READ, EV_DISPATCH)),
            Type::Write => Some((EVFILT_WRITE, EV_DISPATCH)),
            Type::MachRecv => Some((EVFILT_MACHPORT, EV_DISPATCH)),
            Type::Signal => Some((EVFILT_SIGNAL, EV_CLEAR)),
            Type::Proc => Some((EVFILT_PROC, EV_CLEAR)),
            Type::Vnode => Some((EVFILT_VNODE, EV_CLEAR)),
            _ => None,
        }
    }
}

/// What `dux_create` makes of a type, handle and mask.
struct Unote {
    handle: u64,
    mask: u64,
    extended: bool,
    /// A timer created on a named clock, which `set_timer` may not change.
    clock: Option<Clock>,
}

/// `dux_create`: the source a type, handle and mask describe, or `None` for
/// `DISPATCH_BAD_INPUT`.
fn unote(ty: Type, handle: u64, mask: u64) -> Option<Unote> {
    // `_dispatch_unote_create`: no bit outside the type's mask, and a type
    // with a mask needs one of them unless it allows none.
    let within =
        |allowed: u64, empty: bool| mask & !allowed == 0 && (allowed == 0 || empty || mask != 0);
    let plain = |handle: u64, valid: bool| {
        valid.then_some(Unote {
            handle,
            mask,
            extended: false,
            clock: None,
        })
    };
    match ty {
        Type::DataAdd | Type::DataOr | Type::DataReplace => plain(handle, handle == 0 && mask == 0),
        Type::Read | Type::Write => plain(handle, within(0, false)),
        Type::Vnode => plain(handle, within(VNODE_MASK, false)),
        Type::Signal => plain(handle, handle != 0 && handle < NSIG && within(0, false)),
        Type::MemoryPressure => plain(handle, handle == 0 && within(MEMORYPRESSURE_MASK, false)),
        Type::MachRecv => plain(handle, handle != 0 && within(MACH_RCV_SYNC_PEEK, true)),
        Type::Proc => (handle != 0 && within(PROC_MASK, false)).then_some(Unote {
            handle,
            mask,
            extended: mask & NOTE_EXITSTATUS != 0,
            clock: None,
        }),
        Type::MachSend => {
            // Legacy: no mask is `DISPATCH_MACH_SEND_DEAD`, no port is a dead one.
            let mask = if mask == 0 {
                DISPATCH_MACH_SEND_DEAD
            } else {
                mask
            };
            let handle = if handle == 0 { MACH_PORT_DEAD } else { handle };
            (mask & !(DISPATCH_MACH_SEND_DEAD | DISPATCH_MACH_SEND_POSSIBLE) == 0).then_some(
                Unote {
                    handle,
                    mask,
                    extended: false,
                    clock: None,
                },
            )
        }
        Type::Timer => {
            let mask = match mask & TIMER_STRICT {
                0 => mask,
                _ => mask & !TIMER_BACKGROUND,
            };
            if mask & !(TIMER_STRICT | TIMER_BACKGROUND) != 0 {
                return None;
            }
            // `DISPATCH_CLOCKID_*` as the handle names the clock for good.
            let clock = match handle {
                0 => None,
                1 => Some(Clock::Uptime),
                2 => Some(Clock::Monotonic),
                3 => Some(Clock::Wall),
                _ => return None,
            };
            Some(Unote {
                handle,
                mask,
                extended: false,
                clock,
            })
        }
    }
}

/// A handler as `_dispatch_source_handler_alloc` keeps it.
#[derive(Clone, Copy)]
enum Handler {
    /// A block this module copied, and releases when it is done with it.
    Block(u64),
    /// A function and the source's context as of when it was fetched.
    Function { function: u64, context: u64 },
}

impl Handler {
    /// `DC_FLAG_FETCH_CONTEXT`: a function handler is called with the
    /// source's context, read at the points Apple's reads it.
    fn fetching(self, handle: u64) -> Handler {
        match self {
            Handler::Function { function, .. } => Handler::Function {
                function,
                // SAFETY: a live source.
                context: unsafe { object::get_context(handle) } as u64,
            },
            block => block,
        }
    }

    /// # Safety
    ///
    /// Guest code whose pointers are thunks, called on the source's queue.
    unsafe fn call(self) {
        match self {
            // SAFETY: a copied block whose invoke is a thunk.
            Handler::Block(b) => unsafe { block::invoke(b) },
            // SAFETY: a `dispatch_function_t`, thunked by its signature.
            Handler::Function { function, context } => unsafe {
                std::mem::transmute::<u64, object::Function>(function)(context as *mut c_void)
            },
        }
    }

    fn dispose(self) {
        if let Handler::Block(b) = self {
            block::release(b);
        }
    }
}

const EVENT: usize = 0;
const CANCEL: usize = 1;
const REGISTRATION: usize = 2;

/// Where a source's kernel registration stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Knote {
    /// None: a source no kernel event feeds, or one not registered.
    None,
    Armed,
    /// Delivered with `EV_DISPATCH`, and off until the invoke enables it.
    Disarmed,
    /// Delivered with `EV_ONESHOT`: the kernel dropped it.
    Gone,
}

struct State {
    /// `DISPATCH_QUEUE_INACTIVE`: created, never activated.
    inactive: bool,
    /// `DISPATCH_QUEUE_ACTIVATED`: activated while suspended, so the last
    /// resume finishes the activation.
    activated: bool,
    suspend: u32,
    /// `DSF_CANCELED`.
    cancelled: bool,
    /// `DQF_RELEASED`: the last external reference is gone.
    released: bool,
    /// `ds_is_installed`.
    installed: bool,
    /// `DSF_DELETED`: unregistered, or never registered.
    deleted: bool,
    /// An invoke is queued or running.
    scheduled: bool,
    /// A handler is running, so a replacement waits for it to return.
    running: bool,
    /// `DSF_STRICT`, from a mandatory cancel handler.
    strict: bool,
    knote: Knote,
    handlers: [Option<Handler>; 3],
    /// Handler replacements made while one was running, applied after.
    deferred: Vec<(usize, Option<Handler>)>,
}

impl State {
    fn runnable(&self) -> bool {
        !self.inactive && !self.activated && self.suspend == 0
    }

    fn dead(&self) -> bool {
        self.cancelled || self.released
    }
}

/// `dispatch_timer_config_s`: what `dispatch_source_set_timer` asked for,
/// until the source applies it.
#[derive(Clone, Copy, Debug)]
struct Config {
    clock: Clock,
    target: u64,
    deadline: u64,
    interval: u64,
}

/// A source. `#[repr(C)]` with the header first, as every dispatch object.
#[repr(C)]
pub struct Source {
    #[allow(dead_code)]
    header: Header,
    ty: Type,
    /// `du_ident`, or for a timer the `DISPATCH_CLOCKID_*` it was made with.
    handle: u64,
    /// `du_fflags`, or for a timer its `STRICT`/`BACKGROUND` flags.
    mask: u64,
    /// `du_has_extended_status`.
    extended: bool,
    fixed_clock: Option<Clock>,
    /// The clock a timer is on now.
    clock: AtomicU8,
    /// A retained queue.
    target: AtomicU64,
    /// The internal reference count: the external references as one, the
    /// registration until it is undone, and each invoke or delivery in
    /// flight. The memory goes when this does.
    internal: AtomicUsize,
    /// `ds_pending_data`.
    pending: AtomicU64,
    /// `ds_data`, as the last event handler latched it.
    data: AtomicU64,
    /// `runnable()`, for the manager, which may not take `state`.
    runnable: AtomicBool,
    /// `dt_pending_config`.
    config: Mutex<Option<Config>>,
    state: Mutex<State>,
}

impl Source {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn has_config(&self) -> bool {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn current_clock(&self) -> Clock {
        clock_from(self.clock.load(Ordering::Acquire))
    }

    fn target(&self) -> u64 {
        self.target.load(Ordering::Acquire)
    }

    /// The flags a kernel registration of this source asks for.
    fn knote_fflags(&self) -> u32 {
        match self.ty {
            // `dst_fflags = NOTE_EXIT`, rdar://16655831.
            Type::Proc => (self.mask | NOTE_EXIT) as u32,
            Type::Vnode => self.mask as u32,
            _ => 0,
        }
    }

    fn publish_runnable(&self, state: &State) {
        self.runnable.store(state.runnable(), Ordering::Release);
    }
}

fn clock_index(clock: Clock) -> u8 {
    match clock {
        Clock::Uptime => 0,
        Clock::Monotonic => 1,
        Clock::Wall => 2,
    }
}

fn clock_from(index: u8) -> Clock {
    match index {
        1 => Clock::Monotonic,
        2 => Clock::Wall,
        _ => Clock::Uptime,
    }
}

/// The source a handle names.
///
/// # Safety
///
/// `handle` is null or a live dispatch object.
unsafe fn source<'a>(handle: u64) -> Option<&'a Source> {
    // SAFETY: the caller's guarantee; the kind check makes the cast sound.
    unsafe { object::typed(handle, Kind::Source) }
        .map(|h| unsafe { &*(h as *const Header as *const Source) })
}

/// # Safety
///
/// `handle` is a source an internal reference keeps alive.
unsafe fn source_unchecked<'a>(handle: u64) -> &'a Source {
    // SAFETY: the caller's guarantee.
    unsafe { &*(handle as *const Source) }
}

/// `DISPATCH_CLIENT_CRASH`.
fn client_crash(message: &str) -> ! {
    eprintln!("BUG IN CLIENT OF LIBDISPATCH: {message}");
    std::process::abort()
}

/// The guest's `errno` across a kqueue call this module makes on its behalf.
struct KeepErrno(i32, #[allow(dead_code)] crate::errno::Held);

impl KeepErrno {
    fn new() -> KeepErrno {
        let guest = crate::errno::guest_errno();
        KeepErrno(guest, crate::errno::Held::now())
    }
}

impl Drop for KeepErrno {
    fn drop(&mut self) {
        crate::errno::set_guest(self.0);
    }
}

/// Registered timers, by source: `dispatch_timer_heap_s` without the heap.
struct Slot {
    clock: Clock,
    target: u64,
    deadline: u64,
    interval: u64,
    armed: bool,
}

fn timers() -> MutexGuard<'static, HashMap<u64, Slot>> {
    static TIMERS: OnceLock<Mutex<HashMap<u64, Slot>>> = OnceLock::new();
    TIMERS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Kernel registrations, by ident and filter, with the sources each feeds.
/// One kqueue registration serves every source on the same pair, as
/// Apple's muxnotes do.
fn knotes() -> MutexGuard<'static, HashMap<(u64, i16), Vec<u64>>> {
    static KNOTES: OnceLock<Mutex<HashMap<(u64, i16), Vec<u64>>>> = OnceLock::new();
    KNOTES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// The manager's kqueue, with its thread started.
fn manager() -> c_int {
    static KQ: OnceLock<c_int> = OnceLock::new();
    *KQ.get_or_init(|| {
        let _keep = KeepErrno::new();
        let kq = kqueue::kqueue();
        let wake = Kevent64 {
            filter: EVFILT_USER,
            flags: EV_ADD | EV_CLEAR,
            ..Kevent64::default()
        };
        // SAFETY: one change, no events.
        unsafe { kqueue::kevent64(kq, &wake, 1, std::ptr::null_mut(), 0, 0, std::ptr::null()) };
        let _ = std::thread::Builder::new()
            .name("dispatch-manager".into())
            .spawn(move || run_manager(kq));
        kq
    })
}

/// Make the manager look again: at a timer armed or moved, or at a kernel
/// registration it is not yet waiting on.
fn poke() {
    let _keep = KeepErrno::new();
    let trigger = Kevent64 {
        filter: EVFILT_USER,
        fflags: NOTE_TRIGGER,
        ..Kevent64::default()
    };
    // SAFETY: one change, no events.
    unsafe {
        kqueue::kevent64(
            manager(),
            &trigger,
            1,
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null(),
        )
    };
}

/// Apply one change to the manager's kqueue: zero, or the errno it failed with.
fn change(ident: u64, filter: i16, flags: u16, fflags: u32) -> i64 {
    let _keep = KeepErrno::new();
    let change = Kevent64 {
        ident,
        filter,
        flags: flags | EV_RECEIPT,
        fflags,
        ..Kevent64::default()
    };
    let mut receipt = Kevent64::default();
    // SAFETY: one change and room for its receipt.
    let n =
        unsafe { kqueue::kevent64(manager(), &change, 1, &mut receipt, 1, 0, std::ptr::null()) };
    match n {
        n if n < 0 => EBADF,
        1 if receipt.flags & EV_ERROR != 0 => receipt.data,
        _ => 0,
    }
}

fn run_manager(kq: c_int) -> ! {
    let mut events = [Kevent64::default(); 32];
    loop {
        let wait = next_wait();
        let timeout = wait.map(|left| libc::timespec {
            tv_sec: left.as_secs() as libc::time_t,
            tv_nsec: left.subsec_nanos() as libc::c_long,
        });
        let timeout = timeout
            .as_ref()
            .map_or(std::ptr::null(), |t| t as *const libc::timespec);
        // SAFETY: no changes, and room for `events.len()`.
        let n = unsafe {
            kqueue::kevent64(
                kq,
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as c_int,
                0,
                timeout,
            )
        };
        if n < 0 {
            // Without a kqueue the timers still run, by sleeping for them.
            std::thread::sleep(wait.unwrap_or(Duration::MAX).min(Duration::from_millis(10)));
        }
        for event in &events[..n.max(0) as usize] {
            if event.filter != EVFILT_USER {
                deliver(event);
            }
        }
        fire_timers();
    }
}

/// How long until the first armed timer is due. A wall-clock wait is cut
/// to a second, since the wall clock can be set while the manager waits on
/// the monotonic one.
fn next_wait() -> Option<Duration> {
    timers()
        .values()
        .filter(|slot| slot.armed)
        .map(|slot| {
            let left = Duration::from_nanos(slot.target.saturating_sub(slot.clock.now()));
            match slot.clock {
                Clock::Wall => left.min(Duration::from_secs(1)),
                _ => left,
            }
        })
        .min()
}

/// `_dispatch_timer_unote_compute_missed`: how many intervals have passed
/// since the target, the target moved past them.
fn compute_missed(slot: &mut Slot, now: u64, prev: u64) -> u64 {
    let mut missed = now.wrapping_sub(slot.target) / slot.interval.max(1) + 1;
    if missed.saturating_add(prev) > INT64_MAX {
        missed = INT64_MAX - prev;
    }
    if slot.interval < INT64_MAX {
        let push = missed.wrapping_mul(slot.interval);
        slot.target = slot.target.wrapping_add(push);
        slot.deadline = slot.deadline.wrapping_add(push);
    } else {
        slot.target = u64::MAX;
        slot.deadline = u64::MAX;
    }
    prev + missed
}

/// `_dispatch_timer_unote_configure`: put a timer on its new configuration,
/// dropping whatever the old one accumulated. Under `TIMERS`.
fn apply_config(source: &Source, slot: &mut Slot, config: Config) {
    source
        .clock
        .store(clock_index(config.clock), Ordering::Release);
    slot.clock = config.clock;
    slot.target = config.target;
    slot.deadline = config.deadline;
    slot.interval = config.interval;
    source.pending.store(0, Ordering::Release);
    if slot.armed {
        // `_dispatch_timer_unote_resume`.
        slot.armed = source.runnable.load(Ordering::Acquire) && slot.target < INT64_MAX;
    }
}

/// Apply the timer's pending configuration, if it is registered and has one.
fn configure(handle: u64, source: &Source) {
    let mut timers = timers();
    let Some(slot) = timers.get_mut(&handle) else {
        return;
    };
    let Some(config) = source
        .config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    else {
        return;
    };
    apply_config(source, slot, config);
    drop(timers);
    poke();
}

/// `_dispatch_timers_run2`: fire every armed timer that is due.
fn fire_timers() {
    let mut fired = Vec::new();
    {
        let mut timers = timers();
        for (&handle, slot) in timers.iter_mut() {
            if !slot.armed {
                continue;
            }
            let now = slot.clock.now();
            if slot.target > now {
                continue;
            }
            // SAFETY: a registered timer's source outlives its slot, which is
            // removed under this lock.
            let source = unsafe { source_unchecked(handle) };
            let config = source
                .config
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(config) = config {
                // Reconfigured since it was armed; the next pass looks again.
                apply_config(source, slot, config);
                continue;
            }
            if source.pending.load(Ordering::Acquire) != 0 {
                // The handler has not kept up: out of the heap until it does,
                // and the invoke counts what was missed meanwhile.
                slot.armed = false;
                source.pending.fetch_or(DISARMED_MARKER, Ordering::AcqRel);
            } else {
                let pending = compute_missed(slot, now, 0) << 1;
                if source.runnable.load(Ordering::Acquire) && slot.target < INT64_MAX {
                    source.pending.store(pending, Ordering::Release);
                } else {
                    slot.armed = false;
                    source
                        .pending
                        .store(pending | DISARMED_MARKER, Ordering::Release);
                }
            }
            source.internal.fetch_add(1, Ordering::AcqRel);
            fired.push(handle);
        }
    }
    for handle in fired {
        // SAFETY: the reference taken above.
        wake(handle, unsafe { source_unchecked(handle) });
        release_internal(handle);
    }
}

/// `_dispatch_kevent_merge`: hand a kernel event to every source it feeds.
fn deliver(event: &Kevent64) {
    let handles: Vec<u64> = {
        let knotes = knotes();
        let Some(handles) = knotes.get(&(event.ident, event.filter)) else {
            return;
        };
        for &handle in handles {
            // SAFETY: a registered source outlives its registration, which is
            // removed under this lock.
            unsafe { source_unchecked(handle) }
                .internal
                .fetch_add(1, Ordering::AcqRel);
        }
        handles.clone()
    };
    for handle in handles {
        // SAFETY: the reference taken above.
        let source = unsafe { source_unchecked(handle) };
        merge_event(source, event);
        {
            let mut state = source.lock();
            if event.flags & EV_ONESHOT != 0 {
                state.knote = Knote::Gone;
            } else if event.flags & EV_DISPATCH != 0 && state.knote == Knote::Armed {
                state.knote = Knote::Disarmed;
            }
        }
        wake(handle, source);
        release_internal(handle);
    }
}

/// The pending data an event adds, by the type's action.
fn merge_event(source: &Source, event: &Kevent64) {
    match source.ty.action() {
        Action::SetData => source
            .pending
            .store(!(event.data.max(0) as u64), Ordering::Release),
        Action::AddData => {
            let data = event.data as u64;
            if data != 0 {
                source.pending.fetch_add(data, Ordering::AcqRel);
            }
        }
        Action::OrFflags => {
            let data = u64::from(event.fflags) & source.mask;
            if source.extended {
                // `DISPATCH_SOURCE_COMBINE_DATA_AND_STATUS`.
                let value = (u64::from(event.data as u32) << 32) | data;
                let mut old = source.pending.load(Ordering::Acquire);
                while let Err(now) = source.pending.compare_exchange_weak(
                    old,
                    (old & 0xffff_ffff) | value,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    old = now;
                }
            } else if event.filter == EVFILT_MACHPORT {
                source
                    .pending
                    .store(DISPATCH_MACH_RECV_MESSAGE, Ordering::Release);
            } else if data != 0 {
                source.pending.fetch_or(data, Ordering::AcqRel);
            }
        }
        Action::PassData | Action::Timer => {}
    }
}

/// Register `source`'s kernel event, joining any registration on the same
/// ident and filter.
fn register_knote(handle: u64, source: &Source, filter: i16, flags: u16) -> Result<(), i64> {
    let key = (source.handle, filter);
    let mut knotes = knotes();
    let others = knotes.get(&key).cloned().unwrap_or_default();
    let fflags = others.iter().fold(source.knote_fflags(), |all, &other| {
        // SAFETY: registered, so alive.
        all | unsafe { source_unchecked(other) }.knote_fflags()
    });
    let error = change(key.0, filter, EV_ADD | flags, fflags);
    if error != 0 {
        return Err(error);
    }
    knotes.entry(key).or_default().push(handle);
    drop(knotes);
    poke();
    Ok(())
}

fn unregister_knote(handle: u64, source: &Source, filter: i16, flags: u16) {
    let key = (source.handle, filter);
    let mut knotes = knotes();
    let Some(handles) = knotes.get_mut(&key) else {
        return;
    };
    handles.retain(|&other| other != handle);
    if handles.is_empty() {
        knotes.remove(&key);
        change(key.0, filter, EV_DELETE, 0);
        return;
    }
    let fflags = handles.iter().fold(0, |all, &other| {
        // SAFETY: registered, so alive.
        all | unsafe { source_unchecked(other) }.knote_fflags()
    });
    change(key.0, filter, EV_ADD | flags, fflags);
}

/// `_dispatch_source_install`: register what feeds the source. False when
/// the registration failed, which leaves the source never firing.
fn install(handle: u64, source: &Source, state: &mut State) -> bool {
    match source.ty {
        Type::DataAdd | Type::DataOr | Type::DataReplace => true,
        Type::Timer => {
            timers().insert(
                handle,
                Slot {
                    clock: source.current_clock(),
                    target: u64::MAX,
                    deadline: u64::MAX,
                    interval: u64::MAX,
                    armed: false,
                },
            );
            configure(handle, source);
            true
        }
        // Nothing here reports memory pressure or a send right's death, so
        // these register and never fire, as on a quiet machine.
        Type::MemoryPressure | Type::MachSend => true,
        ty => {
            let Some((filter, flags)) = ty.knote() else {
                return false;
            };
            match register_knote(handle, source, filter, flags) {
                Ok(()) => {
                    state.knote = Knote::Armed;
                    true
                }
                Err(ESRCH) if filter == EVFILT_PROC => {
                    // `_dispatch_kevent_proc_exit`: a process already gone
                    // has exited, as far as its source is concerned.
                    merge_event(
                        source,
                        &Kevent64 {
                            ident: source.handle,
                            filter,
                            flags: EV_ONESHOT,
                            fflags: (NOTE_EXIT | NOTE_EXITSTATUS) as u32,
                            ..Kevent64::default()
                        },
                    );
                    state.knote = Knote::Gone;
                    true
                }
                Err(_) => {
                    if filter == EVFILT_VNODE {
                        static SAID: std::sync::Once = std::sync::Once::new();
                        SAID.call_once(|| {
                            eprintln!(
                                "rosemary: DISPATCH_SOURCE_TYPE_VNODE is accepted, but no vnode events are delivered"
                            )
                        });
                    }
                    false
                }
            }
        }
    }
}

/// `_dispatch_unote_unregister`.
fn unregister(handle: u64, source: &Source, state: &mut State) {
    if source.ty == Type::Timer {
        timers().remove(&handle);
    } else if state.knote != Knote::None
        && let Some((filter, flags)) = source.ty.knote()
    {
        unregister_knote(handle, source, filter, flags);
    }
    state.knote = Knote::None;
}

/// `_dispatch_source_refs_needs_rearm`.
fn needs_rearm(handle: u64, source: &Source, state: &State) -> bool {
    if !state.installed || state.deleted {
        return false;
    }
    match source.ty {
        Type::Timer => {
            if source.has_config() {
                return true;
            }
            timers()
                .get(&handle)
                .is_some_and(|slot| !slot.armed && slot.target < INT64_MAX)
        }
        _ => state.knote == Knote::Disarmed,
    }
}

/// `_dispatch_unote_resume`.
fn rearm(handle: u64, source: &Source, state: &mut State) {
    match source.ty {
        Type::Timer => {
            let armed = {
                let mut timers = timers();
                match timers.get_mut(&handle) {
                    Some(slot) if !slot.armed && slot.target < INT64_MAX => {
                        slot.armed = source.runnable.load(Ordering::Acquire);
                        slot.armed
                    }
                    _ => false,
                }
            };
            if armed {
                poke();
            }
        }
        _ if state.knote == Knote::Disarmed => {
            if let Some((filter, _)) = source.ty.knote() {
                change(source.handle, filter, EV_ENABLE, 0);
                state.knote = Knote::Armed;
                poke();
            }
        }
        _ => {}
    }
}

/// `_dispatch_source_wakeup`'s question: is there anything for an invoke to do?
fn needs_invoke(handle: u64, source: &Source, state: &State) -> bool {
    let dead = state.dead();
    !state.deferred.is_empty()
        || (!dead
            && source.ty == Type::Timer
            && state.installed
            && !state.deleted
            && source.has_config())
        || state.handlers[REGISTRATION].is_some()
        || (!dead && source.pending.load(Ordering::Acquire) != 0)
        || (dead && !state.deleted)
        || (dead && state.deleted && state.handlers.iter().any(Option::is_some))
        || (!dead && needs_rearm(handle, source, state))
}

/// Queue an invoke on the target, unless one is already queued or there is
/// nothing to do. The caller holds a reference.
fn wake(handle: u64, source: &Source) {
    {
        let mut state = source.lock();
        if state.scheduled || !state.runnable() || !needs_invoke(handle, source, &state) {
            return;
        }
        state.scheduled = true;
    }
    source.internal.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the target is a live queue the source holds, and the invoke
    // takes the reference above.
    unsafe { queue::async_f(source.target(), handle, invoke_entry as *const () as u64) };
}

/// Drop an internal reference, disposing of the source at the last.
fn release_internal(handle: u64) {
    // SAFETY: the caller's reference keeps it alive until this drop.
    let source = unsafe { source_unchecked(handle) };
    if source.internal.fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: that was the last reference.
        unsafe { dispose(handle) };
    }
}

/// `_dispatch_source_dispose`, then the object's: the handlers left, the
/// finalizer on the target queue, and the target.
///
/// # Safety
///
/// No reference to the source is left.
unsafe fn dispose(handle: u64) {
    // SAFETY: the caller's guarantee; boxed by `create`.
    let source = *unsafe { Box::from_raw(handle as *mut Source) };
    let (finalizer, context) = object::finalizer_of(&source.header);
    let target = source.target();
    let state = source.state.into_inner().unwrap_or_else(|e| e.into_inner());
    for handler in state.handlers.into_iter().flatten() {
        handler.dispose();
    }
    for handler in state.deferred.into_iter().filter_map(|(_, h)| h) {
        handler.dispose();
    }
    if finalizer != 0 && context != 0 {
        // SAFETY: the guest's finalizer, called later with its context.
        unsafe { queue::async_f(target, context, finalizer) };
    }
    // SAFETY: the reference `create` took.
    unsafe { object::release(target) };
}

/// Replace the handlers whose replacement waited for a handler to return.
fn apply_deferred(handle: u64, state: &mut State, garbage: &mut Vec<Handler>) {
    for (kind, handler) in std::mem::take(&mut state.deferred) {
        let handler = handler.map(|h| h.fetching(handle));
        garbage.extend(std::mem::replace(&mut state.handlers[kind], handler));
    }
}

/// `_dispatch_source_timer_data`: a disarmed timer's fire count, with what it
/// missed since it left the heap.
fn timer_data(handle: u64, prev: u64) -> u64 {
    let mut data = prev >> 1;
    let mut timers = timers();
    if let Some(slot) = timers.get_mut(&handle)
        && slot.target < INT64_MAX
    {
        let now = slot.clock.now();
        if now >= slot.target {
            data = compute_missed(slot, now, data);
        }
    }
    data
}

/// `_dispatch_source_latch_and_call`.
///
/// # Safety
///
/// On the source's target queue, inside its invoke.
unsafe fn latch_and_call<'a>(
    handle: u64,
    source: &'a Source,
    mut state: MutexGuard<'a, State>,
    garbage: &mut Vec<Handler>,
) -> MutexGuard<'a, State> {
    let prev = source.pending.swap(0, Ordering::AcqRel);
    let data = match source.ty.action() {
        Action::Timer if prev & DISARMED_MARKER != 0 => timer_data(handle, prev),
        Action::Timer => prev >> 1,
        Action::SetData => !prev,
        _ => {
            if prev == 0 && source.ty == Type::DataReplace {
                return state;
            }
            prev
        }
    };
    source.data.store(data, Ordering::Release);
    let Some(handler) = state.handlers[EVENT] else {
        return state;
    };
    if prev == 0 {
        return state;
    }
    state.running = true;
    drop(state);
    // SAFETY: the caller's guarantee.
    unsafe { handler.call() };
    let mut state = source.lock();
    state.running = false;
    apply_deferred(handle, &mut state, garbage);
    if source.ty == Type::Timer && prev & DISARMED_MARKER != 0 && source.has_config() {
        configure(handle, source);
    }
    state
}

/// `_dispatch_source_invoke2`, run on the target queue.
///
/// # Safety
///
/// On the source's target queue, with an internal reference held.
unsafe fn invoke(handle: u64, source: &Source) {
    let mut garbage = Vec::new();
    let mut state = source.lock();
    apply_deferred(handle, &mut state, &mut garbage);

    if state.runnable()
        && !state.dead()
        && source.ty == Type::Timer
        && state.installed
        && !state.deleted
        && source.has_config()
    {
        configure(handle, source);
    }

    if state.runnable()
        && let Some(registration) = state.handlers[REGISTRATION].take()
    {
        if state.dead() {
            // No registration callout for a cancelled source,
            // rdar://problem/8955246.
            garbage.push(registration);
        } else {
            let registration = registration.fetching(handle);
            state.running = true;
            drop(state);
            // SAFETY: the caller's guarantee.
            unsafe { registration.call() };
            registration.dispose();
            state = source.lock();
            state.running = false;
            apply_deferred(handle, &mut state, &mut garbage);
        }
    }

    if state.runnable() && !state.dead() && source.pending.load(Ordering::Acquire) != 0 {
        // SAFETY: the caller's guarantee.
        state = unsafe { latch_and_call(handle, source, state, &mut garbage) };
    }

    if state.runnable() && state.dead() && !state.deleted {
        unregister(handle, source, &mut state);
        // `_dispatch_source_refs_finalize_unregistration`: the registration's
        // reference. Never the last - this invoke holds one.
        state.deleted = true;
        source.internal.fetch_sub(1, Ordering::AcqRel);
    }

    if state.runnable()
        && state.dead()
        && state.deleted
        && state.handlers.iter().any(Option::is_some)
    {
        // `_dispatch_source_cancel_callout`.
        let cancel = state.handlers[CANCEL].take();
        source.pending.store(0, Ordering::Release);
        source.data.store(0, Ordering::Release);
        garbage.extend(state.handlers[EVENT].take());
        garbage.extend(state.handlers[REGISTRATION].take());
        match cancel {
            Some(cancel) if state.cancelled => {
                let cancel = cancel.fetching(handle);
                state.running = true;
                drop(state);
                for handler in garbage.drain(..) {
                    handler.dispose();
                }
                // SAFETY: the caller's guarantee.
                unsafe { cancel.call() };
                cancel.dispose();
                state = source.lock();
                state.running = false;
                apply_deferred(handle, &mut state, &mut garbage);
            }
            // Released without being cancelled: the handler is dropped
            // uncalled.
            Some(cancel) => garbage.push(cancel),
            None => {}
        }
    }

    if state.runnable() && !state.dead() && needs_rearm(handle, source, &state) {
        rearm(handle, source, &mut state);
    }
    drop(state);
    for handler in garbage {
        handler.dispose();
    }
}

/// A source's invoke, as a `dispatch_function_t` on its target queue.
unsafe extern "C" fn invoke_entry(context: *mut c_void) {
    let handle = context as u64;
    // SAFETY: `wake` took a reference for this invoke.
    let source = unsafe { source_unchecked(handle) };
    // Handlers run with the source as the current queue, as Apple's do: a
    // `dispatch_get_specific` from one looks up the source's target chain.
    // SAFETY: on the target queue, with the reference held.
    queue::run_tracked(handle, || unsafe { invoke(handle, source) });
    let again = {
        let mut state = source.lock();
        state.scheduled = false;
        let again = state.runnable() && needs_invoke(handle, source, &state);
        state.scheduled = again;
        again
    };
    if again {
        // A round trip through the target queue, as Apple's starvation
        // avoidance makes, so other work there gets its turn. The reference
        // goes with it.
        // SAFETY: as in `wake`.
        unsafe { queue::async_f(source.target(), handle, invoke_entry as *const () as u64) };
    } else {
        release_internal(handle);
    }
}

/// `_dispatch_source_activate`. The caller wakes the source after.
fn activate_now(handle: u64, source: &Source, state: &mut State) {
    state.inactive = false;
    state.activated = false;
    state.installed = true;
    // The registration's reference, until it is undone.
    source.internal.fetch_add(1, Ordering::AcqRel);
    let registered = !state.cancelled && {
        if let Some(event) = state.handlers[EVENT] {
            state.handlers[EVENT] = Some(event.fetching(handle));
        }
        install(handle, source, state)
    };
    if !registered {
        state.deleted = true;
        source.internal.fetch_sub(1, Ordering::AcqRel);
    }
    source.publish_runnable(state);
}

/// `_dispatch_xref_dispose` for a source: the last external reference is
/// gone, so it unregisters and drops its handlers - running no cancel
/// handler unless it was cancelled.
///
/// # Safety
///
/// `handle` is a source whose external count just reached zero.
pub unsafe fn xref_dispose(handle: u64) {
    // SAFETY: the caller's guarantee.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    {
        let mut state = source.lock();
        if state.inactive {
            client_crash("Release of an inactive object");
        }
        if state.suspend > 0 || state.activated {
            client_crash("Release of a suspended object");
        }
        if state.strict && !state.cancelled && state.handlers[CANCEL].is_some() {
            client_crash(
                "Release of a source that has not been cancelled, but has a mandatory cancel handler",
            );
        }
        state.released = true;
    }
    wake(handle, source);
    release_internal(handle);
}

/// `dispatch_source_t dispatch_source_create(dispatch_source_type_t,
/// uintptr_t handle, uintptr_t mask, dispatch_queue_t)`: an inactive source,
/// or null for a handle or mask its type does not take.
pub unsafe extern "C" fn create(ty: u64, handle: u64, mask: u64, target: u64) -> u64 {
    let Some(ty) = type_at(ty) else {
        return 0;
    };
    let Some(unote) = unote(ty, handle, mask) else {
        return 0;
    };
    let target = match target {
        // SAFETY: no arguments.
        0 => unsafe { queue::get_global_queue(0, 0) },
        queue => queue,
    };
    object::retain(target);
    let source = Box::new(Source {
        header: Header::new(Kind::Source),
        ty,
        handle: unote.handle,
        mask: unote.mask,
        extended: unote.extended,
        fixed_clock: unote.clock,
        clock: AtomicU8::new(clock_index(unote.clock.unwrap_or(Clock::Uptime))),
        target: AtomicU64::new(target),
        internal: AtomicUsize::new(1),
        pending: AtomicU64::new(0),
        data: AtomicU64::new(0),
        runnable: AtomicBool::new(false),
        config: Mutex::new(None),
        state: Mutex::new(State {
            inactive: true,
            activated: false,
            suspend: 0,
            cancelled: false,
            released: false,
            installed: false,
            deleted: false,
            scheduled: false,
            running: false,
            strict: false,
            knote: Knote::None,
            handlers: [None; 3],
            deferred: Vec::new(),
        }),
    });
    Box::into_raw(source) as u64
}

/// The queue a source delivers to, for a target-chain walk.
pub(crate) fn target(handle: u64) -> u64 {
    // SAFETY: a live object, by the walk's caller.
    unsafe { source(handle) }.map_or(0, Source::target)
}

/// `dispatch_set_target_queue` on a source: where its handlers run from now on.
pub(crate) fn set_target(handle: u64, target: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    let target = match target {
        // SAFETY: no arguments.
        0 => unsafe { queue::get_global_queue(0, 0) },
        queue => queue,
    };
    object::retain(target);
    let previous = source.target.swap(target, Ordering::AcqRel);
    // SAFETY: the reference the source held on it.
    unsafe { object::release(previous) };
}

/// The label a source reports: Apple's are all "source".
pub(crate) fn label(handle: u64) -> Option<*const c_char> {
    // SAFETY: a live object.
    unsafe { source(handle) }.map(|_| c"source".as_ptr())
}

/// `dispatch_suspend` on a source.
pub(crate) fn suspend(handle: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    let mut state = source.lock();
    state.suspend += 1;
    source.publish_runnable(&state);
}

/// `dispatch_resume` on a source, which for an inactive one that is not
/// suspended means `dispatch_activate`, for compatibility.
pub(crate) fn resume(handle: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    {
        let mut state = source.lock();
        if state.inactive && state.suspend == 0 {
            activate_now(handle, source, &mut state);
        } else if state.suspend == 0 {
            drop(state);
            client_crash("Over-resume of an object");
        } else {
            state.suspend -= 1;
            if state.suspend == 0 && state.activated {
                activate_now(handle, source, &mut state);
            }
            source.publish_runnable(&state);
        }
    }
    wake(handle, source);
}

/// `dispatch_activate` on a source.
pub(crate) fn activate(handle: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    {
        let mut state = source.lock();
        if !state.inactive {
            return;
        }
        if state.suspend > 0 {
            state.inactive = false;
            state.activated = true;
            return;
        }
        activate_now(handle, source, &mut state);
    }
    wake(handle, source);
}

/// `void dispatch_source_cancel(dispatch_source_t)`.
pub unsafe extern "C" fn cancel(handle: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    {
        let mut state = source.lock();
        if state.cancelled {
            return;
        }
        state.cancelled = true;
    }
    wake(handle, source);
}

/// `intptr_t dispatch_source_testcancel(dispatch_source_t)`.
pub unsafe extern "C" fn testcancel(handle: u64) -> isize {
    // SAFETY: the guest's live source.
    unsafe { source(handle) }.map_or(0, |s| isize::from(s.lock().cancelled))
}

/// `uintptr_t dispatch_source_get_data(dispatch_source_t)`.
pub unsafe extern "C" fn get_data(handle: u64) -> u64 {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return 0;
    };
    let value = source.data.load(Ordering::Acquire);
    match source.extended {
        // `DISPATCH_SOURCE_GET_DATA`.
        true => value & 0xffff_ffff,
        false => value,
    }
}

/// `dispatch_source_extended_data_s`.
#[repr(C)]
struct ExtendedData {
    data: u64,
    status: u64,
}

/// `size_t dispatch_source_get_extended_data(dispatch_source_t,
/// dispatch_source_extended_data_t, size_t)`.
///
/// # Safety
///
/// `edata` has room for `size` bytes.
pub unsafe extern "C" fn get_extended_data(handle: u64, edata: *mut u8, size: usize) -> usize {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return 0;
    };
    let full = size_of::<ExtendedData>();
    if size == 0 || edata.is_null() {
        return size.min(full);
    }
    let combined = source.data.load(Ordering::Acquire);
    let (data, status) = match source.extended {
        true => (combined & 0xffff_ffff, combined >> 32),
        false => (combined, 0),
    };
    let bytes: Vec<u8> = data
        .to_ne_bytes()
        .into_iter()
        .chain(status.to_ne_bytes())
        .collect();
    // Only whole fields are written, then zeroes past the structure.
    let whole = match size {
        n if n >= 16 => 16,
        n if n >= 8 => 8,
        _ => 0,
    };
    // SAFETY: the caller's room for `size` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), edata, whole);
        if size > full {
            std::ptr::write_bytes(edata.add(full), 0, size - full);
        }
    }
    size.min(full)
}

/// `uintptr_t dispatch_source_get_mask(dispatch_source_t)`.
pub unsafe extern "C" fn get_mask(handle: u64) -> u64 {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return 0;
    };
    if source.lock().cancelled {
        return 0;
    }
    match source.ty {
        // `du_timer_flags`: the flags and the clock.
        Type::Timer => {
            source.mask | (u64::from(clock_index(source.current_clock())) << TIMER_CLOCK_SHIFT)
        }
        _ => source.mask,
    }
}

/// `uintptr_t dispatch_source_get_handle(dispatch_source_t)`.
pub unsafe extern "C" fn get_handle(handle: u64) -> u64 {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return 0;
    };
    match (source.ty, source.fixed_clock) {
        (Type::Timer, Some(_)) => source.handle,
        // A timer's `du_ident` is its heap index: clock, then QoS.
        (Type::Timer, None) => {
            u64::from(clock_index(source.current_clock())) * TIMER_QOS_COUNT
                + (source.mask & (TIMER_STRICT | TIMER_BACKGROUND))
        }
        _ => source.handle,
    }
}

/// `void dispatch_source_merge_data(dispatch_source_t, uintptr_t)`.
pub unsafe extern "C" fn merge_data(handle: u64, value: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    if source.lock().dead() {
        return;
    }
    match source.ty {
        Type::DataAdd => {
            source.pending.fetch_add(value, Ordering::AcqRel);
        }
        Type::DataOr => {
            source.pending.fetch_or(value, Ordering::AcqRel);
        }
        Type::DataReplace => source.pending.store(value, Ordering::Release),
        _ => client_crash("Invalid source type"),
    }
    wake(handle, source);
}

/// `_dispatch_timer_config_create`.
fn timer_config(start: u64, interval: u64, leeway: u64, current: Clock) -> Config {
    let interval = match interval {
        0 => 1,
        // 6866347 - make sure nanoseconds won't overflow.
        n if (n as i64) < 0 => INT64_MAX,
        n => n,
    };
    let leeway = match (leeway as i64) < 0 {
        true => INT64_MAX,
        false => leeway,
    };
    let (clock, target) = match start {
        // Postponed forever: the clock stays as it was.
        time::FOREVER => (current, INT64_MAX),
        start => time::to_clock_and_value(start, true),
    };
    // Mach time is nanoseconds here, so no conversion; at least one, so
    // the missed count never divides by zero.
    let interval = interval.max(1);
    let leeway = match interval < INT64_MAX && leeway > interval / 2 {
        true => interval / 2,
        false => leeway,
    };
    // Unsigned, as Apple's: a target out of range wraps here, and is never
    // armed whatever its deadline says.
    let deadline = match target.wrapping_add(leeway) < INT64_MAX {
        true => target.wrapping_add(leeway),
        false => INT64_MAX,
    };
    Config {
        clock,
        target,
        deadline,
        interval,
    }
}

/// `void dispatch_source_set_timer(dispatch_source_t, dispatch_time_t start,
/// uint64_t interval, uint64_t leeway)`: the configuration the source applies
/// at its next invoke, which also drops what the old one accumulated.
pub unsafe extern "C" fn set_timer(handle: u64, start: u64, interval: u64, leeway: u64) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        return;
    };
    if source.ty != Type::Timer {
        client_crash("Attempt to set timer on a non-timer source");
    }
    let config = timer_config(start, interval, leeway, source.current_clock());
    if source
        .fixed_clock
        .is_some_and(|clock| clock != config.clock)
    {
        client_crash("Attempting to modify timer clock");
    }
    *source.config.lock().unwrap_or_else(|e| e.into_inner()) = Some(config);
    wake(handle, source);
}

/// `_dispatch_source_set_handler`: replaced at once on an inactive source;
/// on an active one, once no handler is running, since Apple's replacement
/// is an item on the source's own queue.
fn set_handler(handle: u64, kind: usize, handler: Option<Handler>) {
    // SAFETY: the guest's live source.
    let Some(source) = (unsafe { source(handle) }) else {
        handler.inspect(|h| h.dispose());
        return;
    };
    let mut garbage = Vec::new();
    {
        let mut state = source.lock();
        if !state.inactive && state.strict {
            drop(state);
            client_crash("Cannot change a handler of this source after it has been activated");
        }
        if state.running {
            state.deferred.push((kind, handler));
        } else {
            let handler = handler.map(|h| h.fetching(handle));
            garbage.extend(std::mem::replace(&mut state.handlers[kind], handler));
        }
    }
    for handler in garbage {
        handler.dispose();
    }
    wake(handle, source);
}

/// A block handler, copied since it outlives the call; null clears.
fn block_handler(block: u64) -> Option<Handler> {
    block::copy(block).map(Handler::Block)
}

fn function_handler(function: u64) -> Option<Handler> {
    (function != 0).then_some(Handler::Function {
        function,
        context: 0,
    })
}

/// `void dispatch_source_set_event_handler(dispatch_source_t, dispatch_block_t)`.
pub unsafe extern "C" fn set_event_handler(handle: u64, block: u64) {
    set_handler(handle, EVENT, block_handler(block));
}

/// `void dispatch_source_set_event_handler_f(dispatch_source_t, dispatch_function_t)`.
pub unsafe extern "C" fn set_event_handler_f(handle: u64, function: u64) {
    set_handler(handle, EVENT, function_handler(function));
}

/// `void dispatch_source_set_cancel_handler(dispatch_source_t, dispatch_block_t)`.
pub unsafe extern "C" fn set_cancel_handler(handle: u64, block: u64) {
    set_handler(handle, CANCEL, block_handler(block));
}

/// `void dispatch_source_set_cancel_handler_f(dispatch_source_t, dispatch_function_t)`.
pub unsafe extern "C" fn set_cancel_handler_f(handle: u64, function: u64) {
    set_handler(handle, CANCEL, function_handler(function));
}

fn make_strict(handle: u64) {
    // SAFETY: the guest's live source.
    if let Some(source) = unsafe { source(handle) } {
        source.lock().strict = true;
    }
}

/// `void dispatch_source_set_mandatory_cancel_handler(dispatch_source_t,
/// dispatch_block_t)`: a cancel handler the source may not be released without
/// running, after which no handler may change.
pub unsafe extern "C" fn set_mandatory_cancel_handler(handle: u64, block: u64) {
    let handler = block_handler(block);
    make_strict(handle);
    set_handler(handle, CANCEL, handler);
}

/// `void dispatch_source_set_mandatory_cancel_handler_f(dispatch_source_t,
/// dispatch_function_t)`.
pub unsafe extern "C" fn set_mandatory_cancel_handler_f(handle: u64, function: u64) {
    make_strict(handle);
    set_handler(handle, CANCEL, function_handler(function));
}

/// `void dispatch_source_set_registration_handler(dispatch_source_t,
/// dispatch_block_t)`.
pub unsafe extern "C" fn set_registration_handler(handle: u64, block: u64) {
    set_handler(handle, REGISTRATION, block_handler(block));
}

/// `void dispatch_source_set_registration_handler_f(dispatch_source_t,
/// dispatch_function_t)`.
pub unsafe extern "C" fn set_registration_handler_f(handle: u64, function: u64) {
    set_handler(handle, REGISTRATION, function_handler(function));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "{what} never happened");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// What the handlers saw, through the source's context.
    #[derive(Default)]
    struct Seen {
        source: AtomicU64,
        events: AtomicU64,
        data: AtomicU64,
        last: AtomicU64,
        cancelled: AtomicU64,
        registered: AtomicU64,
        finalized: AtomicU64,
    }

    unsafe extern "C" fn on_event(context: *mut c_void) {
        // SAFETY: a `Seen` that outlives the source.
        let seen = unsafe { &*(context as *const Seen) };
        let data = unsafe { get_data(seen.source.load(Ordering::Acquire)) };
        seen.data.fetch_add(data, Ordering::AcqRel);
        seen.last.store(data, Ordering::Release);
        seen.events.fetch_add(1, Ordering::AcqRel);
    }

    unsafe extern "C" fn on_cancel(context: *mut c_void) {
        // SAFETY: as above.
        unsafe { &*(context as *const Seen) }
            .cancelled
            .fetch_add(1, Ordering::AcqRel);
    }

    unsafe extern "C" fn on_registration(context: *mut c_void) {
        // SAFETY: as above.
        unsafe { &*(context as *const Seen) }
            .registered
            .fetch_add(1, Ordering::AcqRel);
    }

    unsafe extern "C" fn on_finalize(context: *mut c_void) {
        // SAFETY: as above.
        unsafe { &*(context as *const Seen) }
            .finalized
            .fetch_add(1, Ordering::AcqRel);
    }

    fn function(f: unsafe extern "C" fn(*mut c_void)) -> u64 {
        f as *const () as u64
    }

    /// A source with every handler reporting into a leaked `Seen`.
    fn watched(ty: Type, handle: u64, mask: u64) -> (u64, &'static Seen) {
        let seen: &'static Seen = Box::leak(Box::default());
        // SAFETY: a type this module publishes and handlers that take the context.
        unsafe {
            let source = create(type_address(ty), handle, mask, 0);
            assert_ne!(source, 0, "{ty:?} refused");
            seen.source.store(source, Ordering::Release);
            object::set_context(source, seen as *const Seen as *mut c_void);
            object::set_finalizer_f(source, function(on_finalize));
            set_event_handler_f(source, function(on_event));
            set_cancel_handler_f(source, function(on_cancel));
            set_registration_handler_f(source, function(on_registration));
            (source, seen)
        }
    }

    /// Data merged into an add source coalesces into one sum per run, the
    /// registration handler runs once first, and cancelling then releasing
    /// runs the cancel handler and then the finalizer.
    #[test]
    fn a_data_add_source_coalesces_and_cancels() {
        let (source, seen) = watched(Type::DataAdd, 0, 0);
        // SAFETY: a live source of this module's.
        unsafe {
            resume(source);
            wait_until("registration", || {
                seen.registered.load(Ordering::Acquire) == 1
            });
            suspend(source);
            for n in 1..=4 {
                merge_data(source, n);
            }
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(seen.events.load(Ordering::Acquire), 0, "suspended");
            resume(source);
            wait_until("the event", || seen.events.load(Ordering::Acquire) == 1);
            assert_eq!(seen.data.load(Ordering::Acquire), 10);
            cancel(source);
            assert_eq!(testcancel(source), 1);
            wait_until("the cancel handler", || {
                seen.cancelled.load(Ordering::Acquire) == 1
            });
            merge_data(source, 5);
            object::release(source);
        }
        wait_until("the finalizer", || {
            seen.finalized.load(Ordering::Acquire) == 1
        });
        assert_eq!(
            seen.events.load(Ordering::Acquire),
            1,
            "nothing after cancel"
        );
        assert_eq!(seen.registered.load(Ordering::Acquire), 1);
    }

    /// Releasing without cancelling unregisters the source and drops the
    /// cancel handler uncalled.
    #[test]
    fn a_released_source_drops_its_cancel_handler() {
        let (source, seen) = watched(Type::DataOr, 0, 0);
        // SAFETY: a live source of this module's.
        unsafe {
            activate(source);
            merge_data(source, 0b01);
            wait_until("the event", || seen.events.load(Ordering::Acquire) == 1);
            object::release(source);
        }
        wait_until("the finalizer", || {
            seen.finalized.load(Ordering::Acquire) == 1
        });
        assert_eq!(seen.cancelled.load(Ordering::Acquire), 0);
    }

    /// `dux_create`'s checks: a handle or mask the type does not take is
    /// `DISPATCH_BAD_INPUT`.
    #[test]
    fn bad_input_makes_no_source() {
        // SAFETY: published types, or a pointer that is none.
        unsafe {
            assert_eq!(create(type_address(Type::DataAdd), 1, 0, 0), 0);
            assert_eq!(create(type_address(Type::Timer), 0, 0x4, 0), 0);
            assert_eq!(create(type_address(Type::Timer), 4, 0, 0), 0);
            assert_eq!(create(type_address(Type::Signal), 0, 0, 0), 0);
            assert_eq!(create(type_address(Type::Signal), 32, 0, 0), 0);
            assert_eq!(create(type_address(Type::Proc), 1, 0, 0), 0);
            assert_eq!(create(type_address(Type::Read), 0, 1, 0), 0);
            assert_eq!(create(0x10, 0, 0, 0), 0);
            let strict = create(type_address(Type::Timer), 0, 0x3, 0);
            assert_eq!(get_mask(strict), 0x1, "STRICT clears BACKGROUND");
            assert_eq!(get_handle(strict), 1, "heap index: uptime, critical");
            let clock = create(type_address(Type::Timer), 3, 0, 0);
            assert_eq!(get_handle(clock), 3);
            assert_eq!(get_mask(clock), 2 << TIMER_CLOCK_SHIFT, "the wall clock");
        }
    }

    /// A repeating timer fires on its interval, and a handler that falls
    /// behind sees one event counting every interval it missed.
    #[test]
    fn a_repeating_timer_counts_what_it_missed() {
        let (source, seen) = watched(Type::Timer, 0, 0);
        // SAFETY: a live source of this module's.
        unsafe {
            set_timer(source, time::time(time::NOW, 10_000_000), 10_000_000, 0);
            resume(source);
            wait_until("three events", || seen.events.load(Ordering::Acquire) >= 3);
            suspend(source);
            let (events, data) = (
                seen.events.load(Ordering::Acquire),
                seen.data.load(Ordering::Acquire),
            );
            std::thread::sleep(Duration::from_millis(100));
            resume(source);
            wait_until("the catch-up event", || {
                seen.events.load(Ordering::Acquire) > events
            });
            let missed = seen.data.load(Ordering::Acquire) - data;
            assert!(
                missed >= 8,
                "a single event for ~10 intervals, got {missed}"
            );
            cancel(source);
            wait_until("the cancel handler", || {
                seen.cancelled.load(Ordering::Acquire) == 1
            });
            object::release(source);
        }
    }

    /// A one-shot timer fires once, with a count of one.
    #[test]
    fn a_one_shot_timer_fires_once() {
        let (source, seen) = watched(Type::Timer, 0, 0);
        // SAFETY: a live source of this module's.
        unsafe {
            set_timer(source, time::time(time::NOW, 5_000_000), time::FOREVER, 0);
            resume(source);
            wait_until("the event", || seen.events.load(Ordering::Acquire) == 1);
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(seen.events.load(Ordering::Acquire), 1);
            assert_eq!(seen.data.load(Ordering::Acquire), 1);
            cancel(source);
            object::release(source);
        }
    }

    /// A read source reports how many bytes are waiting.
    #[test]
    fn a_read_source_reports_the_bytes_available() {
        let mut fds = [0; 2];
        // SAFETY: a two-int array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (source, seen) = watched(Type::Read, fds[0] as u64, 0);
        // SAFETY: a live source and a pipe this test owns.
        unsafe {
            resume(source);
            libc::write(fds[1], b"hello".as_ptr().cast(), 5);
            wait_until("the event", || seen.events.load(Ordering::Acquire) >= 1);
            // Unread, so it fires again once re-armed - with the same count.
            assert_eq!(seen.last.load(Ordering::Acquire), 5);
            cancel(source);
            wait_until("the cancel handler", || {
                seen.cancelled.load(Ordering::Acquire) == 1
            });
            object::release(source);
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
