use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::{Arc, RwLock};

use super::kern::*;
use super::wire::{Address, Receiver};

/// `mach_port_name_t`, and the two values that are not names.
pub type Name = u32;
pub const MACH_PORT_NULL: Name = 0;
pub const MACH_PORT_DEAD: Name = !0;

/// `MACH_PORT_RIGHT_*`, in the order `<mach/port.h>` declares them. Send is
/// zero, which is the one worth reading twice - `mach_port_allocate` is nearly
/// always called with `1`.
pub const RIGHT_SEND: u32 = 0;
pub const RIGHT_RECEIVE: u32 = 1;
pub const RIGHT_SEND_ONCE: u32 = 2;
pub const RIGHT_PORT_SET: u32 = 3;
pub const RIGHT_DEAD_NAME: u32 = 4;

/// `MACH_PORT_TYPE(right)`, which is `1 << (right + 16)`.
pub const fn type_of(right: u32) -> u32 {
    1 << (right + 16)
}

/// The names that exist before anything is allocated.
///
/// Fixed rather than drawn from the counter so that `mach_task_self_` can be a
/// constant: it is a *data* import, bound before a line of guest code runs, and
/// a data import that read zero is the segfault this whole directory exists to
/// stop.
pub const TASK_SELF: Name = 0x103;
pub const HOST_SELF: Name = 0x203;
pub const BOOTSTRAP: Name = 0x303;
/// The two clock services `host_get_clock_service` hands out. Fixed because
/// every caller asking for the same clock gets the same port on a real system.
pub const SYSTEM_CLOCK: Name = 0x403;
pub const CALENDAR_CLOCK: Name = 0x503;
/// The one processor set there is, by its name port and its control port.
/// `host_processor_sets` hands out the first and `host_processor_set_priv`
/// turns it into the second, which is what enumerates tasks.
pub const PSET_NAME: Name = 0x603;
pub const PSET_CONTROL: Name = 0x703;
/// The first name [`allocate`] hands out. Above the fixed ones, and stepped by
/// four the way a real space's names are, so a caller that assumes a name is
/// not a small integer is not surprised.
const FIRST_DYNAMIC: Name = 0x1003;

/// A receive right, and what Mach keeps beside it under the same name.
///
/// A space has one name per port: a send right to a port whose receive right
/// is here is the receive right's own name, which is `MACH_PORT_TYPE_SEND_RECEIVE`
/// in `mach_port_type`. That is what `mach_port_insert_right(task, port, port,
/// MACH_MSG_TYPE_MAKE_SEND)` - the commonest line in any Mach program - makes,
/// and what a caller then sends to and deallocates.
pub struct Owned {
    /// Held by `Arc` because a port set names its members and a receive in
    /// progress must keep the socket alive.
    port: Arc<Receiver>,
    /// The user references of the send right under this name; zero for none.
    sends: u32,
    /// What makes that send right count as a sender, as [`Right::Send`]'s does.
    claim: Option<OwnedFd>,
    /// `ip_context`: the caller's word, or the guard when `guarded`.
    context: u64,
    guarded: bool,
    /// `MPG_STRICT`: the context is the guard and cannot be read or replaced.
    strict: bool,
    /// `MPO_IMMOVABLE_RECEIVE`: the right cannot be sent anywhere.
    immovable: bool,
}

impl Owned {
    fn new(port: Arc<Receiver>) -> Owned {
        Owned {
            port,
            sends: 0,
            claim: None,
            context: 0,
            guarded: false,
            strict: false,
            immovable: false,
        }
    }

    /// One more user reference on the send right under this name.
    fn add_send(&mut self, carried: Option<OwnedFd>) {
        if self.sends == 0 {
            self.claim = carried.or_else(|| super::wire::claim(self.port.address()));
        }
        self.sends = self.sends.saturating_add(1);
    }

    /// What is left under the name once the receive right is gone: the send
    /// rights, if there were any, as dead names - the port went with the
    /// receive right, as `ipc_right_destruct` leaves it.
    fn remainder(&self) -> Option<Right> {
        (self.sends > 0).then_some(Right::Dead { refs: self.sends })
    }
}

/// What a name refers to.
pub enum Right {
    /// The receiving end, and any send right held under the same name.
    Receive(Owned),
    /// A send right: the address of somebody else's receive right, and the user
    /// reference count Mach makes the caller balance.
    ///
    /// `claim` is what makes this right count as a sender: an open connection to
    /// the port's listener, closed when the name is, or when this process exits.
    /// `None` when the port could not be reached, which reports no senders
    /// changes for it.
    Send {
        address: Address,
        refs: u32,
        claim: Option<OwnedFd>,
    },
    /// A send-once right, which is destroyed by the message that uses it.
    SendOnce { address: Address },
    /// A port set, which has no queue of its own - only members.
    Set(Vec<Name>),
    /// A right whose port has been destroyed.
    Dead { refs: u32 },
    /// A Mach semaphore, which is named out of the same space and is not a port.
    Semaphore(Arc<super::sync::Semaphore>),
    /// A send right to a task: this one under a name other than
    /// [`TASK_SELF`], or another guest's, from `task_for_pid`. The pid is the
    /// whole of it - every question about the task goes to the process server
    /// - but for the flavor of port it is, which is what the calls taking it
    /// accept or refuse.
    Task {
        pid: i32,
        flavor: TaskFlavor,
        refs: u32,
    },
    /// A send right to a thread of some task, by its host thread id.
    Thread { pid: i32, tid: i32, refs: u32 },
    /// A name this runtime answers for without a port behind it: the task, the
    /// host, the bootstrap server, a clock, the processor set.
    Special,
}

impl Right {
    fn type_bits(&self) -> u32 {
        match self {
            Right::Receive(owned) => match owned.sends {
                0 => type_of(RIGHT_RECEIVE),
                _ => type_of(RIGHT_RECEIVE) | type_of(RIGHT_SEND),
            },
            Right::Send { .. } => type_of(RIGHT_SEND),
            Right::SendOnce { .. } => type_of(RIGHT_SEND_ONCE),
            Right::Set(_) => type_of(RIGHT_PORT_SET),
            Right::Dead { .. } => type_of(RIGHT_DEAD_NAME),
            // Neither is a port right. A caller asking after one is asking about
            // something this host does not model, and `mach_port_type` reports
            // it as a send right because that is what the task and host ports
            // are on a real system.
            Right::Semaphore(_) | Right::Special => type_of(RIGHT_SEND),
            Right::Task { .. } | Right::Thread { .. } => type_of(RIGHT_SEND),
        }
    }
}

struct Space {
    names: HashMap<Name, Right>,
    next: Name,
}

fn space() -> &'static RwLock<Space> {
    static SPACE: std::sync::OnceLock<RwLock<Space>> = std::sync::OnceLock::new();
    SPACE.get_or_init(|| {
        let mut names = HashMap::new();
        names.insert(TASK_SELF, Right::Special);
        names.insert(HOST_SELF, Right::Special);
        names.insert(BOOTSTRAP, Right::Special);
        names.insert(SYSTEM_CLOCK, Right::Special);
        names.insert(CALENDAR_CLOCK, Right::Special);
        names.insert(PSET_NAME, Right::Special);
        names.insert(PSET_CONTROL, Right::Special);
        RwLock::new(Space {
            names,
            next: FIRST_DYNAMIC,
        })
    })
}

fn with<R>(f: impl FnOnce(&mut Space) -> R) -> R {
    let mut guard = space().write().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Put `right` in the table under a fresh name.
pub fn insert(right: Right) -> Name {
    with(|space| {
        let name = space.next;
        space.next = space.next.wrapping_add(4);
        space.names.insert(name, right);
        name
    })
}

/// The address a send or send-once right names, and whether it was send-once.
///
/// A send-once right is *not* consumed here: a message that fails to send has
/// not used it, so [`super::msg`] consumes it only once the datagram is away.
pub fn destination(name: Name) -> Result<(Address, bool), i32> {
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.get(&name) {
        Some(Right::Send { address, .. }) => Ok((*address, false)),
        Some(Right::SendOnce { address }) => Ok((*address, true)),
        // A receive right is a legal destination: a task can send to itself.
        Some(Right::Receive(owned)) => Ok((owned.port.address(), false)),
        Some(Right::Dead { .. }) => Err(MACH_SEND_INVALID_DEST),
        Some(_) => Err(MACH_SEND_INVALID_RIGHT),
        None => Err(MACH_SEND_INVALID_DEST),
    }
}

/// The receive right `name` refers to.
pub fn receiver(name: Name) -> Option<Arc<Receiver>> {
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.get(&name) {
        Some(Right::Receive(owned)) => Some(owned.port.clone()),
        _ => None,
    }
}

/// Look at whatever `name` refers to, without copying it out.
pub fn with_right<R>(name: Name, f: impl FnOnce(&Right) -> R) -> Option<R> {
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    guard.names.get(&name).map(f)
}

/// The members of a port set, or `None` if `name` is not one.
pub fn members(name: Name) -> Option<Vec<Name>> {
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.get(&name) {
        Some(Right::Set(members)) => Some(members.clone()),
        _ => None,
    }
}

/// The address a right names, whatever kind it is - for a descriptor that has
/// to be encoded without regard to what the caller is doing with it.
pub fn address_of(name: Name) -> Option<Address> {
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.get(&name) {
        Some(Right::Receive(owned)) => Some(owned.port.address()),
        Some(Right::Send { address, .. }) | Some(Right::SendOnce { address }) => Some(*address),
        _ => None,
    }
}

/// Take a receive right out of the space so its descriptor can be sent
/// elsewhere - `MACH_MSG_TYPE_MOVE_RECEIVE`.
///
/// Fails when something else still holds the port: a member of a port set, or a
/// receive in progress on another thread. Mach would refuse the same move for
/// the same reason, and moving it anyway would leave this process reading a
/// socket another process now owns. An immovable right is refused as
/// `ipc_move_receive_allowed` refuses it; a guarded one moves, and its guard
/// stays behind, as `ipc_port_mark_in_limbo` drops it.
///
/// A send right under the same name stays, as Mach's entry keeps
/// `MACH_PORT_TYPE_SEND` when the receive bit is cleared from it.
pub fn move_receive(name: Name) -> Result<Receiver, i32> {
    let taken = with(|space| match space.names.get(&name) {
        Some(Right::Receive(owned)) if !owned.immovable => space.names.remove(&name),
        Some(_) => None,
        None => None,
    });
    let Some(Right::Receive(owned)) = taken else {
        return Err(MACH_SEND_INVALID_RIGHT);
    };
    let Owned {
        port,
        sends,
        claim,
        context,
        guarded,
        strict,
        immovable,
    } = owned;
    let address = port.address();
    match Arc::try_unwrap(port) {
        Ok(port) => {
            if sends > 0 {
                with(|space| {
                    space.names.insert(
                        name,
                        Right::Send {
                            address,
                            refs: sends,
                            claim,
                        },
                    )
                });
            }
            Ok(port)
        }
        Err(port) => {
            // Put it back: the caller still holds the right it asked to move.
            let owned = Owned {
                port,
                sends,
                claim,
                context,
                guarded,
                strict,
                immovable,
            };
            with(|space| space.names.insert(name, Right::Receive(owned)));
            Err(MACH_SEND_INVALID_RIGHT)
        }
    }
}

/// Add a send right for `address`, reusing an existing name for the same port.
///
/// Reuse is what Mach does and what callers depend on: two messages carrying a
/// send right to the same port arrive naming the same integer, and a client that
/// compares them - a crash reporter deciding whether it already knows this
/// sender - would otherwise see two ports where there is one.
pub fn insert_send(address: Address) -> Name {
    insert_send_with(address, None)
}

/// [`insert_send`] for a right that arrived with its claim, which is the one
/// that was made when it was sent and so kept the port's count up while the
/// message was in flight.
pub fn insert_send_with(address: Address, carried: Option<OwnedFd>) -> Name {
    with(|space| {
        for (name, right) in space.names.iter_mut() {
            if let Right::Receive(owned) = right
                && owned.port.address() == address
            {
                owned.add_send(carried);
                return *name;
            }
            if let Right::Send {
                address: existing,
                refs,
                claim,
            } = right
                && *existing == address
            {
                *refs = refs.saturating_add(1);
                if claim.is_none() {
                    *claim = carried;
                }
                return *name;
            }
        }
        let claim = carried.or_else(|| super::wire::claim(address));
        let name = space.next;
        space.next = space.next.wrapping_add(4);
        space.names.insert(
            name,
            Right::Send {
                address,
                refs: 1,
                claim,
            },
        );
        name
    })
}

/// `mach_task_flavor_t`: which of a task's four ports a right is to, in
/// descending capability. XNU makes each a port of its own (`IKOT_TASK_CONTROL`,
/// `_READ`, `_INSPECT`, `_NAME`), so they answer to different names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskFlavor {
    Control = 0,
    Read = 1,
    Inspect = 2,
    Name = 3,
}

impl TaskFlavor {
    pub fn from_raw(flavor: u32) -> Option<TaskFlavor> {
        Some(match flavor {
            0 => TaskFlavor::Control,
            1 => TaskFlavor::Read,
            2 => TaskFlavor::Inspect,
            3 => TaskFlavor::Name,
            _ => return None,
        })
    }

    /// XNU's `task_port_kotype_valid_for_flavor`: a port serves any call that
    /// asks for its own flavor or a weaker one.
    pub fn serves(self, wanted: TaskFlavor) -> bool {
        self <= wanted
    }
}

/// A send right to the task `pid`'s port of `flavor`, reusing the name
/// already held for it.
///
/// One name per port for the same reason as [`insert_send`]: `top` compares
/// what two calls handed back, and a task that answered to two names would be
/// two tasks. This task's control port is always [`TASK_SELF`].
pub fn insert_task(pid: i32, flavor: TaskFlavor) -> Name {
    if pid == own_pid() && flavor == TaskFlavor::Control {
        return TASK_SELF;
    }
    with(|space| {
        for (name, right) in space.names.iter_mut() {
            if let Right::Task {
                pid: held,
                flavor: held_flavor,
                refs,
            } = right
                && (*held, *held_flavor) == (pid, flavor)
            {
                *refs = refs.saturating_add(1);
                return *name;
            }
        }
        let name = space.next;
        space.next = space.next.wrapping_add(4);
        space.names.insert(
            name,
            Right::Task {
                pid,
                flavor,
                refs: 1,
            },
        );
        name
    })
}

/// A send right to thread `tid` of task `pid`, reusing a name already held.
pub fn insert_thread(pid: i32, tid: i32) -> Name {
    thread_name(pid, tid, true)
}

/// A borrowed thread name, as `pthread_mach_thread_np` returns.
pub fn borrow_thread(pid: i32, tid: i32) -> Name {
    thread_name(pid, tid, false)
}

fn thread_name(pid: i32, tid: i32, add_reference: bool) -> Name {
    with(|space| {
        for (name, right) in space.names.iter_mut() {
            if let Right::Thread {
                pid: held_pid,
                tid: held_tid,
                refs,
            } = right
                && (*held_pid, *held_tid) == (pid, tid)
            {
                if add_reference {
                    *refs = refs.saturating_add(1);
                }
                return *name;
            }
        }
        let name = space.next;
        space.next = space.next.wrapping_add(4);
        space
            .names
            .insert(name, Right::Thread { pid, tid, refs: 1 });
        name
    })
}

fn own_pid() -> i32 {
    starnix::process::me()
}

/// The pid of the task `name` is a right to, whichever of its ports.
pub fn task_pid(name: Name) -> Option<i32> {
    task_of(name).map(|(pid, _)| pid)
}

/// The pid of the task `name` is a right to, if it is a port that serves a
/// call wanting `wanted` - as XNU's `convert_port_to_task_with_flavor`.
pub fn task_pid_as(name: Name, wanted: TaskFlavor) -> Option<i32> {
    task_of(name)
        .filter(|(_, flavor)| flavor.serves(wanted))
        .map(|(pid, _)| pid)
}

/// The task `name` is a right to, and which of its ports.
pub fn task_of(name: Name) -> Option<(i32, TaskFlavor)> {
    if name == TASK_SELF {
        return Some((own_pid(), TaskFlavor::Control));
    }
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.get(&name) {
        Some(Right::Task { pid, flavor, .. }) => Some((*pid, *flavor)),
        _ => None,
    }
}

/// The task and thread `name` is a right to.
///
/// Other hosts use a kernel thread id as the borrowed pthread port name.
pub fn thread_of(name: Name) -> Option<(i32, i32)> {
    {
        let guard = space().read().unwrap_or_else(|e| e.into_inner());
        match guard.names.get(&name) {
            Some(Right::Thread { pid, tid, .. }) => return Some((*pid, *tid)),
            Some(_) => return None,
            None => {}
        }
    }
    let pid = own_pid();
    let tid = name as i32;
    starnix::process::has_thread(tid).then_some((pid, tid))
}

/// How many names the space holds, for `mach_port_space_basic_info`.
pub fn count() -> usize {
    space()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .names
        .len()
}

/// Add a send-once right, which is never shared with an existing name.
pub fn insert_send_once(address: Address) -> Name {
    insert(Right::SendOnce { address })
}

/// Add a receive right this process has just acquired.
pub fn insert_receive(port: Receiver) -> Name {
    insert(Right::Receive(Owned::new(Arc::new(port))))
}

/// Drop one user reference to `name`, removing it when the last one goes.
///
/// This is `mach_port_deallocate`'s whole behaviour and the tail of several
/// others, so it is spelled once.
fn release(space: &mut Space, name: Name) -> i32 {
    let Some(right) = space.names.get_mut(&name) else {
        return KERN_INVALID_NAME;
    };
    match right {
        Right::Send { refs, .. }
        | Right::Dead { refs }
        | Right::Task { refs, .. }
        | Right::Thread { refs, .. } => {
            *refs -= 1;
            if *refs == 0 {
                space.names.remove(&name);
            }
            KERN_SUCCESS
        }
        Right::SendOnce { .. } => {
            space.names.remove(&name);
            KERN_SUCCESS
        }
        // The send right under a receive right's name is the one released.
        Right::Receive(owned) if owned.sends > 0 => {
            owned.sends -= 1;
            if owned.sends == 0 {
                owned.claim = None;
            }
            KERN_SUCCESS
        }
        // `mach_port_deallocate` on a receive right is an error on a real
        // system, and the mistake it catches - deallocating the port you are
        // about to listen on - is one worth still catching here.
        Right::Receive(_) | Right::Set(_) => KERN_INVALID_RIGHT,
        Right::Semaphore(_) | Right::Special => KERN_SUCCESS,
    }
}

/// Remove `name` and everything behind it, whatever kind of right it is.
///
/// Except a guarded receive right, which `ipc_right_destroy` refuses to destroy
/// by any route but `mach_port_destruct` with its guard.
pub fn destroy(name: Name) -> i32 {
    with(|space| {
        if let Some(Right::Receive(owned)) = space.names.get(&name)
            && owned.guarded
            && owned.context != 0
        {
            return KERN_INVALID_RIGHT;
        }
        match space.names.remove(&name) {
            Some(_) => KERN_SUCCESS,
            None => KERN_INVALID_NAME,
        }
    })
}

/// `kern_return_t mach_port_allocate(ipc_space_t, mach_port_right_t, mach_port_name_t *)`
///
/// # Safety
///
/// `out` is a writable `mach_port_name_t`.
pub unsafe extern "C" fn mach_port_allocate(task: Name, right: u32, out: *mut Name) -> i32 {
    if out.is_null() {
        return KERN_INVALID_ADDRESS;
    }
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let name = match right {
        RIGHT_RECEIVE => match Receiver::bind() {
            Ok(port) => insert_receive(port),
            Err(_) => return KERN_RESOURCE_SHORTAGE,
        },
        RIGHT_PORT_SET => insert(Right::Set(Vec::new())),
        // A dead name with no port behind it; Mach allows this and nothing this
        // runtime has met asks for it, but the alternative is answering an
        // unknown right with a receive right, which is a live port a caller
        // would then listen on.
        RIGHT_DEAD_NAME => insert(Right::Dead { refs: 1 }),
        _ => return KERN_INVALID_VALUE,
    };
    // SAFETY: the caller's `mach_port_name_t`.
    unsafe { out.write(name) };
    KERN_SUCCESS
}

/// `kern_return_t mach_port_deallocate(ipc_space_t, mach_port_name_t)`
pub extern "C" fn mach_port_deallocate(task: Name, name: Name) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
        return KERN_SUCCESS;
    }
    with(|space| release(space, name))
}

/// `kern_return_t mach_port_destroy(ipc_space_t, mach_port_name_t)`
pub extern "C" fn mach_port_destroy(task: Name, name: Name) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    destroy(name)
}

/// `kern_return_t mach_port_mod_refs(ipc_space_t, mach_port_name_t,
/// mach_port_right_t, mach_port_delta_t)`
pub extern "C" fn mach_port_mod_refs(task: Name, name: Name, right: u32, delta: i32) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    with(|space| {
        let Some(held) = space.names.get_mut(&name) else {
            return KERN_INVALID_NAME;
        };
        if held.type_bits() & type_of(right) == 0 {
            return KERN_INVALID_RIGHT;
        }
        if let Right::Receive(owned) = held {
            return match right {
                RIGHT_SEND => {
                    let updated = owned.sends as i64 + delta as i64;
                    if updated < 0 {
                        return KERN_INVALID_VALUE;
                    }
                    if updated > u32::MAX as i64 {
                        return KERN_UREFS_OVERFLOW;
                    }
                    owned.sends = updated as u32;
                    if updated == 0 {
                        owned.claim = None;
                    }
                    KERN_SUCCESS
                }
                // A receive right has one reference, and dropping it is
                // destroying the port: what is left is the send rights, dead.
                _ => match delta {
                    0 => KERN_SUCCESS,
                    -1 if owned.guarded => KERN_INVALID_RIGHT,
                    -1 => {
                        match owned.remainder() {
                            Some(dead) => space.names.insert(name, dead),
                            None => space.names.remove(&name),
                        };
                        KERN_SUCCESS
                    }
                    _ => KERN_INVALID_VALUE,
                },
            };
        }
        match held {
            Right::Send { refs, .. }
            | Right::Dead { refs }
            | Right::Task { refs, .. }
            | Right::Thread { refs, .. } => {
                let updated = *refs as i64 + delta as i64;
                if updated < 0 {
                    return KERN_INVALID_VALUE;
                }
                if updated > u32::MAX as i64 {
                    return KERN_UREFS_OVERFLOW;
                }
                *refs = updated as u32;
                if updated == 0 {
                    space.names.remove(&name);
                }
                KERN_SUCCESS
            }
            // A receive right and a port set have exactly one reference, so the
            // only legal delta is the one that destroys them.
            _ => match delta {
                0 => KERN_SUCCESS,
                -1 => {
                    space.names.remove(&name);
                    KERN_SUCCESS
                }
                _ => KERN_INVALID_VALUE,
            },
        }
    })
}

/// `kern_return_t mach_port_get_refs(ipc_space_t, mach_port_name_t,
/// mach_port_right_t, mach_port_urefs_t *)`
///
/// # Safety
///
/// `out` is a writable `mach_port_urefs_t`.
pub unsafe extern "C" fn mach_port_get_refs(
    task: Name,
    name: Name,
    right: u32,
    out: *mut u32,
) -> i32 {
    if out.is_null() {
        return KERN_INVALID_ADDRESS;
    }
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    let Some(held) = guard.names.get(&name) else {
        return KERN_INVALID_NAME;
    };
    let refs = match (held, held.type_bits() & type_of(right) != 0) {
        (_, false) => 0,
        (Right::Send { refs, .. } | Right::Dead { refs }, true) => *refs,
        (Right::Receive(owned), true) if right == RIGHT_SEND => owned.sends,
        (_, true) => 1,
    };
    // SAFETY: the caller's `mach_port_urefs_t`.
    unsafe { out.write(refs) };
    KERN_SUCCESS
}

/// `kern_return_t mach_port_insert_right(ipc_space_t, mach_port_name_t,
/// mach_port_poly_t, mach_msg_type_name_t)`
///
/// The name is the caller's choice, not this space's, which is the one place a
/// caller writes into the namespace rather than reading a name out of it.
pub extern "C" fn mach_port_insert_right(
    task: Name,
    name: Name,
    right: Name,
    disposition: u32,
) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let Some(address) = address_of(right) else {
        return KERN_INVALID_CAPABILITY;
    };
    with(|space| {
        if space.names.contains_key(&name) && name != right {
            return KERN_RIGHT_EXISTS;
        }
        // A send right made from a receive right, under its own name: the two
        // share the entry. Copying or moving a send right needs one there.
        if let Some(Right::Receive(owned)) = space.names.get_mut(&name) {
            return match disposition {
                super::msg::MAKE_SEND => {
                    owned.add_send(None);
                    KERN_SUCCESS
                }
                super::msg::COPY_SEND if owned.sends > 0 => {
                    owned.add_send(None);
                    KERN_SUCCESS
                }
                // The right moves onto the name it is already under.
                super::msg::MOVE_SEND if owned.sends > 0 => KERN_SUCCESS,
                super::msg::COPY_SEND | super::msg::MOVE_SEND => KERN_INVALID_RIGHT,
                // A send-once right never shares a name.
                _ => KERN_RIGHT_EXISTS,
            };
        }
        let inserted = match disposition {
            super::msg::MAKE_SEND | super::msg::COPY_SEND | super::msg::MOVE_SEND => Right::Send {
                address,
                refs: 1,
                claim: super::wire::claim(address),
            },
            super::msg::MAKE_SEND_ONCE | super::msg::MOVE_SEND_ONCE => Right::SendOnce { address },
            _ => return KERN_INVALID_VALUE,
        };
        space.names.insert(name, inserted);
        KERN_SUCCESS
    })
}

/// `kern_return_t mach_port_extract_right(ipc_space_t, mach_port_name_t,
/// mach_msg_type_name_t, mach_port_poly_t *, mach_msg_type_name_t *)`
///
/// The call a crash reporter makes to keep a send right to the port whose
/// receive right it is about to hand its handler.
///
/// # Safety
///
/// `out` and `out_type` are writable 32-bit words, or null.
pub unsafe extern "C" fn mach_port_extract_right(
    task: Name,
    name: Name,
    disposition: u32,
    out: *mut Name,
    out_type: *mut u32,
) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let Some(address) = address_of(name) else {
        return KERN_INVALID_NAME;
    };
    let (extracted, kind) = match disposition {
        super::msg::MAKE_SEND | super::msg::COPY_SEND => {
            (insert_send(address), super::msg::MOVE_SEND)
        }
        super::msg::MAKE_SEND_ONCE => (insert_send_once(address), super::msg::MOVE_SEND_ONCE),
        super::msg::MOVE_SEND => (name, super::msg::MOVE_SEND),
        _ => return KERN_INVALID_VALUE,
    };
    if !out.is_null() {
        // SAFETY: the caller's `mach_port_t`.
        unsafe { out.write(extracted) };
    }
    if !out_type.is_null() {
        // SAFETY: the caller's `mach_msg_type_name_t`.
        unsafe { out_type.write(kind) };
    }
    KERN_SUCCESS
}

/// `kern_return_t mach_port_type(ipc_space_t, mach_port_name_t, mach_port_type_t *)`
///
/// # Safety
///
/// `out` is a writable `mach_port_type_t`.
pub unsafe extern "C" fn mach_port_type(task: Name, name: Name, out: *mut u32) -> i32 {
    if out.is_null() {
        return KERN_INVALID_ADDRESS;
    }
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    let Some(held) = guard.names.get(&name) else {
        return KERN_INVALID_NAME;
    };
    // SAFETY: the caller's `mach_port_type_t`.
    unsafe { out.write(held.type_bits()) };
    KERN_SUCCESS
}

/// `kern_return_t mach_port_insert_member(ipc_space_t, mach_port_name_t,
/// mach_port_name_t pset)`
pub extern "C" fn mach_port_insert_member(task: Name, name: Name, pset: Name) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if receiver(name).is_none() {
        return KERN_INVALID_RIGHT;
    }
    with(|space| match space.names.get_mut(&pset) {
        Some(Right::Set(members)) => {
            if !members.contains(&name) {
                members.push(name);
            }
            KERN_SUCCESS
        }
        Some(_) => KERN_INVALID_RIGHT,
        None => KERN_INVALID_NAME,
    })
}

/// `kern_return_t mach_port_move_member(ipc_space_t, mach_port_name_t,
/// mach_port_name_t after)`
///
/// A member belongs to at most one set, so this is a removal from every set
/// followed by an insertion - and `MACH_PORT_NULL` for `after` is the removal
/// on its own.
pub extern "C" fn mach_port_move_member(task: Name, name: Name, after: Name) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if receiver(name).is_none() {
        return KERN_INVALID_RIGHT;
    }
    with(|space| {
        for right in space.names.values_mut() {
            if let Right::Set(members) = right {
                members.retain(|member| *member != name);
            }
        }
        if after == MACH_PORT_NULL {
            return KERN_SUCCESS;
        }
        match space.names.get_mut(&after) {
            Some(Right::Set(members)) => {
                members.push(name);
                KERN_SUCCESS
            }
            Some(_) => KERN_INVALID_RIGHT,
            None => KERN_INVALID_NAME,
        }
    })
}

/// `kern_return_t mach_port_get_set_status(...)` and the attribute calls beside
/// it, which set queue limits and other things this transport does not model.
///
/// Accepted rather than refused: every one of them is advisory - a caller that
/// is told its queue limit was raised behaves the same either way - and the
/// alternative is failing an initialisation that had nothing wrong with it.
pub extern "C" fn mach_port_set_attributes(
    task: Name,
    name: Name,
    _flavor: i32,
    _info: *mut std::ffi::c_void,
    _count: u32,
) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let guard = space().read().unwrap_or_else(|e| e.into_inner());
    match guard.names.contains_key(&name) {
        true => KERN_SUCCESS,
        false => KERN_INVALID_NAME,
    }
}

/// `MPO_*`, the `mach_port_options_t` flags from `<mach/port.h>`.
mod mpo {
    pub const CONTEXT_AS_GUARD: u32 = 0x01;
    pub const QLIMIT: u32 = 0x02;
    pub const TEMPOWNER: u32 = 0x04;
    pub const IMPORTANCE_RECEIVER: u32 = 0x08;
    pub const INSERT_SEND_RIGHT: u32 = 0x10;
    pub const STRICT: u32 = 0x20;
    pub const DENAP_RECEIVER: u32 = 0x40;
    pub const IMMOVABLE_RECEIVE: u32 = 0x80;
    pub const FILTER_MSG: u32 = 0x100;
    pub const TG_BLOCK_TRACKING: u32 = 0x200;
    pub const ENFORCE_REPLY_PORT_SEMANTICS: u32 = 0x2000;
    pub const OPTIONS_MASK: u32 = CONTEXT_AS_GUARD
        | QLIMIT
        | TEMPOWNER
        | IMPORTANCE_RECEIVER
        | INSERT_SEND_RIGHT
        | STRICT
        | DENAP_RECEIVER
        | IMMOVABLE_RECEIVE
        | FILTER_MSG
        | TG_BLOCK_TRACKING
        | ENFORCE_REPLY_PORT_SEMANTICS;
    /// `MPO_PORT_TYPE_MASK`: `MPO_MAKE_PORT_TYPE(7, 7)`.
    pub const PORT_TYPE_MASK: u32 = (7 << 14) | (7 << 10);
    /// The port types: a plain port, a service port, a connection port, a
    /// reply port, a provisional reply port, an exception port, and a
    /// connection port with a port array.
    pub const PORT_TYPES: [u32; 7] = [0, 0x400, 0x800, 0x1000, 0x4000, 0x8000, 0x10000];
    pub const SERVICE_PORT: u32 = 0x400;
    pub const CONNECTION_PORT: u32 = 0x800;
}

/// `MACH_PORT_QLIMIT_MAX`, which is `MACH_PORT_QLIMIT_LARGE`.
const QLIMIT_MAX: u32 = 1024;

/// `mach_port_options_t`: the flags, `mach_port_limits_t`, then a sixteen-byte
/// union whose first word is a port name for the types that take one.
#[repr(C)]
pub struct Options {
    flags: u32,
    qlimit: u32,
    union: [u64; 2],
}

/// `kern_return_t mach_port_construct(ipc_space_t, mach_port_options_t *,
/// uint64_t context, mach_port_name_t *)`
///
/// `mach_port_construct` in `osfmk/ipc/mach_port.c`: a receive right with the
/// options applied - a send right under the same name, a guard, a context, an
/// immovable receive right. The scheduling hints (importance, de-nap,
/// thread-group tracking, temporary ownership) and the queue limit change how
/// the kernel schedules and buffers, which nothing here models; they are
/// validated as XNU validates them and otherwise accepted.
///
/// # Safety
///
/// `options` is a readable `mach_port_options_t` and `out` a writable name.
pub unsafe extern "C" fn mach_port_construct(
    task: Name,
    options: *const Options,
    context: u64,
    out: *mut Name,
) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if options.is_null() || out.is_null() {
        return KERN_INVALID_ADDRESS;
    }
    // SAFETY: the caller's options.
    let options = unsafe { &*options };
    let flags = options.flags;
    if flags & !(mpo::OPTIONS_MASK | mpo::PORT_TYPE_MASK) != 0 {
        return KERN_INVALID_ARGUMENT;
    }
    let port_type = flags & mpo::PORT_TYPE_MASK;
    if !mpo::PORT_TYPES.contains(&port_type) {
        return KERN_INVALID_ARGUMENT;
    }
    // A service port is launchd's to make, and a connection port names the
    // service port it connects to - `mach_port_construct_check_service_port`
    // and the `service_port_name` check.
    match port_type {
        mpo::SERVICE_PORT => return KERN_DENIED,
        mpo::CONNECTION_PORT if options.union[0] as u32 == MACH_PORT_NULL => {
            return KERN_INVALID_ARGUMENT;
        }
        _ => {}
    }
    if flags & mpo::QLIMIT != 0 && options.qlimit > QLIMIT_MAX {
        return KERN_INVALID_VALUE;
    }
    // Only the window server may track thread-group blocking.
    if flags & mpo::TG_BLOCK_TRACKING != 0 {
        return KERN_DENIED;
    }
    let Ok(port) = Receiver::bind() else {
        return KERN_RESOURCE_SHORTAGE;
    };
    let mut owned = Owned::new(Arc::new(port));
    owned.immovable = flags & mpo::IMMOVABLE_RECEIVE != 0;
    if flags & mpo::INSERT_SEND_RIGHT != 0 {
        owned.add_send(None);
    }
    owned.context = context;
    if flags & mpo::CONTEXT_AS_GUARD != 0 {
        owned.guarded = true;
        owned.strict = flags & mpo::STRICT != 0;
    }
    let name = insert(Right::Receive(owned));
    // SAFETY: the caller's `mach_port_name_t`.
    unsafe { out.write(name) };
    KERN_SUCCESS
}

/// Whether `name` is a name rather than `MACH_PORT_NULL` or `MACH_PORT_DEAD`:
/// `MACH_PORT_VALID`.
fn valid(name: Name) -> bool {
    name != MACH_PORT_NULL && name != MACH_PORT_DEAD
}

/// Run `f` on the receive right `name`, or answer as
/// `ipc_port_translate_receive` does for a name that is not one.
fn with_receive(name: Name, f: impl FnOnce(&mut Owned) -> i32) -> i32 {
    with(|space| match space.names.get_mut(&name) {
        Some(Right::Receive(owned)) => f(owned),
        Some(_) => KERN_INVALID_RIGHT,
        None => KERN_INVALID_NAME,
    })
}

/// `kern_return_t mach_port_destruct(ipc_space_t, mach_port_name_t,
/// mach_port_delta_t srdelta, uint64_t guard)`
///
/// `ipc_right_destruct`: drop `-srdelta` user references from the send right
/// under the name, then destroy the receive right - which must be given its
/// guard if it has one. Send references left over become a dead name.
pub extern "C" fn mach_port_destruct(task: Name, name: Name, srdelta: i32, guard: u64) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if !valid(name) {
        return KERN_INVALID_NAME;
    }
    with(|space| {
        let Some(held) = space.names.get_mut(&name) else {
            return KERN_INVALID_NAME;
        };
        let Right::Receive(owned) = held else {
            return KERN_INVALID_RIGHT;
        };
        if srdelta != 0 && owned.sends == 0 {
            return KERN_INVALID_RIGHT;
        }
        if srdelta > 0 {
            return KERN_INVALID_VALUE;
        }
        if owned.guarded && guard != owned.context {
            return KERN_INVALID_ARGUMENT;
        }
        let remaining = owned.sends as i64 + srdelta as i64;
        if remaining < 0 {
            return KERN_INVALID_VALUE;
        }
        owned.sends = remaining as u32;
        match owned.remainder() {
            Some(dead) => space.names.insert(name, dead),
            None => space.names.remove(&name),
        };
        KERN_SUCCESS
    })
}

/// `kern_return_t mach_port_guard(ipc_space_t, mach_port_name_t,
/// mach_port_context_t guard, boolean_t strict)`
///
/// `mach_port_guard_locked`: a port that already carries a context, guard or
/// not, cannot be guarded.
pub extern "C" fn mach_port_guard(task: Name, name: Name, guard: u64, strict: i32) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if !valid(name) {
        return KERN_INVALID_NAME;
    }
    with_receive(name, |owned| {
        if owned.context != 0 {
            return KERN_INVALID_ARGUMENT;
        }
        owned.context = guard;
        owned.guarded = true;
        owned.strict = strict != 0;
        KERN_SUCCESS
    })
}

/// `kern_return_t mach_port_unguard(ipc_space_t, mach_port_name_t,
/// mach_port_context_t guard)`
pub extern "C" fn mach_port_unguard(task: Name, name: Name, guard: u64) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if !valid(name) {
        return KERN_INVALID_NAME;
    }
    with_receive(name, |owned| {
        if !owned.guarded || owned.context != guard {
            return KERN_INVALID_ARGUMENT;
        }
        owned.context = 0;
        owned.guarded = false;
        owned.strict = false;
        KERN_SUCCESS
    })
}

/// `kern_return_t mach_port_get_context(ipc_space_t, mach_port_name_t,
/// mach_port_context_t *)`
///
/// A strict guard is not given away: the context reads as zero.
///
/// # Safety
///
/// `out` is a writable `mach_port_context_t`.
pub unsafe extern "C" fn mach_port_get_context(task: Name, name: Name, out: *mut u64) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if !valid(name) {
        return KERN_INVALID_RIGHT;
    }
    if out.is_null() {
        return KERN_INVALID_ADDRESS;
    }
    with_receive(name, |owned| {
        let context = if owned.strict { 0 } else { owned.context };
        // SAFETY: the caller's word.
        unsafe { out.write(context) };
        KERN_SUCCESS
    })
}

/// `kern_return_t mach_port_set_context(ipc_space_t, mach_port_name_t,
/// mach_port_context_t)`
///
/// A strictly guarded port's context is its guard and cannot be replaced; a
/// loosely guarded one's can, and the guard is then the new value, as XNU
/// stores both in the one `ip_context`.
pub extern "C" fn mach_port_set_context(task: Name, name: Name, context: u64) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    if !valid(name) {
        return KERN_INVALID_RIGHT;
    }
    with_receive(name, |owned| {
        if owned.strict {
            return KERN_INVALID_ARGUMENT;
        }
        owned.context = context;
        KERN_SUCCESS
    })
}

/// `MACH_NOTIFY_NO_SENDERS`, from `<mach/notify.h>`: `MACH_NOTIFY_FIRST + 6`.
pub const NOTIFY_NO_SENDERS: i32 = 0o106;

/// `kern_return_t mach_port_request_notification(ipc_space_t, mach_port_name_t,
/// mach_msg_id_t, mach_port_mscount_t, mach_port_name_t notify,
/// mach_msg_type_name_t, mach_port_name_t *previous)`
///
/// `MACH_NOTIFY_NO_SENDERS` is delivered - see [`super::senders`] - because a
/// process that is the only thing keeping a helper alive is what the helper
/// watches for: a crash handler that is never told its client has exited stays
/// behind forever. Every other notification is recorded and never delivered.
/// Inventing one would be worse than withholding it: a dead-name notification
/// tells a client its server has died, so a spurious one makes a working server
/// look dead, where the withheld direction says "still alive", which is the
/// failure a caller can survive.
///
/// # Safety
///
/// `previous` is a writable `mach_port_name_t`, or null.
pub unsafe extern "C" fn mach_port_request_notification(
    task: Name,
    name: Name,
    id: i32,
    sync: u32,
    notify: Name,
    disposition: u32,
    previous: *mut Name,
) -> i32 {
    if task != TASK_SELF {
        return KERN_INVALID_TASK;
    }
    let held = with_right(name, |right| matches!(right, Right::Receive(..)));
    let Some(is_receive) = held else {
        return KERN_INVALID_NAME;
    };
    if id == NOTIFY_NO_SENDERS && !is_receive {
        return KERN_INVALID_RIGHT;
    }
    let port = receiver(name);
    // Where the notification goes. A `MAKE_` disposition names the receive right
    // it is made from and leaves it alone; a `MOVE_` one hands over a send-once
    // right, which the request consumes whether or not it ever fires.
    let destination = (notify != MACH_PORT_NULL)
        .then(|| address_of(notify))
        .flatten();
    if notify != MACH_PORT_NULL
        && matches!(
            disposition,
            super::msg::MOVE_SEND_ONCE | super::msg::MOVE_SEND
        )
    {
        with(|space| release(space, notify));
    }
    if !previous.is_null() {
        // SAFETY: the caller's `mach_port_name_t`.
        unsafe { previous.write(MACH_PORT_NULL) };
    }
    if id == NOTIFY_NO_SENDERS
        && let Some(port) = port
        && super::senders::request(port.address(), destination, sync)
    {
        return KERN_SUCCESS;
    }
    announce_undelivered_notifications(id);
    KERN_SUCCESS
}

fn announce_undelivered_notifications(id: i32) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "rosemary: mach_port_request_notification {id:#o} accepted but never delivered - \
             nothing here watches this kind of port event, so a caller waiting for it waits \
             forever rather than being told a live port died"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mistake this constant exists to stop: `MACH_PORT_RIGHT_SEND` is
    /// zero and `MACH_PORT_RIGHT_RECEIVE` is one, so a table indexed the
    /// intuitive way round hands out a send right to a caller that asked to
    /// receive.
    #[test]
    fn the_right_numbers_are_the_headers_and_not_the_intuitive_order() {
        assert_eq!(RIGHT_SEND, 0);
        assert_eq!(RIGHT_RECEIVE, 1);
        assert_eq!(type_of(RIGHT_SEND), 0x0001_0000);
        assert_eq!(type_of(RIGHT_RECEIVE), 0x0002_0000);
        assert_eq!(type_of(RIGHT_DEAD_NAME), 0x0010_0000);
    }

    #[test]
    fn allocating_a_receive_right_gives_a_name_that_reports_itself_as_one() {
        let mut name = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        assert_eq!(
            unsafe { mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut name) },
            KERN_SUCCESS
        );
        assert_ne!(name, MACH_PORT_NULL);

        let mut bits = 0;
        assert_eq!(
            unsafe { mach_port_type(TASK_SELF, name, &mut bits) },
            KERN_SUCCESS
        );
        assert_eq!(bits, type_of(RIGHT_RECEIVE));

        // A receive right cannot be deallocated, only destroyed - the check
        // that catches "deallocate the port you are about to listen on".
        assert_eq!(mach_port_deallocate(TASK_SELF, name), KERN_INVALID_RIGHT);
        assert_eq!(mach_port_destroy(TASK_SELF, name), KERN_SUCCESS);
        assert_eq!(mach_port_destroy(TASK_SELF, name), KERN_INVALID_NAME);
    }

    /// Crashpad's sequence: allocate a receive right, extract a send right to
    /// keep, hand the receive right away. A space names a port once, so the
    /// send right is the receive right's own name.
    #[test]
    fn a_send_right_extracted_from_a_receive_right_names_the_same_port() {
        let mut receive = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut receive) };

        let (mut send, mut kind) = (MACH_PORT_NULL, 0);
        // SAFETY: two live locals for the out-parameters.
        let rc = unsafe {
            mach_port_extract_right(
                TASK_SELF,
                receive,
                super::super::msg::MAKE_SEND,
                &mut send,
                &mut kind,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
        assert_eq!(kind, super::super::msg::MOVE_SEND);
        assert_eq!(send, receive);
        assert_eq!(destination(send).unwrap().1, false, "not send-once");

        // Moving the receive right away leaves the send right behind.
        let moved = move_receive(receive).expect("a movable receive right");
        assert_eq!(address_of(send), Some(moved.address()));
        assert!(receiver(send).is_none());
        assert_eq!(mach_port_deallocate(TASK_SELF, send), KERN_SUCCESS);
        assert!(address_of(send).is_none());
    }

    fn port_type(name: Name) -> u32 {
        let mut bits = 0;
        // SAFETY: a live local for the out-parameter.
        assert_eq!(
            unsafe { mach_port_type(TASK_SELF, name, &mut bits) },
            KERN_SUCCESS
        );
        bits
    }

    fn refs(name: Name, right: u32) -> u32 {
        let mut count = 0;
        // SAFETY: a live local for the out-parameter.
        assert_eq!(
            unsafe { mach_port_get_refs(TASK_SELF, name, right, &mut count) },
            KERN_SUCCESS
        );
        count
    }

    const SEND_RECEIVE: u32 = type_of(RIGHT_SEND) | type_of(RIGHT_RECEIVE);

    /// `mach_port_insert_right(task, port, port, MAKE_SEND)`: the send right
    /// joins the receive right under its name, and releasing it leaves the
    /// receive right alone.
    #[test]
    fn a_send_right_made_under_the_receive_rights_name_shares_it() {
        let mut name = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut name) };
        assert_eq!(
            mach_port_insert_right(TASK_SELF, name, name, super::super::msg::COPY_SEND),
            KERN_INVALID_RIGHT,
            "nothing to copy yet"
        );
        assert_eq!(
            mach_port_insert_right(TASK_SELF, name, name, super::super::msg::MAKE_SEND),
            KERN_SUCCESS
        );
        assert_eq!(port_type(name), SEND_RECEIVE);
        assert!(receiver(name).is_some(), "the receive right is still there");
        assert_eq!(refs(name, RIGHT_SEND), 1);
        assert_eq!(
            insert_send(address_of(name).unwrap()),
            name,
            "one name per port"
        );
        assert_eq!(refs(name, RIGHT_SEND), 2);

        assert_eq!(mach_port_deallocate(TASK_SELF, name), KERN_SUCCESS);
        assert_eq!(
            mach_port_mod_refs(TASK_SELF, name, RIGHT_SEND, -1),
            KERN_SUCCESS
        );
        assert_eq!(port_type(name), type_of(RIGHT_RECEIVE));
        assert_eq!(mach_port_deallocate(TASK_SELF, name), KERN_INVALID_RIGHT);

        // Dropping the receive right with a send right still under the name
        // leaves a dead name, as the port is gone.
        mach_port_insert_right(TASK_SELF, name, name, super::super::msg::MAKE_SEND);
        assert_eq!(
            mach_port_mod_refs(TASK_SELF, name, RIGHT_RECEIVE, -1),
            KERN_SUCCESS
        );
        assert_eq!(port_type(name), type_of(RIGHT_DEAD_NAME));
        assert_eq!(mach_port_deallocate(TASK_SELF, name), KERN_SUCCESS);
        assert_eq!(mach_port_destroy(TASK_SELF, name), KERN_INVALID_NAME);
    }

    fn options(flags: u32) -> Options {
        Options {
            flags,
            qlimit: 0,
            union: [0; 2],
        }
    }

    fn construct(flags: u32, context: u64) -> Result<Name, i32> {
        let mut name = MACH_PORT_NULL;
        // SAFETY: live locals for the options and the out-parameter.
        match unsafe { mach_port_construct(TASK_SELF, &options(flags), context, &mut name) } {
            KERN_SUCCESS => Ok(name),
            error => Err(error),
        }
    }

    /// `mach_port_construct`'s options, as `osfmk/ipc/mach_port.c` reads them.
    #[test]
    fn a_constructed_port_has_the_options_it_was_asked_for() {
        let plain = construct(0, 0x1234).unwrap();
        assert_eq!(port_type(plain), type_of(RIGHT_RECEIVE));
        let mut context = 0;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_get_context(TASK_SELF, plain, &mut context) };
        assert_eq!(context, 0x1234, "an unguarded port keeps the context");
        assert_eq!(mach_port_destruct(TASK_SELF, plain, 0, 0), KERN_SUCCESS);

        let with_send = construct(mpo::INSERT_SEND_RIGHT | mpo::QLIMIT, 0).unwrap();
        assert_eq!(port_type(with_send), SEND_RECEIVE);
        assert_eq!(
            mach_port_destruct(TASK_SELF, with_send, 1, 0),
            KERN_INVALID_VALUE,
            "srdelta only ever removes"
        );
        assert_eq!(
            mach_port_destruct(TASK_SELF, with_send, -1, 0),
            KERN_SUCCESS
        );
        assert_eq!(mach_port_destroy(TASK_SELF, with_send), KERN_INVALID_NAME);

        assert_eq!(
            construct(0x8000_0000, 0),
            Err(KERN_INVALID_ARGUMENT),
            "an unknown bit"
        );
        assert_eq!(
            construct(0x400 | 0x800, 0),
            Err(KERN_INVALID_ARGUMENT),
            "two port types"
        );
        let mut too_deep = options(mpo::QLIMIT);
        too_deep.qlimit = QLIMIT_MAX + 1;
        let mut name = MACH_PORT_NULL;
        // SAFETY: live locals.
        assert_eq!(
            unsafe { mach_port_construct(TASK_SELF, &too_deep, 0, &mut name) },
            KERN_INVALID_VALUE
        );
    }

    /// A guarded port can be destroyed only by `mach_port_destruct` with its
    /// guard, and a strict guard is not given away by `mach_port_get_context`.
    #[test]
    fn a_guarded_port_is_destroyed_only_with_its_guard() {
        let guard = 0xfeed_f00d;
        let name = construct(mpo::CONTEXT_AS_GUARD | mpo::STRICT, guard).unwrap();
        let mut context = 1;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_get_context(TASK_SELF, name, &mut context) };
        assert_eq!(context, 0);
        assert_eq!(
            mach_port_set_context(TASK_SELF, name, 7),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(mach_port_destroy(TASK_SELF, name), KERN_INVALID_RIGHT);
        assert_eq!(
            mach_port_mod_refs(TASK_SELF, name, RIGHT_RECEIVE, -1),
            KERN_INVALID_RIGHT
        );
        assert_eq!(
            mach_port_destruct(TASK_SELF, name, 0, guard + 1),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(
            mach_port_unguard(TASK_SELF, name, guard + 1),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(mach_port_destruct(TASK_SELF, name, 0, guard), KERN_SUCCESS);

        // Guarding after the fact, and a context already set is refused.
        let later = construct(0, 0).unwrap();
        assert_eq!(mach_port_guard(TASK_SELF, later, guard, 0), KERN_SUCCESS);
        assert_eq!(
            mach_port_guard(TASK_SELF, later, guard, 0),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(mach_port_unguard(TASK_SELF, later, guard), KERN_SUCCESS);
        assert_eq!(mach_port_destroy(TASK_SELF, later), KERN_SUCCESS);
    }

    /// `MPO_IMMOVABLE_RECEIVE`: the right stays in this space.
    #[test]
    fn an_immovable_receive_right_is_not_moved() {
        let name = construct(mpo::IMMOVABLE_RECEIVE, 0).unwrap();
        assert_eq!(move_receive(name).err(), Some(MACH_SEND_INVALID_RIGHT));
        assert!(receiver(name).is_some());
        assert_eq!(mach_port_destruct(TASK_SELF, name, 0, 0), KERN_SUCCESS);
    }

    #[test]
    fn a_send_right_is_reference_counted_and_the_name_survives_until_the_last_one() {
        // The receive right goes elsewhere first, so the send rights are a
        // name of their own rather than the receive right's.
        let mut receive = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut receive) };
        let elsewhere = move_receive(receive).expect("a movable receive right");
        let address = elsewhere.address();

        let first = insert_send(address);
        let second = insert_send(address);
        assert_eq!(first, second, "the same port keeps the same name");

        assert_eq!(mach_port_deallocate(TASK_SELF, first), KERN_SUCCESS);
        assert!(address_of(first).is_some(), "one reference is still held");
        assert_eq!(mach_port_deallocate(TASK_SELF, first), KERN_SUCCESS);
        assert!(address_of(first).is_none());
    }

    #[test]
    fn a_port_set_holds_the_members_put_into_it() {
        let mut set = MACH_PORT_NULL;
        let mut member = MACH_PORT_NULL;
        // SAFETY: live locals for the out-parameters.
        unsafe {
            mach_port_allocate(TASK_SELF, RIGHT_PORT_SET, &mut set);
            mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut member);
        }
        assert_eq!(
            mach_port_insert_member(TASK_SELF, member, set),
            KERN_SUCCESS
        );
        assert_eq!(members(set).unwrap(), vec![member]);
        // A set is not a receive right, and inserting one into itself is not a
        // question with an answer.
        assert_eq!(
            mach_port_insert_member(TASK_SELF, set, set),
            KERN_INVALID_RIGHT
        );
        assert_eq!(
            mach_port_move_member(TASK_SELF, member, MACH_PORT_NULL),
            KERN_SUCCESS
        );
        assert!(members(set).unwrap().is_empty());

        mach_port_destroy(TASK_SELF, set);
        mach_port_destroy(TASK_SELF, member);
    }

    /// A receive right somebody else still holds cannot be moved out from under
    /// them - the check that stops this process reading a socket another
    /// process now owns.
    #[test]
    fn a_receive_right_in_use_is_not_moved() {
        let mut name = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe { mach_port_allocate(TASK_SELF, RIGHT_RECEIVE, &mut name) };
        let held = receiver(name).expect("a receive right");
        assert_eq!(move_receive(name).err(), Some(MACH_SEND_INVALID_RIGHT));
        assert!(receiver(name).is_some(), "the right was put back");
        drop(held);
        assert!(move_receive(name).is_ok());
    }
}
