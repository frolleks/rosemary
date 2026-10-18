use std::ffi::c_void;
use std::os::fd::FromRawFd;

use super::kern::*;
use super::space::{self, MACH_PORT_DEAD, MACH_PORT_NULL, Name};
use super::wire::{self, Datagram, Receiver};

/// `MACH_MSG_TYPE_*`, the dispositions a header field or descriptor can carry.
pub const MOVE_RECEIVE: u32 = 16;
pub const MOVE_SEND: u32 = 17;
pub const MOVE_SEND_ONCE: u32 = 18;
pub const COPY_SEND: u32 = 19;
pub const MAKE_SEND: u32 = 20;
pub const MAKE_SEND_ONCE: u32 = 21;

/// `MACH_MSGH_BITS_*`.
const BITS_COMPLEX: u32 = 0x8000_0000;
const BITS_PORTS_MASK: u32 = 0x1f;
const BITS_LOCAL_SHIFT: u32 = 8;

/// `MACH_SEND_MSG` and friends, from `<mach/message.h>`.
const SEND_MSG: i32 = 0x0000_0001;
const RCV_MSG: i32 = 0x0000_0002;
const RCV_LARGE: i32 = 0x0000_0004;
const SEND_TIMEOUT: i32 = 0x0000_0010;
const RCV_TIMEOUT: i32 = 0x0000_0100;

/// Where a descriptor says what it is.
///
/// The type byte is at offset 11 of *every* 64-bit descriptor, whatever its
/// kind and whatever its length - the headers lay the bitfields out that way on
/// purpose, so a reader can tell what it is looking at before it knows how far
/// to step.
const DESCRIPTOR_TYPE_AT: usize = 11;
/// The disposition byte, one before it.
const DESCRIPTOR_DISPOSITION_AT: usize = 10;
/// `MACH_MSG_PORT_DESCRIPTOR`, `MACH_MSG_OOL_DESCRIPTOR`,
/// `MACH_MSG_OOL_PORTS_DESCRIPTOR` and `MACH_MSG_OOL_VOLATILE_DESCRIPTOR`.
/// `MACH_MSG_GUARDED_PORT_DESCRIPTOR` is refused.
const DESCRIPTOR_PORT: u8 = 0;
const DESCRIPTOR_OOL: u8 = 1;
const DESCRIPTOR_OOL_PORTS: u8 = 2;
const DESCRIPTOR_OOL_VOLATILE: u8 = 3;
/// `MACH_MSG_PHYSICAL_COPY` and `MACH_MSG_VIRTUAL_COPY`, the copy options a
/// send may name. Both copy here, as XNU's virtual copy is a copy-on-write
/// one: what the receiver gets never changes with the sender's memory.
const PHYSICAL_COPY: u8 = 0;
const VIRTUAL_COPY: u8 = 1;

/// `mach_msg_header_t`, `mach_msg_body_t` and `mach_msg_port_descriptor_t`, in
/// bytes. All three are the same size on x86-64 and arm64.
const HEADER: usize = 24;
const BODY: usize = 4;
const DESCRIPTOR: usize = 12;
/// `mach_msg_ool_descriptor64_t` and `mach_msg_ool_ports_descriptor64_t`: a
/// 64-bit address where a port descriptor has a name.
const OOL_DESCRIPTOR: usize = 16;

/// `mach_msg_trailer_t`: the eight bytes the kernel appends to a received
/// message. `msgh_size` does not include it, but `rcv_size` has to - which is
/// the arithmetic a receiver gets wrong and then blames on the sender.
const TRAILER: usize = 8;
/// `MACH_MSG_TRAILER_FORMAT_0`.
const TRAILER_FORMAT_0: u32 = 0;

/// The trailer a receive asked for with `MACH_RCV_TRAILER_ELEMENTS`, and its
/// size, as `<mach/message.h>`'s `REQUESTED_TRAILER_SIZE` computes it: each
/// element adds its field to the one before.
mod trailer {
    /// `MACH_RCV_TRAILER_ELEMENTS(x)` is `x << 24`, four bits wide.
    pub fn elements(option: i32) -> u32 {
        (option as u32 >> 24) & 0xf
    }

    /// `mach_msg_trailer_t`, `_seqno_`, `_security_`, `_audit_`, `_context_`
    /// and `_mac_trailer_t`: 8, 12, 20, 52, 60 and 68 bytes. `MACH_RCV_TRAILER_AV`
    /// (7) and anything above it get the largest, `max_trailer_t`.
    pub fn size(elements: u32) -> usize {
        match elements {
            0 => super::TRAILER,
            1 => 12,
            2 => 20,
            3 => 52,
            4 => 60,
            _ => 68,
        }
    }

    /// `KERNEL_SECURITY_TOKEN_VALUE`: what a message the kernel wrote says
    /// about its sender. Its audit token is all zeros.
    pub const KERNEL_SECURITY_TOKEN: [u32; 2] = [0, 1];
}

/// `MACH_NOTIFY_SEND_ONCE`, from `<mach/notify.h>`: `MACH_NOTIFY_FIRST + 7`.
pub const NOTIFY_SEND_ONCE: i32 = 0o107;

/// The envelope that crosses the socket, in front of the message's own bytes.
mod envelope {
    pub const MAGIC: u32 = 0x3372_4d43;
    pub const VERSION: u32 = 2;
    /// Where the sender's audit token is: after magic, version, bits, id,
    /// descriptor count and payload length.
    pub const AUDIT_AT: usize = 24;
    /// Where the reply reference is, after the token's eight words.
    pub const REPLY_AT: usize = AUDIT_AT + 32;
    /// Fixed part: all of the above and the reply reference.
    pub const FIXED: usize = REPLY_AT + super::REFERENCE;
}

/// Who a message is from, as its receiver's audit trailer reports it.
#[derive(Clone, Copy)]
enum Sender {
    /// This process, as `task_info(TASK_AUDIT_TOKEN)` describes it.
    Task,
    /// A notification, which on a real system the kernel writes.
    Kernel,
}

impl Sender {
    fn token(self) -> [u32; 8] {
        match self {
            Sender::Task => super::info::audit_token(starnix::process::me()).val,
            Sender::Kernel => [0; 8],
        }
    }
}

/// A port reference as it crosses: 16 bytes, never a name.
const REFERENCE: usize = 16;

/// What a [`Reference`] refers to.
mod refkind {
    pub const NONE: u8 = 0;
    /// A send capability: the receiver may send to `address`.
    pub const SEND: u8 = 1;
    /// A receive right, whose socket is the descriptor at `fd_index`.
    pub const RECEIVE: u8 = 2;
    /// A right whose port is gone.
    pub const DEAD: u8 = 3;
    /// A send right to a task's port: the pid in the low word of the
    /// address, the flavor in the high one.
    pub const TASK: u8 = 4;
    /// A send right to a thread: the pid low, the host thread id high.
    pub const THREAD: u8 = 5;
    /// A send right to a memory entry: its object's descriptor at
    /// `fd_index`, and the address the index of its [`super::MemoryRecord`].
    pub const MEMORY: u8 = 6;
    /// Out-of-line memory: its bytes in the file at `fd_index`, which an empty
    /// region has none of; its length in `address`, and its copy option in
    /// `disposition`.
    pub const REGION: u8 = 7;
    /// The same, sent as `MACH_MSG_OOL_VOLATILE_DESCRIPTOR`.
    pub const VOLATILE_REGION: u8 = 8;
    /// An out-of-line array of ports, `address` long: that many references
    /// follow, one per member, and `disposition` is what each arrives as.
    pub const PORT_ARRAY: u8 = 9;
    /// A send right to a fileport: its file at `fd_index`, and in `address`
    /// bit 0 for the socket's `SO_NOSIGPIPE`.
    pub const FILEPORT: u8 = 10;
}

/// A memory entry's fields as they cross, after the payload: one per
/// [`refkind::MEMORY`] reference, in the order the references index them.
struct MemoryRecord;

impl MemoryRecord {
    const SIZE: usize = 40;

    fn encode(fields: &super::memory::Fields, out: &mut Vec<u8>) {
        out.extend_from_slice(&fields.id.to_le_bytes());
        out.extend_from_slice(&fields.offset.to_le_bytes());
        out.extend_from_slice(&fields.size.to_le_bytes());
        out.extend_from_slice(&fields.data_offset.to_le_bytes());
        out.extend_from_slice(&fields.protection.to_le_bytes());
        let flags = u32::from(fields.copy) | u32::from(fields.private) << 1;
        out.extend_from_slice(&flags.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Option<super::memory::Fields> {
        let bytes = bytes.get(..Self::SIZE)?;
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default());
        let flags = u32::from_le_bytes(bytes[36..40].try_into().ok()?);
        Some(super::memory::Fields {
            id: long(0),
            offset: long(8),
            size: long(16),
            data_offset: long(24),
            protection: i32::from_le_bytes(bytes[32..36].try_into().ok()?),
            copy: flags & 1 != 0,
            private: flags & 2 != 0,
        })
    }
}

#[derive(Clone, Copy)]
struct Reference {
    kind: u8,
    /// The disposition the *receiver* sees, which is always a `MOVE_`: a right
    /// that has arrived has already been transferred.
    disposition: u8,
    /// The descriptor that travelled with this right: a receive right's port,
    /// or a send right's claim on the port. `-1` for none.
    fd_index: i16,
    /// For a receive right, what follows its port in the descriptors: whether its
    /// listener does, how many claims on it do, and whether those are all of
    /// them.
    listener: bool,
    claims: u16,
    complete: bool,
    address: u64,
}

impl Reference {
    const NONE: Reference = Reference {
        kind: refkind::NONE,
        disposition: 0,
        fd_index: -1,
        listener: false,
        claims: 0,
        complete: false,
        address: 0,
    };

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.push(self.disposition);
        out.extend_from_slice(&self.fd_index.to_le_bytes());
        let extra = u32::from(self.claims)
            | u32::from(self.listener) << 16
            | u32::from(self.complete) << 17;
        out.extend_from_slice(&extra.to_le_bytes());
        out.extend_from_slice(&self.address.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Option<Reference> {
        let bytes: &[u8; REFERENCE] = bytes.get(..REFERENCE)?.try_into().ok()?;
        let extra = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        Some(Reference {
            kind: bytes[0],
            disposition: bytes[1],
            fd_index: i16::from_le_bytes([bytes[2], bytes[3]]),
            listener: extra & 1 << 16 != 0,
            claims: (extra & 0xffff) as u16,
            complete: extra & 1 << 17 != 0,
            address: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        })
    }

    /// Put this reference into the receiving task's space and answer with the
    /// name it got. `records` is what follows the payload.
    fn adopt(&self, message: &mut Datagram, records: &[u8]) -> Name {
        match self.kind {
            refkind::TASK => {
                let flavor = space::TaskFlavor::from_raw((self.address >> 32) as u32)
                    .unwrap_or(space::TaskFlavor::Name);
                space::insert_task(self.address as u32 as i32, flavor)
            }
            refkind::THREAD => {
                space::insert_thread(self.address as u32 as i32, (self.address >> 32) as i32)
            }
            refkind::MEMORY => {
                let fd = usize::try_from(self.fd_index)
                    .ok()
                    .and_then(|index| message.take_fd(index));
                let fields = usize::try_from(self.address)
                    .ok()
                    .and_then(|index| records.get(index.checked_mul(MemoryRecord::SIZE)?..))
                    .and_then(MemoryRecord::decode);
                match (fd, fields) {
                    (Some(fd), Some(fields)) => {
                        // SAFETY: a descriptor that arrived over `SCM_RIGHTS`,
                        // now owned by this process.
                        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
                        match super::memory::Entry::adopt(fd, fields) {
                            Ok(entry) => space::insert_memory(entry),
                            Err(_) => MACH_PORT_DEAD,
                        }
                    }
                    _ => MACH_PORT_DEAD,
                }
            }
            refkind::FILEPORT => {
                match usize::try_from(self.fd_index)
                    .ok()
                    .and_then(|index| message.take_fd(index))
                {
                    // SAFETY: a descriptor that arrived over `SCM_RIGHTS`, now
                    // owned by this process.
                    Some(fd) => space::insert_fileport(
                        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
                        self.address & 1 != 0,
                    ),
                    None => MACH_PORT_DEAD,
                }
            }
            refkind::SEND => match self.disposition as u32 {
                MOVE_SEND_ONCE => space::insert_send_once(self.address),
                _ => {
                    let claim = usize::try_from(self.fd_index)
                        .ok()
                        .and_then(|index| message.take_fd(index))
                        // SAFETY: a descriptor that arrived over `SCM_RIGHTS`,
                        // now owned by this process.
                        .map(|fd| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
                    space::insert_send_with(self.address, claim)
                }
            },
            refkind::RECEIVE => match message.take_fd(self.fd_index.max(0) as usize) {
                Some(fd) => {
                    let base = self.fd_index.max(0) as usize;
                    let senders = match self.listener {
                        true => message.take_fd(base + 1).unwrap_or(-1),
                        false => -1,
                    };
                    let claims: Vec<_> = (0..self.claims as usize)
                        .filter_map(|i| message.take_fd(base + 2 + i))
                        .collect();
                    let complete = self.complete && claims.len() == self.claims as usize;
                    // SAFETY: descriptors that arrived over `SCM_RIGHTS` for
                    // the socket bound to `address`, its listener and the
                    // claims on it, now owned by this process.
                    space::insert_receive(unsafe {
                        Receiver::adopt(fd, senders, claims, complete, self.address)
                    })
                }
                // The sender said a right was coming and none did. The name it
                // would have had is dead rather than null, so a caller that
                // sends to it is told the port is gone.
                None => MACH_PORT_DEAD,
            },
            refkind::DEAD => MACH_PORT_DEAD,
            _ => MACH_PORT_NULL,
        }
    }
}

/// A right taken out of this task's space for a send that has not happened yet.
///
/// Held rather than consumed immediately because a failed send has not used the
/// right: Mach leaves the caller holding exactly what it had, and so does this.
enum Pending {
    /// Nothing to undo: `MAKE_SEND` and `COPY_SEND` leave the original in place.
    Copied,
    /// A name to release once the message is away.
    Moved(Name),
    /// A receive right already out of the space, with the descriptors to send:
    /// the port, and its listener or `-1`. `name` is where it goes back.
    Receive {
        name: Name,
        moved: wire::Moved,
        address: u64,
    },
}

impl Pending {
    /// The send failed: put back whatever was taken.
    fn restore(self) {
        match self {
            Pending::Copied | Pending::Moved(_) => {}
            Pending::Receive {
                name,
                moved,
                address,
            } => {
                // SAFETY: the descriptors taken out of the space above, never
                // handed to anything else.
                space::return_receive(name, unsafe {
                    Receiver::adopt(
                        moved.fd,
                        moved.senders,
                        moved.claims,
                        moved.complete,
                        address,
                    )
                });
            }
        }
    }

    /// The send succeeded: consume what the disposition said it would.
    fn commit(self) {
        match self {
            Pending::Copied => {}
            Pending::Moved(name) => {
                space::spend(name);
            }
            Pending::Receive { moved, .. } => {
                // The kernel holds the in-flight reference until the receiver
                // takes it, so this end is done with the descriptors.
                // SAFETY: this process's own copies, already sent.
                unsafe {
                    libc::close(moved.fd);
                    if moved.senders >= 0 {
                        libc::close(moved.senders);
                    }
                    for claim in moved.claims {
                        libc::close(claim);
                    }
                }
            }
        }
    }
}

/// What a message carries beside its datagram, held until the send is done.
#[derive(Default)]
struct Outgoing {
    /// The descriptors that go over `SCM_RIGHTS`, in the order references
    /// index them.
    fds: Vec<std::ffi::c_int>,
    /// Descriptors this send opened - claims, and the files regions travel
    /// in - closed once it is done.
    opened: Vec<std::os::fd::OwnedFd>,
    /// Memory entries whose objects are in `fds`, and whose fields follow the
    /// payload.
    memory: Vec<std::sync::Arc<super::memory::Entry>>,
    /// Fileports' files, kept open while their descriptors are in `fds`.
    files: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// Memory the sender gave up with `deallocate`, released once the message
    /// is away, as address and length.
    released: Vec<(u64, u64)>,
}

impl Outgoing {
    /// Pass `fd` with the message, and say where it is.
    fn pass(&mut self, fd: std::ffi::c_int) -> i16 {
        self.fds.push(fd);
        (self.fds.len() - 1) as i16
    }
}

/// A send right to a kernel object - a task, a thread, a memory entry or a
/// fileport - as it crosses, or `None` for a port. What a memory entry or a
/// fileport needs to cross goes in `out`.
fn kernel_object(name: Name, out: &mut Outgoing) -> Option<Reference> {
    use std::os::fd::AsRawFd;
    let reference = |kind, address| Reference {
        kind,
        disposition: MOVE_SEND as u8,
        address,
        ..Reference::NONE
    };
    if let Some((pid, flavor)) = space::task_of(name) {
        return Some(reference(
            refkind::TASK,
            u64::from(pid as u32) | (flavor as u64) << 32,
        ));
    }
    if let Some(entry) = space::memory_entry(name) {
        let mut carried = reference(refkind::MEMORY, out.memory.len() as u64);
        carried.fd_index = out.pass(entry.object.fd());
        out.memory.push(entry);
        return Some(carried);
    }
    if let Some((file, nosigpipe)) = space::fileport_of(name) {
        let mut carried = reference(refkind::FILEPORT, u64::from(nosigpipe));
        carried.fd_index = out.pass(file.as_raw_fd());
        out.files.push(file);
        return Some(carried);
    }
    // Last, because a thread's borrowed name is its host thread id and is in
    // no table: only a thread right, or a name that is nothing else, is one.
    let thread = space::with_right(name, |right| matches!(right, space::Right::Thread { .. }));
    if thread != Some(false)
        && let Some((pid, tid)) = space::thread_of(name)
    {
        return Some(reference(
            refkind::THREAD,
            u64::from(pid as u32) | u64::from(tid as u32) << 32,
        ));
    }
    None
}

/// What a right sent under `disposition` arrives as, `ipc_object_copyin_type`'s
/// mapping: every send right is a `MOVE_SEND` by the time it lands, and every
/// send-once right a `MOVE_SEND_ONCE`.
fn arrives_as(disposition: u32) -> Option<u8> {
    match disposition {
        MOVE_RECEIVE => Some(MOVE_RECEIVE as u8),
        MOVE_SEND | COPY_SEND | MAKE_SEND => Some(MOVE_SEND as u8),
        MOVE_SEND_ONCE | MAKE_SEND_ONCE => Some(MOVE_SEND_ONCE as u8),
        _ => None,
    }
}

/// Turn `name`, held under `disposition`, into something that can cross.
fn export(
    name: Name,
    disposition: u32,
    out: &mut Outgoing,
) -> Result<(Reference, Option<Pending>), i32> {
    if name == MACH_PORT_NULL {
        return Ok((Reference::NONE, None));
    }
    if matches!(disposition, COPY_SEND | MOVE_SEND)
        && let Some(reference) = kernel_object(name, out)
    {
        let held = match disposition {
            MOVE_SEND => Pending::Moved(name),
            _ => Pending::Copied,
        };
        return Ok((reference, Some(held)));
    }
    if name == MACH_PORT_DEAD {
        return Ok((
            Reference {
                kind: refkind::DEAD,
                ..Reference::NONE
            },
            None,
        ));
    }
    match disposition {
        MOVE_RECEIVE => {
            let port = space::move_receive(name)?;
            let address = port.address();
            let moved = port.into_parts();
            Ok((
                Reference {
                    kind: refkind::RECEIVE,
                    disposition: MOVE_RECEIVE as u8,
                    fd_index: -1,
                    listener: moved.senders >= 0,
                    claims: 0,
                    complete: moved.complete,
                    address,
                },
                Some(Pending::Receive {
                    name,
                    moved,
                    address,
                }),
            ))
        }
        MAKE_SEND | COPY_SEND | MOVE_SEND => {
            let address = space::address_of(name).ok_or(MACH_SEND_INVALID_RIGHT)?;
            let held = match disposition {
                MOVE_SEND => Pending::Moved(name),
                _ => Pending::Copied,
            };
            Ok((
                Reference {
                    kind: refkind::SEND,
                    disposition: MOVE_SEND as u8,
                    fd_index: -1,
                    listener: false,
                    claims: 0,
                    complete: false,
                    address,
                },
                Some(held),
            ))
        }
        MAKE_SEND_ONCE | MOVE_SEND_ONCE => {
            let address = space::address_of(name).ok_or(MACH_SEND_INVALID_RIGHT)?;
            let held = match disposition {
                MOVE_SEND_ONCE => Pending::Moved(name),
                _ => Pending::Copied,
            };
            Ok((
                Reference {
                    kind: refkind::SEND,
                    disposition: MOVE_SEND_ONCE as u8,
                    fd_index: -1,
                    listener: false,
                    claims: 0,
                    complete: false,
                    address,
                },
                Some(held),
            ))
        }
        _ => Err(MACH_SEND_INVALID_TYPE),
    }
}

/// The datagram for a message: the envelope, its references, then the payload.
fn encode(
    sender: Sender,
    bits: u32,
    id: i32,
    reply: &Reference,
    descriptors: &[Reference],
    payload: &[u8],
    memory: &[std::sync::Arc<super::memory::Entry>],
) -> Vec<u8> {
    let mut wire_bytes =
        Vec::with_capacity(envelope::FIXED + descriptors.len() * REFERENCE + payload.len());
    wire_bytes.extend_from_slice(&envelope::MAGIC.to_le_bytes());
    wire_bytes.extend_from_slice(&envelope::VERSION.to_le_bytes());
    wire_bytes.extend_from_slice(&bits.to_le_bytes());
    wire_bytes.extend_from_slice(&id.to_le_bytes());
    wire_bytes.extend_from_slice(&(descriptors.len() as u32).to_le_bytes());
    wire_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    for word in sender.token() {
        wire_bytes.extend_from_slice(&word.to_le_bytes());
    }
    reply.encode(&mut wire_bytes);
    for reference in descriptors {
        reference.encode(&mut wire_bytes);
    }
    wire_bytes.extend_from_slice(payload);
    for entry in memory {
        MemoryRecord::encode(&entry.fields(), &mut wire_bytes);
    }
    wire_bytes
}

/// Queue a `MACH_NOTIFY_NO_SENDERS` message on the port at `destination`.
///
/// What a kernel would write on a port's behalf: a `mach_no_senders_notification_t`
/// - header, `NDR_record_t`, and the make-send count - arriving as a message with
/// no reply port, which is how a MIG notify server tells it from a request.
pub fn deliver_no_senders(destination: wire::Address, count: u32) {
    /// `NDR_record`: little-endian integers, ASCII characters, IEEE floats.
    const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
    let mut payload = Vec::with_capacity(NDR.len() + 4);
    payload.extend_from_slice(&NDR);
    payload.extend_from_slice(&count.to_le_bytes());
    let bytes = encode(
        Sender::Kernel,
        MOVE_SEND_ONCE,
        space::NOTIFY_NO_SENDERS,
        &Reference::NONE,
        &[],
        &payload,
        &[],
    );
    // A destination that is gone has nothing left to tell.
    let _ = wire::send(destination, &bytes, &[]);
}

/// Queue a `MACH_NOTIFY_DEAD_NAME` on the port at `destination`: the send
/// right `name` - a name in the requesting task's space - is now dead.
///
/// `mach_dead_name_notification_t`: header, `NDR_record_t`, and the name.
pub fn deliver_dead_name(destination: wire::Address, name: Name) {
    /// `NDR_record`, as in [`deliver_no_senders`].
    const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
    let mut payload = Vec::with_capacity(NDR.len() + 4);
    payload.extend_from_slice(&NDR);
    payload.extend_from_slice(&name.to_le_bytes());
    let bytes = encode(
        Sender::Kernel,
        MOVE_SEND_ONCE,
        space::NOTIFY_DEAD_NAME,
        &Reference::NONE,
        &[],
        &payload,
        &[],
    );
    let _ = wire::send(destination, &bytes, &[]);
}

/// Queue a `MACH_NOTIFY_SEND_ONCE` on the port at `destination`, whose
/// send-once right was destroyed without carrying a message.
///
/// `mach_send_once_notification_t` is the header alone, arriving on the port
/// the right named - which is how a client blocked on a reply learns that the
/// server dropped its request rather than answering it.
pub fn deliver_send_once(destination: wire::Address) {
    let bytes = encode(
        Sender::Kernel,
        MOVE_SEND_ONCE,
        NOTIFY_SEND_ONCE,
        &Reference::NONE,
        &[],
        &[],
        &[],
    );
    let _ = wire::send(destination, &bytes, &[]);
}

/// Put the descriptors a right travels with in `out`, and say where they are.
///
/// A send right carries a fresh claim on its port rather than the sender's own,
/// so the right counts as a sender while the message is in flight and after the
/// sender has let go of its copy.
fn attach(reference: &mut Reference, held: Option<&Pending>, out: &mut Outgoing) {
    use std::os::fd::AsRawFd;
    match reference.kind {
        refkind::RECEIVE => {
            if let Some(Pending::Receive { moved, .. }) = held {
                reference.fd_index = out.pass(moved.fd);
                if moved.senders >= 0 {
                    out.pass(moved.senders);
                }
                // As many of the port's claims as fit; the rest are closed once
                // the send is done, and the port is then no longer complete.
                let room = wire::MAX_FDS.saturating_sub(out.fds.len());
                let carried = moved.claims.len().min(room);
                out.fds.extend(&moved.claims[..carried]);
                reference.claims = carried as u16;
                reference.complete = moved.complete && carried == moved.claims.len();
            }
        }
        refkind::SEND if reference.disposition as u32 != MOVE_SEND_ONCE => {
            if let Some(claim) = wire::claim(reference.address) {
                reference.fd_index = out.pass(claim.as_raw_fd());
                out.opened.push(claim);
            }
        }
        _ => {}
    }
}

/// Read `len` bytes of the caller's message.
///
/// # Safety
///
/// `msg` addresses at least `len` readable bytes.
unsafe fn read_message(msg: *const u8, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    // SAFETY: the caller's message, whose length it stated in `msgh_size`.
    unsafe { core::ptr::copy_nonoverlapping(msg, bytes.as_mut_ptr(), len) };
    bytes
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn long(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// The bytes of an out-of-line region, in a file of their own: the datagram
/// has a ceiling and a region has none.
fn copy_in(address: u64, length: u32) -> Result<Option<std::os::fd::OwnedFd>, i32> {
    if length == 0 {
        return Ok(None);
    }
    if address == 0 {
        return Err(MACH_SEND_INVALID_MEMORY);
    }
    let file = super::memory::anonymous_file().ok_or(MACH_SEND_NO_BUFFER)?;
    fill(&file, address as *const u8, length as usize)?;
    Ok(Some(file))
}

/// Write `len` bytes of the caller's at `from` to `file`.
///
/// Through `write`, so a range that is not mapped comes back as `EFAULT` -
/// which XNU's `copyin` turns into `MACH_SEND_INVALID_MEMORY` - rather than as
/// a fault in this process.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn fill(file: &std::os::fd::OwnedFd, from: *const u8, len: usize) -> Result<(), i32> {
    use std::os::fd::AsRawFd;
    let mut done = 0;
    while done < len {
        // SAFETY: the kernel reads the caller's range and reports a bad one.
        let n = unsafe { libc::write(file.as_raw_fd(), from.add(done).cast(), len - done) };
        match n {
            n if n > 0 => done += n as usize,
            0 => return Err(MACH_SEND_NO_BUFFER),
            _ => match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EFAULT) => return Err(MACH_SEND_INVALID_MEMORY),
                _ => return Err(MACH_SEND_NO_BUFFER),
            },
        }
    }
    Ok(())
}

/// Write `len` bytes of the caller's at `from` to `file`, through a mapping:
/// a POSIX shared memory object here takes no `write`.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn fill(file: &std::os::fd::OwnedFd, from: *const u8, len: usize) -> Result<(), i32> {
    use std::os::fd::AsRawFd;
    let length = libc::off_t::try_from(len).map_err(|_| MACH_SEND_TOO_LARGE)?;
    // SAFETY: a live descriptor.
    if unsafe { libc::ftruncate(file.as_raw_fd(), length) } != 0 {
        return Err(MACH_SEND_NO_BUFFER);
    }
    // SAFETY: a new shared mapping of the whole file.
    let mapped = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(MACH_SEND_NO_BUFFER);
    }
    // SAFETY: the caller's range, and the mapping just made of the same length.
    unsafe {
        core::ptr::copy_nonoverlapping(from, mapped.cast::<u8>(), len);
        libc::munmap(mapped, len);
    }
    Ok(())
}

/// One right of a message on its way out: exported, its descriptors attached.
fn carry(
    name: Name,
    disposition: u32,
    out: &mut Outgoing,
    pending: &mut Vec<Pending>,
) -> Result<Reference, i32> {
    let (mut reference, held) = export(name, disposition, out)?;
    attach(&mut reference, held.as_ref(), out);
    pending.extend(held);
    if let Some(arrives) = arrives_as(disposition) {
        reference.disposition = arrives;
    }
    Ok(reference)
}

/// The descriptors of a complex message, from `bytes[HEADER..]`, as the
/// references that cross for them, and where the payload starts.
///
/// Each descriptor's size depends on its type, so they are walked in order.
fn descriptors(
    bytes: &[u8],
    out: &mut Outgoing,
    pending: &mut Vec<Pending>,
) -> Result<(Vec<Reference>, usize), i32> {
    let size = bytes.len();
    if size < HEADER + BODY {
        return Err(MACH_SEND_INVALID_DATA);
    }
    let count = word(bytes, HEADER) as usize;
    let mut crossing = Vec::new();
    let mut at = HEADER + BODY;
    for _ in 0..count {
        // A port descriptor is the shortest, and every one has its type where
        // a port descriptor's is.
        if at + DESCRIPTOR > size {
            return Err(MACH_SEND_INVALID_DATA);
        }
        match bytes[at + DESCRIPTOR_TYPE_AT] {
            DESCRIPTOR_PORT => {
                let name = word(bytes, at);
                let disposition = bytes[at + DESCRIPTOR_DISPOSITION_AT] as u32;
                crossing.push(carry(name, disposition, out, pending)?);
                at += DESCRIPTOR;
            }
            kind @ (DESCRIPTOR_OOL | DESCRIPTOR_OOL_VOLATILE) => {
                if at + OOL_DESCRIPTOR > size {
                    return Err(MACH_SEND_INVALID_DATA);
                }
                let address = long(bytes, at);
                let deallocate = bytes[at + 8] != 0;
                let copy = bytes[at + 9];
                let length = word(bytes, at + 12);
                if !matches!(copy, PHYSICAL_COPY | VIRTUAL_COPY) {
                    return Err(MACH_SEND_INVALID_TYPE);
                }
                let mut reference = Reference {
                    kind: match kind {
                        DESCRIPTOR_OOL => refkind::REGION,
                        _ => refkind::VOLATILE_REGION,
                    },
                    disposition: copy,
                    address: u64::from(length),
                    ..Reference::NONE
                };
                if let Some(file) = copy_in(address, length)? {
                    use std::os::fd::AsRawFd;
                    reference.fd_index = out.pass(file.as_raw_fd());
                    out.opened.push(file);
                }
                if deallocate && length > 0 {
                    out.released.push((address, u64::from(length)));
                }
                crossing.push(reference);
                at += OOL_DESCRIPTOR;
            }
            DESCRIPTOR_OOL_PORTS => {
                if at + OOL_DESCRIPTOR > size {
                    return Err(MACH_SEND_INVALID_DATA);
                }
                let address = long(bytes, at);
                let deallocate = bytes[at + 8] != 0;
                let disposition = bytes[at + DESCRIPTOR_DISPOSITION_AT] as u32;
                let members = word(bytes, at + 12) as usize;
                let arrives = arrives_as(disposition).ok_or(MACH_SEND_INVALID_TYPE)?;
                if members > 0 && address == 0 {
                    return Err(MACH_SEND_INVALID_MEMORY);
                }
                // A name per member, at the caller's address.
                let mut names = vec![0 as Name; members];
                // SAFETY: the caller's array of `count` names, as the
                // descriptor states it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        address as *const Name,
                        names.as_mut_ptr(),
                        members,
                    )
                };
                crossing.push(Reference {
                    kind: refkind::PORT_ARRAY,
                    disposition: arrives,
                    address: members as u64,
                    ..Reference::NONE
                });
                for name in names {
                    crossing.push(carry(name, disposition, out, pending)?);
                }
                if deallocate && members > 0 {
                    out.released.push((address, (members * 4) as u64));
                }
                at += OOL_DESCRIPTOR;
            }
            kind => {
                announce_unsupported(kind);
                return Err(MACH_SEND_INVALID_TYPE);
            }
        }
    }
    Ok((crossing, at))
}

/// # Safety
///
/// `msg` addresses a `mach_msg_header_t` and `send_size` readable bytes.
unsafe fn send(msg: *const u8, send_size: u32) -> i32 {
    let size = send_size as usize;
    if !(HEADER..=wire::MAX_MESSAGE).contains(&size) {
        return MACH_SEND_TOO_LARGE;
    }
    // SAFETY: the caller's message, of the size it stated.
    let bytes = unsafe { read_message(msg, size) };

    let bits = word(&bytes, 0);
    let remote_name = word(&bytes, 8);
    let local_name = word(&bytes, 12);
    let id = word(&bytes, 20) as i32;

    let destination = match space::destination(remote_name) {
        Ok((address, _)) => address,
        Err(code) => return code,
    };

    let mut pending = Vec::new();
    let failure = |pending: Vec<Pending>, code: i32| -> i32 {
        for held in pending {
            held.restore();
        }
        code
    };

    // The reply port. Its disposition is the *local* field of `msgh_bits`, which
    // is the one a MIG routine sets to `MAKE_SEND_ONCE` so the server can answer.
    let local_disposition = (bits >> BITS_LOCAL_SHIFT) & BITS_PORTS_MASK;
    let mut out = Outgoing::default();
    let reply = match export(local_name, local_disposition, &mut out) {
        Ok((mut reference, held)) => {
            attach(&mut reference, held.as_ref(), &mut out);
            pending.extend(held);
            reference
        }
        Err(code) => return failure(pending, code),
    };

    let (crossing, payload_at) = match bits & BITS_COMPLEX != 0 {
        true => match descriptors(&bytes, &mut out, &mut pending) {
            Ok(walked) => walked,
            Err(code) => return failure(pending, code),
        },
        false => (Vec::new(), HEADER),
    };

    let wire_bytes = encode(
        Sender::Task,
        bits,
        id,
        &reply,
        &crossing,
        &bytes[payload_at..],
        &out.memory,
    );

    match wire::send(destination, &wire_bytes, &out.fds) {
        Ok(()) => {
            for held in pending {
                held.commit();
            }
            for (address, length) in out.released {
                // SAFETY: memory the caller gave up by sending it with
                // `deallocate`, which is the caller's to give.
                unsafe { super::vm::vm_deallocate(space::TASK_SELF, address, length) };
            }
            // A send-once right is spent by the message that used it, and the
            // destination's own right is released when it was moved.
            let remote_disposition = bits & BITS_PORTS_MASK;
            if let Ok((_, once)) = space::destination(remote_name)
                && (once || remote_disposition == MOVE_SEND)
            {
                space::spend(remote_name);
            }
            MACH_MSG_SUCCESS
        }
        Err(error) => failure(
            pending,
            send_failure(error.raw_os_error().unwrap_or(libc::ECONNREFUSED)),
        ),
    }
}

fn announce_unsupported(kind: u8) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("rosemary: mach_msg refused a message carrying a descriptor of type {kind}");
    }
}

/// Take the next message for `rcv_name`, and the port it actually arrived on -
/// which is a member when the caller is receiving on a port set.
fn next_message(rcv_name: Name, timeout_ms: i32) -> Result<(Datagram, Name), i32> {
    if let Some(port) = space::receiver(rcv_name) {
        return match port.receive(timeout_ms) {
            Ok(Some(message)) => Ok((message, rcv_name)),
            Ok(None) => Err(MACH_RCV_TIMED_OUT),
            Err(_) => Err(MACH_RCV_INVALID_NAME),
        };
    }

    let Some(members) = space::members(rcv_name) else {
        return Err(MACH_RCV_INVALID_NAME);
    };
    let ports: Vec<_> = members
        .iter()
        .filter_map(|name| space::receiver(*name).map(|port| (*name, port)))
        .collect();
    if ports.is_empty() {
        return Err(MACH_RCV_INVALID_NAME);
    }
    // A message held back from a too-small buffer is not on the socket any more,
    // so the set has to be asked about it before anything is polled.
    for (name, port) in &ports {
        if let Some(held) = port.take_held() {
            return Ok((held, *name));
        }
    }
    let fds: Vec<_> = ports.iter().map(|(_, port)| port.fd()).collect();
    let Some(index) = wire::poll_any(&fds, timeout_ms) else {
        return Err(MACH_RCV_TIMED_OUT);
    };
    let (name, port) = &ports[index];
    match port.receive(0) {
        Ok(Some(message)) => Ok((message, *name)),
        // Another thread receiving on the same set took it first.
        Ok(None) => Err(MACH_RCV_TIMED_OUT),
        Err(_) => Err(MACH_RCV_INVALID_NAME),
    }
}

/// A descriptor as its receiver will see it, from the references that
/// crossed for it.
enum Arrived {
    Port(Reference),
    Region(Reference),
    Array(Reference, Vec<Reference>),
}

impl Arrived {
    /// Its size in the receiver's message.
    fn size(&self) -> usize {
        match self {
            Arrived::Port(_) => DESCRIPTOR,
            Arrived::Region(_) | Arrived::Array(..) => OOL_DESCRIPTOR,
        }
    }

    /// The port references in it.
    fn rights(&self) -> &[Reference] {
        match self {
            Arrived::Port(reference) => std::slice::from_ref(reference),
            Arrived::Array(_, members) => members,
            Arrived::Region(_) => &[],
        }
    }
}

/// The descriptors of a datagram, from its `count` references; `None` when
/// they are not what a sender in this module writes.
fn arrived(bytes: &[u8], count: usize) -> Option<Vec<Arrived>> {
    let reference = |i: usize| Reference::decode(bytes.get(envelope::FIXED + i * REFERENCE..)?);
    let mut out = Vec::new();
    let mut i = 0;
    while i < count {
        let first = reference(i)?;
        i += 1;
        out.push(match first.kind {
            refkind::REGION | refkind::VOLATILE_REGION => Arrived::Region(first),
            refkind::PORT_ARRAY => {
                let members = usize::try_from(first.address).ok()?;
                if members > count - i {
                    return None;
                }
                let array = (i..i + members)
                    .map(reference)
                    .collect::<Option<Vec<_>>>()?;
                i += members;
                Arrived::Array(first, array)
            }
            _ => Arrived::Port(first),
        });
    }
    Some(out)
}

/// What destroying a message nobody received does: each send-once right in it
/// is destroyed unused, which its port hears about. Everything else goes with
/// the descriptors the datagram drops.
fn abandon(reply: &Reference, arrived: &[Arrived]) {
    let rights = arrived.iter().flat_map(Arrived::rights);
    for reference in std::iter::once(reply).chain(rights) {
        if reference.kind == refkind::SEND && reference.disposition as u32 == MOVE_SEND_ONCE {
            deliver_send_once(reference.address);
        }
    }
}

/// Map an arrived region into this task as `vm_map_copyout` places one: new,
/// page-aligned memory, private to the receiver, holding the sender's bytes.
/// `None` when it could not be placed.
fn copy_out(file: Option<std::os::fd::OwnedFd>, length: u32) -> Option<u64> {
    use std::os::fd::AsRawFd;
    if length == 0 {
        return Some(0);
    }
    let file = file?;
    let rounded = u64::from(length).next_multiple_of(super::info::page_size());
    let rounded_len = libc::off_t::try_from(rounded).ok()?;
    // The rest of the last page has to be in the file for the mapping to read
    // to its end, as every page of Mach memory does.
    // SAFETY: a descriptor this process now owns.
    if unsafe { libc::ftruncate(file.as_raw_fd(), rounded_len) } != 0 {
        return None;
    }
    // SAFETY: a new private mapping of the whole file, which nothing else
    // writes once it has arrived.
    let mapped = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            rounded as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    (mapped != libc::MAP_FAILED).then_some(mapped as u64)
}

/// A descriptor ready to be written into the receiver's message.
enum Placed {
    Port(Name, u8),
    Memory {
        address: u64,
        length: u32,
        copy: u8,
        kind: u8,
    },
    Ports {
        address: u64,
        count: u32,
        disposition: u8,
    },
}

/// Put an arrived descriptor's rights in this task's space and its memory in
/// its address space. The second value is false when memory could not be
/// placed, which the receive reports as `MACH_MSG_VM_SPACE`.
fn place(arrived: &Arrived, message: &mut Datagram, records: &[u8]) -> (Placed, bool) {
    match arrived {
        Arrived::Port(reference) => (
            Placed::Port(reference.adopt(message, records), reference.disposition),
            true,
        ),
        Arrived::Region(reference) => {
            let file = usize::try_from(reference.fd_index)
                .ok()
                .and_then(|index| message.take_fd(index))
                // SAFETY: a descriptor that arrived over `SCM_RIGHTS`, now
                // owned by this process.
                .map(|fd| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
            let length = reference.address as u32;
            let kind = match reference.kind {
                refkind::REGION => DESCRIPTOR_OOL,
                _ => DESCRIPTOR_OOL_VOLATILE,
            };
            let placed = copy_out(file, length);
            // A region that could not be placed arrives empty.
            let (address, length) = match placed {
                Some(address) => (address, length),
                None => (0, 0),
            };
            (
                Placed::Memory {
                    address,
                    length,
                    copy: reference.disposition,
                    kind,
                },
                placed.is_some(),
            )
        }
        Arrived::Array(header, members) => {
            let names: Vec<Name> = members
                .iter()
                .map(|member| member.adopt(message, records))
                .collect();
            let mut address = 0u64;
            let mut placed = true;
            if !names.is_empty() {
                // SAFETY: a live local for the out-parameter.
                let kr = unsafe {
                    super::vm::vm_allocate(
                        space::TASK_SELF,
                        &mut address,
                        (names.len() * 4) as u64,
                        super::vm::VM_FLAGS_ANYWHERE,
                    )
                };
                match kr {
                    // SAFETY: the allocation just made, a name per member long.
                    KERN_SUCCESS => unsafe {
                        core::ptr::copy_nonoverlapping(
                            names.as_ptr(),
                            address as *mut Name,
                            names.len(),
                        )
                    },
                    _ => {
                        placed = false;
                        address = 0;
                    }
                }
            }
            (
                Placed::Ports {
                    address,
                    count: names.len() as u32,
                    disposition: header.disposition,
                },
                placed,
            )
        }
    }
}

/// # Safety
///
/// `msg` addresses `at + DESCRIPTOR` writable bytes for a port and
/// `at + OOL_DESCRIPTOR` for the rest.
unsafe fn write_descriptor(msg: *mut u8, at: usize, placed: &Placed) {
    let (address, fields, last) = match *placed {
        Placed::Port(name, disposition) => {
            // SAFETY: as the caller states.
            unsafe {
                write_word(msg, at, name);
                write_word(msg, at + 4, 0);
                write_word(msg, at + 8, u32::from(disposition) << 16);
            }
            return;
        }
        // XNU hands the receiver a virtual copy to deallocate, and a physical
        // one it does not have to.
        Placed::Memory {
            address,
            length,
            copy,
            kind,
        } => (
            address,
            [u8::from(copy == VIRTUAL_COPY), copy, 0, kind],
            length,
        ),
        // Always the receiver's to deallocate, and always a virtual copy.
        Placed::Ports {
            address,
            count,
            disposition,
        } => (
            address,
            [1, VIRTUAL_COPY, disposition, DESCRIPTOR_OOL_PORTS],
            count,
        ),
    };
    // SAFETY: as the caller states.
    unsafe {
        write_word(msg, at, address as u32);
        write_word(msg, at + 4, (address >> 32) as u32);
        write_word(msg, at + 8, u32::from_le_bytes(fields));
        write_word(msg, at + 12, last);
    }
}

/// # Safety
///
/// `msg` addresses `rcv_size` writable bytes.
unsafe fn receive(
    msg: *mut u8,
    rcv_size: u32,
    rcv_name: Name,
    timeout_ms: i32,
    option: i32,
) -> i32 {
    let large = option & RCV_LARGE != 0;
    let elements = trailer::elements(option);
    let trailer_size = trailer::size(elements);
    let (mut message, arrived_on) = match next_message(rcv_name, timeout_ms) {
        Ok(taken) => taken,
        Err(code) => return code,
    };

    let bytes = &message.bytes;
    if bytes.len() < envelope::FIXED
        || word(bytes, 0) != envelope::MAGIC
        || word(bytes, 4) != envelope::VERSION
    {
        return MACH_RCV_BODY_ERROR;
    }
    let sender_bits = word(bytes, 8);
    let id = word(bytes, 12) as i32;
    let count = word(bytes, 16) as usize;
    let payload_len = word(bytes, 20) as usize;
    if bytes.len() < envelope::FIXED + count * REFERENCE + payload_len {
        return MACH_RCV_BODY_ERROR;
    }
    let Some(arrived) = arrived(bytes, count) else {
        return MACH_RCV_BODY_ERROR;
    };

    let complex = !arrived.is_empty() || sender_bits & BITS_COMPLEX != 0;
    let body = match complex {
        true => BODY + arrived.iter().map(Arrived::size).sum::<usize>(),
        false => 0,
    };
    let size = HEADER + body + payload_len;
    let reply = Reference::decode(&bytes[envelope::REPLY_AT..]).unwrap_or(Reference::NONE);
    if size + trailer_size > rcv_size as usize {
        // Without `MACH_RCV_LARGE` the message is destroyed, which is what
        // dropping `message` does - including any rights it carried. With it,
        // the caller means to come back with a bigger buffer, so the message is
        // kept for the next receive on the same port.
        if large {
            if rcv_size as usize >= HEADER {
                // SAFETY: at least a header's worth of the caller's buffer,
                // just checked.
                unsafe { write_header(msg, 0, size as u32, MACH_PORT_NULL, arrived_on, id) };
            }
            if let Some(port) = space::receiver(arrived_on) {
                port.hold(message);
            }
        } else {
            abandon(&reply, &arrived);
        }
        return MACH_RCV_TOO_LARGE;
    }

    // Every right in the message enters this task's space before any of it is
    // written out, so a failure part-way cannot leave the caller holding names
    // for rights it was never told about.
    let audit: [u32; 8] = std::array::from_fn(|i| word(bytes, envelope::AUDIT_AT + i * 4));
    let payload_at = envelope::FIXED + count * REFERENCE;
    let records_at = payload_at + payload_len;
    let records = message.bytes.get(records_at..).unwrap_or_default().to_vec();
    let reply_name = reply.adopt(&mut message, &records);
    let mut placed_all = true;
    let placed: Vec<Placed> = arrived
        .iter()
        .map(|one| {
            let (placed, ok) = place(one, &mut message, &records);
            placed_all &= ok;
            placed
        })
        .collect();

    let mut bits =
        (reply.disposition as u32 & BITS_PORTS_MASK) | (MOVE_RECEIVE << BITS_LOCAL_SHIFT);
    if complex {
        bits |= BITS_COMPLEX;
    }

    let seqno = space::receiver(arrived_on).map_or(0, |port| port.next_seqno());
    // SAFETY: `size + trailer_size` bytes of the caller's buffer, checked above.
    unsafe {
        write_header(msg, bits, size as u32, reply_name, arrived_on, id);
        if complex {
            write_word(msg, HEADER, placed.len() as u32);
            let mut at = HEADER + BODY;
            for (one, arrived) in placed.iter().zip(&arrived) {
                write_descriptor(msg, at, one);
                at += arrived.size();
            }
        }
        core::ptr::copy_nonoverlapping(
            message.bytes.as_ptr().add(payload_at),
            msg.add(HEADER + body),
            payload_len,
        );
        // The trailer, which `msgh_size` does not count and `rcv_size` must,
        // as long as the caller asked for: `mach_msg_mac_trailer_t`'s fields
        // in order, each one there only when the elements reach it.
        write_word(msg, size, TRAILER_FORMAT_0);
        write_word(msg, size + 4, trailer_size as u32);
        if elements >= 1 {
            write_word(msg, size + 8, seqno);
        }
        if elements >= 2 {
            let security = match audit == [0; 8] {
                true => trailer::KERNEL_SECURITY_TOKEN,
                // `msgh_sender` is the effective user and group.
                false => [audit[1], audit[2]],
            };
            write_word(msg, size + 12, security[0]);
            write_word(msg, size + 16, security[1]);
        }
        if elements >= 3 {
            for (i, value) in audit.iter().enumerate() {
                write_word(msg, size + 20 + i * 4, *value);
            }
        }
        if elements >= 4 {
            let context = space::trailer_context(arrived_on);
            write_word(msg, size + 52, context as u32);
            write_word(msg, size + 56, (context >> 32) as u32);
        }
        if elements >= 5 {
            // `msgh_ad`, the filter id, and `msgh_labels.sender`: no message
            // filter or label is ever applied here.
            write_word(msg, size + 60, 0);
            write_word(msg, size + 64, 0);
        }
    }
    match placed_all {
        true => MACH_MSG_SUCCESS,
        // Delivered all the same, with the memory that did not fit empty, as
        // `ipc_kmsg_copyout_body` reports it.
        false => MACH_RCV_BODY_ERROR | MACH_MSG_VM_SPACE,
    }
}

/// # Safety
///
/// `msg` addresses at least `at + 4` writable bytes.
unsafe fn write_word(msg: *mut u8, at: usize, value: u32) {
    // SAFETY: the caller's buffer, whose length was checked before the call.
    // Unaligned because a message is only guaranteed 4-byte aligned and the
    // trailer may land anywhere.
    unsafe { msg.add(at).cast::<u32>().write_unaligned(value) };
}

/// # Safety
///
/// `msg` addresses at least [`HEADER`] writable bytes.
unsafe fn write_header(msg: *mut u8, bits: u32, size: u32, remote: Name, local: Name, id: i32) {
    // SAFETY: the caller's buffer, at least a header long.
    unsafe {
        write_word(msg, 0, bits);
        write_word(msg, 4, size);
        write_word(msg, 8, remote);
        write_word(msg, 12, local);
        write_word(msg, 16, MACH_PORT_NULL);
        write_word(msg, 20, id as u32);
    }
}

/// `mach_msg_return_t mach_msg_send(mach_msg_header_t *msg)`: libsyscall's
/// `mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL,
/// MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)`.
///
/// # Safety
///
/// `msg` is a whole message of the size its header states.
pub unsafe extern "C" fn mach_msg_send(msg: *mut c_void) -> i32 {
    if msg.is_null() {
        return MACH_SEND_INVALID_DATA;
    }
    // SAFETY: the caller's header.
    let size = unsafe { msg.cast::<u8>().add(4).cast::<u32>().read_unaligned() };
    // SAFETY: as above.
    unsafe { mach_msg(msg, SEND_MSG, size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL) }
}

/// `mach_msg_return_t mach_msg_receive(mach_msg_header_t *msg)`: a receive on
/// the header's `msgh_local_port` into a buffer of its `msgh_size`.
///
/// # Safety
///
/// `msg` addresses `msgh_size` writable bytes.
pub unsafe extern "C" fn mach_msg_receive(msg: *mut c_void) -> i32 {
    if msg.is_null() {
        return MACH_RCV_INVALID_NAME;
    }
    // SAFETY: the caller's header.
    let (size, local) = unsafe {
        let bytes = msg.cast::<u8>();
        (
            bytes.add(4).cast::<u32>().read_unaligned(),
            bytes.add(12).cast::<u32>().read_unaligned(),
        )
    };
    // SAFETY: as above.
    unsafe { mach_msg(msg, RCV_MSG, 0, size, local, 0, MACH_PORT_NULL) }
}

/// `mach_msg_return_t mach_msg(mach_msg_header_t *msg, mach_msg_option_t option,
/// mach_msg_size_t send_size, mach_msg_size_t rcv_size, mach_port_name_t
/// rcv_name, mach_msg_timeout_t timeout, mach_port_name_t notify)`
///
/// A single call can do both halves, in that order, which is how every MIG
/// routine with a reply is implemented.
///
/// # Safety
///
/// `msg` addresses `send_size` readable bytes when `MACH_SEND_MSG` is set and
/// `rcv_size` writable ones when `MACH_RCV_MSG` is.
pub unsafe extern "C" fn mach_msg(
    msg: *mut c_void,
    option: i32,
    send_size: u32,
    rcv_size: u32,
    rcv_name: Name,
    timeout: u32,
    _notify: Name,
) -> i32 {
    if msg.is_null() {
        return MACH_SEND_INVALID_DATA;
    }
    let msg = msg.cast::<u8>();
    if option & SEND_MSG != 0 {
        // SAFETY: the caller's message, of the size it passed.
        let sent = unsafe { send(msg, send_size) };
        if sent != MACH_MSG_SUCCESS {
            return match option & SEND_TIMEOUT != 0 && sent == MACH_SEND_NO_BUFFER {
                true => MACH_SEND_TIMED_OUT,
                false => sent,
            };
        }
    }
    if option & RCV_MSG != 0 {
        let timeout_ms = match option & RCV_TIMEOUT != 0 {
            true => timeout.min(i32::MAX as u32) as i32,
            false => -1,
        };
        // SAFETY: the caller's buffer, of the size it passed.
        return unsafe { receive(msg, rcv_size, rcv_name, timeout_ms, option) };
    }
    MACH_MSG_SUCCESS
}

/// `mach_msg_return_t mach_msg_overwrite(...)` - `mach_msg` with a separate
/// buffer for the reply.
///
/// The overwrite buffer is honoured only when the caller supplies one; a null
/// `rcv_msg` means "reply into `msg`", which is plain [`mach_msg`].
///
/// # Safety
///
/// As [`mach_msg`], with `rcv_msg` addressing `rcv_limit` writable bytes when
/// it is not null.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mach_msg_overwrite(
    msg: *mut c_void,
    option: i32,
    send_size: u32,
    rcv_size: u32,
    rcv_name: Name,
    timeout: u32,
    notify: Name,
    rcv_msg: *mut c_void,
    rcv_limit: u32,
) -> i32 {
    if rcv_msg.is_null() {
        // SAFETY: the caller's, as documented.
        return unsafe { mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify) };
    }
    if option & SEND_MSG != 0 {
        // SAFETY: the caller's message, of the size it passed.
        let sent = unsafe { send(msg.cast(), send_size) };
        if sent != MACH_MSG_SUCCESS {
            return sent;
        }
    }
    if option & RCV_MSG != 0 {
        let timeout_ms = match option & RCV_TIMEOUT != 0 {
            true => timeout.min(i32::MAX as u32) as i32,
            false => -1,
        };
        // SAFETY: the caller's reply buffer, of the size it passed.
        return unsafe {
            receive(
                rcv_msg.cast(),
                rcv_limit.min(rcv_size),
                rcv_name,
                timeout_ms,
                option,
            )
        };
    }
    MACH_MSG_SUCCESS
}

/// `mach_msg_destroy_port`: let go of a right a message holds under
/// `disposition`, as libsyscall does.
fn destroy_port(name: Name, disposition: u32) {
    if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
        return;
    }
    match disposition {
        MOVE_SEND | MOVE_SEND_ONCE => {
            space::mach_port_deallocate(space::TASK_SELF, name);
        }
        // A receive right that arrived is destroyed, not deallocated: it is
        // the port itself and nobody else in this task holds it.
        MOVE_RECEIVE => {
            space::destroy(name);
        }
        // Made and destroyed at once, which leaves nothing but the notice a
        // send-once right destroyed unused gives its port.
        MAKE_SEND_ONCE => {
            if let Some(address) = space::address_of(name) {
                deliver_send_once(address);
            }
        }
        // `MAKE_SEND` makes a right and destroys it, and `COPY_SEND` took
        // nothing: neither leaves anything to release.
        _ => {}
    }
}

/// `void mach_msg_destroy(mach_msg_header_t *)`
///
/// Releases every right and region in a message the caller has decided not to
/// act on. The rights are already in this task's space by the time a receiver
/// sees them, so skipping this leaks a name per message - which is what turns a
/// server loop that discards unknown messages into one that runs out of names.
///
/// # Safety
///
/// `msg` addresses a received `mach_msg_header_t` and the body it describes.
pub unsafe extern "C" fn mach_msg_destroy(msg: *mut c_void) {
    if msg.is_null() {
        return;
    }
    let msg = msg.cast::<u8>();
    // SAFETY: a received message, whose header states its own size.
    let (bits, size) = unsafe {
        (
            msg.cast::<u32>().read_unaligned(),
            msg.add(4).cast::<u32>().read_unaligned() as usize,
        )
    };
    // SAFETY: as above, and the size is the message's own.
    let bytes = unsafe { read_message(msg, size.clamp(HEADER, wire::MAX_MESSAGE)) };

    // `msgh_local_port` holds no right: the receive consumed the destination.
    destroy_port(word(&bytes, 8), bits & BITS_PORTS_MASK);
    if bits & BITS_COMPLEX == 0 || bytes.len() < HEADER + BODY {
        return;
    }
    let count = word(&bytes, HEADER) as usize;
    let mut at = HEADER + BODY;
    for _ in 0..count {
        if at + DESCRIPTOR > bytes.len() {
            return;
        }
        let disposition = bytes[at + DESCRIPTOR_DISPOSITION_AT] as u32;
        let kind = bytes[at + DESCRIPTOR_TYPE_AT];
        if kind != DESCRIPTOR_PORT && at + OOL_DESCRIPTOR > bytes.len() {
            return;
        }
        match kind {
            DESCRIPTOR_PORT => {
                destroy_port(word(&bytes, at), disposition);
                at += DESCRIPTOR;
            }
            DESCRIPTOR_OOL => {
                let length = u64::from(word(&bytes, at + 12));
                if bytes[at + 8] != 0 && length != 0 {
                    // SAFETY: memory the message handed this task.
                    unsafe { super::vm::vm_deallocate(space::TASK_SELF, long(&bytes, at), length) };
                }
                at += OOL_DESCRIPTOR;
            }
            // Volatile memory is the sender's to keep, and so is skipped.
            DESCRIPTOR_OOL_VOLATILE => at += OOL_DESCRIPTOR,
            DESCRIPTOR_OOL_PORTS => {
                let address = long(&bytes, at);
                let members = word(&bytes, at + 12) as usize;
                if address != 0 {
                    for i in 0..members {
                        // SAFETY: the message's array of `members` names.
                        let name = unsafe { (address as *const Name).add(i).read_unaligned() };
                        destroy_port(name, disposition);
                    }
                    if bytes[at + 8] != 0 && members != 0 {
                        // SAFETY: the array the message handed this task.
                        unsafe {
                            super::vm::vm_deallocate(
                                space::TASK_SELF,
                                address,
                                (members * 4) as u64,
                            )
                        };
                    }
                }
                at += OOL_DESCRIPTOR;
            }
            // Nothing this module delivers; stop rather than guess its size.
            _ => return,
        }
    }
}

/// The reply port MIG keeps per thread.
///
/// A MIG routine sends its request with `msgh_local_port` set to this and then
/// receives the reply on it, so it has to be a real receive right and it has to
/// be the *same* one across the two halves of one call.
mod reply {
    use super::*;

    thread_local! {
        static PORT: std::cell::Cell<Name> = const { std::cell::Cell::new(MACH_PORT_NULL) };
    }

    pub extern "C" fn mig_get_reply_port() -> Name {
        PORT.with(|port| {
            if port.get() == MACH_PORT_NULL {
                let mut fresh = MACH_PORT_NULL;
                // SAFETY: a live local for the out-parameter.
                unsafe {
                    super::super::space::mach_port_allocate(
                        space::TASK_SELF,
                        space::RIGHT_RECEIVE,
                        &mut fresh,
                    )
                };
                port.set(fresh);
            }
            port.get()
        })
    }

    /// Hand a reply port back for reuse. A no-op: it was never taken away.
    pub extern "C" fn mig_put_reply_port(_name: Name) {}

    /// Throw the thread's reply port away, which a MIG routine does after a
    /// failed call so the next one is not answered by a stale reply.
    pub extern "C" fn mig_dealloc_reply_port(_name: Name) {
        PORT.with(|port| {
            let held = port.replace(MACH_PORT_NULL);
            if held != MACH_PORT_NULL {
                space::destroy(held);
            }
        });
    }
}

pub use reply::{mig_dealloc_reply_port, mig_get_reply_port, mig_put_reply_port};

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `mach_msg_header_t` plus `extra` bytes of payload.
    fn message(bits: u32, remote: Name, local: Name, id: i32, extra: &[u8]) -> Vec<u8> {
        let size = HEADER + extra.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&bits.to_le_bytes());
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&remote.to_le_bytes());
        bytes.extend_from_slice(&local.to_le_bytes());
        bytes.extend_from_slice(&MACH_PORT_NULL.to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(extra);
        bytes
    }

    fn allocate_receive() -> Name {
        let mut name = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe {
            super::super::space::mach_port_allocate(
                space::TASK_SELF,
                space::RIGHT_RECEIVE,
                &mut name,
            )
        };
        name
    }

    #[test]
    fn a_message_sent_to_a_port_comes_back_with_its_id_and_payload() {
        let port = allocate_receive();
        let mut sent = message(0, port, MACH_PORT_NULL, 0x1234, b"eight!!\0");
        // SAFETY: `sent` is a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);

        let mut buf = vec![0u8; 256];
        // SAFETY: 256 writable bytes for the reply.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                port,
                1000,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        assert_eq!(word(&buf, 20) as i32, 0x1234, "msgh_id");
        assert_eq!(
            word(&buf, 4) as usize,
            HEADER + 8,
            "msgh_size excludes the trailer"
        );
        assert_eq!(
            word(&buf, 12),
            port,
            "msgh_local_port is the port it arrived on"
        );
        assert_eq!(&buf[HEADER..HEADER + 8], b"eight!!\0");
        // The trailer the kernel appends, which `msgh_size` does not count.
        assert_eq!(word(&buf, HEADER + 8 + 4) as usize, TRAILER);

        space::destroy(port);
    }

    #[test]
    fn a_receive_with_no_message_times_out_rather_than_waiting() {
        let port = allocate_receive();
        let mut buf = vec![0u8; 64];
        // SAFETY: 64 writable bytes.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                port,
                20,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_RCV_TIMED_OUT);
        space::destroy(port);
    }

    /// The reply port is how a MIG routine gets an answer, so the send right
    /// the sender put in `msgh_local_port` has to arrive as a usable name.
    #[test]
    fn a_reply_port_arrives_as_a_send_right_that_can_be_answered() {
        let service = allocate_receive();
        let reply = allocate_receive();
        let bits = MAKE_SEND_ONCE << BITS_LOCAL_SHIFT;
        let mut sent = message(bits, service, reply, 99, &[]);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);

        let mut buf = vec![0u8; 256];
        // SAFETY: 256 writable bytes.
        unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                service,
                1000,
                MACH_PORT_NULL,
            )
        };
        let answer_to = word(&buf, 8);
        assert_ne!(answer_to, MACH_PORT_NULL);
        assert_eq!(word(&buf, 0) & BITS_PORTS_MASK, MOVE_SEND_ONCE);
        assert_eq!(space::address_of(answer_to), space::address_of(reply));

        // And the answer reaches the port that asked for it.
        let mut back = message(0, answer_to, MACH_PORT_NULL, 100, &[]);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                back.as_mut_ptr().cast(),
                SEND_MSG,
                back.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                reply,
                1000,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        assert_eq!(word(&buf, 20) as i32, 100);

        space::destroy(service);
        space::destroy(reply);
    }

    /// A right inside a message: the shape of Crashpad's handshake, minus the
    /// process boundary.
    #[test]
    fn a_port_descriptor_carries_a_right_that_the_receiver_can_use() {
        let service = allocate_receive();
        let carried = allocate_receive();
        let address = space::address_of(carried).unwrap();

        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&1u32.to_le_bytes()); // one descriptor
        descriptor.extend_from_slice(&carried.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&[0, 0, MOVE_RECEIVE as u8, DESCRIPTOR_PORT]);
        descriptor.extend_from_slice(&0xdead_beefu32.to_le_bytes()); // the payload

        let mut sent = message(BITS_COMPLEX, service, MACH_PORT_NULL, 7, &descriptor);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        assert!(
            space::receiver(carried).is_none(),
            "a moved receive right leaves the sender's space"
        );

        let mut buf = vec![0u8; 256];
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                service,
                1000,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        assert_ne!(word(&buf, 0) & BITS_COMPLEX, 0, "still complex");
        assert_eq!(word(&buf, HEADER), 1, "one descriptor");
        let arrived = word(&buf, HEADER + BODY);
        assert_eq!(
            buf[HEADER + BODY + DESCRIPTOR_DISPOSITION_AT] as u32,
            MOVE_RECEIVE
        );
        assert_eq!(space::address_of(arrived), Some(address));
        assert!(
            space::receiver(arrived).is_some(),
            "and it is a receive right"
        );
        assert_eq!(
            word(&buf, HEADER + BODY + DESCRIPTOR),
            0xdead_beef,
            "the payload follows the descriptors"
        );

        space::destroy(service);
        space::destroy(arrived);
    }

    /// Out-of-line memory cannot cross, and is refused by name rather than sent
    /// with the sender's pointer in it.
    fn send_bytes(sent: &mut [u8]) -> i32 {
        // SAFETY: a whole message of the size in its header.
        unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        }
    }

    /// A `mach_msg_ool_descriptor64_t`.
    fn ool(address: u64, length: u32, deallocate: bool, copy: u8, kind: u8) -> Vec<u8> {
        let mut descriptor = address.to_le_bytes().to_vec();
        descriptor.extend_from_slice(&[deallocate as u8, copy, 0, kind]);
        descriptor.extend_from_slice(&length.to_le_bytes());
        descriptor
    }

    /// A `mach_msg_port_descriptor_t`.
    fn port_descriptor(name: Name, disposition: u32) -> Vec<u8> {
        let mut descriptor = name.to_le_bytes().to_vec();
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&[0, 0, disposition as u8, DESCRIPTOR_PORT]);
        descriptor
    }

    /// A message body: the descriptor count, the descriptors, the payload.
    fn complex(descriptors: &[Vec<u8>], payload: &[u8]) -> Vec<u8> {
        let mut body = (descriptors.len() as u32).to_le_bytes().to_vec();
        for descriptor in descriptors {
            body.extend_from_slice(descriptor);
        }
        body.extend_from_slice(payload);
        body
    }

    /// Whether any of `[address, address + len)` is mapped.
    fn mapped(address: u64, len: usize) -> bool {
        // SAFETY: `msync` only asks; an unmapped range is `ENOMEM`.
        unsafe { libc::msync(address as *mut c_void, len, libc::MS_ASYNC) == 0 }
    }

    fn pattern(i: usize) -> u8 {
        (i * 7 % 251) as u8
    }

    /// Mojo's `ChannelMac` sends a message of a page or more this way.
    #[test]
    fn an_out_of_line_region_arrives_as_new_memory_holding_its_bytes() {
        let port = allocate_receive();
        let page = super::super::info::page_size() as usize;
        let length = 3 * page + 5;
        let mut virtual_copy: Vec<u8> = (0..length).map(pattern).collect();
        let physical_copy = b"physical".to_vec();
        let body = complex(
            &[
                ool(
                    virtual_copy.as_ptr() as u64,
                    length as u32,
                    false,
                    VIRTUAL_COPY,
                    DESCRIPTOR_OOL,
                ),
                ool(
                    physical_copy.as_ptr() as u64,
                    8,
                    false,
                    PHYSICAL_COPY,
                    DESCRIPTOR_OOL,
                ),
                ool(0, 0, false, VIRTUAL_COPY, DESCRIPTOR_OOL),
            ],
            b"tail",
        );
        let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 7, &body);
        assert_eq!(send_bytes(&mut sent), MACH_MSG_SUCCESS);
        // What arrives is what was sent, whatever the sender does after.
        virtual_copy.fill(0);

        let mut buf = vec![0u8; 256];
        assert_eq!(receive_with(port, 0, &mut buf), MACH_MSG_SUCCESS);
        assert_ne!(word(&buf, 0) & BITS_COMPLEX, 0);
        assert_eq!(word(&buf, HEADER), 3);
        let first = HEADER + BODY;
        let address = long(&buf, first);
        assert_eq!(
            buf[first + 8],
            1,
            "a virtual copy is the receiver's to free"
        );
        assert_eq!(buf[first + 9], VIRTUAL_COPY);
        assert_eq!(buf[first + DESCRIPTOR_TYPE_AT], DESCRIPTOR_OOL);
        assert_eq!(word(&buf, first + 12) as usize, length);
        assert_eq!(address as usize % page, 0, "placed on a page boundary");
        // SAFETY: the region the receive mapped, `length` bytes long.
        let arrived = unsafe { std::slice::from_raw_parts(address as *const u8, length) };
        assert!(arrived.iter().enumerate().all(|(i, b)| *b == pattern(i)));

        let second = first + OOL_DESCRIPTOR;
        assert_eq!(buf[second + 8], 0, "a physical copy is not");
        assert_eq!(buf[second + 9], PHYSICAL_COPY);
        let kept = long(&buf, second);
        // SAFETY: the second region, eight bytes long.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(kept as *const u8, 8) },
            b"physical"
        );

        let third = second + OOL_DESCRIPTOR;
        assert_eq!(
            (long(&buf, third), word(&buf, third + 12)),
            (0, 0),
            "empty is empty"
        );
        assert_eq!(
            &buf[third + OOL_DESCRIPTOR..third + OOL_DESCRIPTOR + 4],
            b"tail"
        );
        assert_eq!(word(&buf, 4) as usize, third + OOL_DESCRIPTOR + 4);

        // SAFETY: the received message in `buf`.
        unsafe { mach_msg_destroy(buf.as_mut_ptr().cast()) };
        assert!(
            !mapped(address, length),
            "destroying the message frees the copy"
        );
        assert!(mapped(kept, 8), "and leaves what was not its to free");
        // SAFETY: the second region, which the receiver owns.
        unsafe { super::super::vm::vm_deallocate(space::TASK_SELF, kept, 8) };
        space::destroy(port);
    }

    #[test]
    fn a_region_that_cannot_be_read_is_invalid_memory() {
        let port = allocate_receive();
        let page = super::super::info::page_size() as usize;
        // SAFETY: a new inaccessible mapping, unmapped below.
        let guard = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(guard, libc::MAP_FAILED);
        for address in [0, guard as u64] {
            let body = complex(&[ool(address, 8, false, VIRTUAL_COPY, DESCRIPTOR_OOL)], &[]);
            let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 1, &body);
            assert_eq!(send_bytes(&mut sent), MACH_SEND_INVALID_MEMORY);
        }
        // `MACH_MSG_ALLOCATE` is for a receive's own buffer, not a send.
        let bytes = [0u8; 8];
        let body = complex(
            &[ool(bytes.as_ptr() as u64, 8, false, 2, DESCRIPTOR_OOL)],
            &[],
        );
        let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 1, &body);
        assert_eq!(send_bytes(&mut sent), MACH_SEND_INVALID_TYPE);
        assert!(take(port, 0).is_none(), "nothing was queued");
        // SAFETY: the mapping made above.
        unsafe { libc::munmap(guard, page) };
        space::destroy(port);
    }

    #[test]
    fn a_region_sent_with_deallocate_leaves_the_sender() {
        let port = allocate_receive();
        let page = super::super::info::page_size();
        let mut region = 0u64;
        // SAFETY: a live local for the out-parameter.
        let kr = unsafe {
            super::super::vm::vm_allocate(
                space::TASK_SELF,
                &mut region,
                page,
                super::super::vm::VM_FLAGS_ANYWHERE,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        // SAFETY: the page just allocated.
        unsafe { core::ptr::write_bytes(region as *mut u8, 0x5a, page as usize) };
        let body = complex(
            &[ool(region, page as u32, true, VIRTUAL_COPY, DESCRIPTOR_OOL)],
            &[],
        );
        let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 1, &body);
        assert_eq!(send_bytes(&mut sent), MACH_MSG_SUCCESS);
        assert!(!mapped(region, page as usize), "the sender gave it up");

        let mut buf = vec![0u8; 256];
        assert_eq!(receive_with(port, 0, &mut buf), MACH_MSG_SUCCESS);
        let address = long(&buf, HEADER + BODY);
        // SAFETY: the region the receive mapped, a page long.
        let arrived = unsafe { std::slice::from_raw_parts(address as *const u8, page as usize) };
        assert!(arrived.iter().all(|b| *b == 0x5a));
        // SAFETY: the received message in `buf`.
        unsafe { mach_msg_destroy(buf.as_mut_ptr().cast()) };
        space::destroy(port);
    }

    #[test]
    fn an_out_of_line_port_array_carries_a_right_per_member() {
        let port = allocate_receive();
        let a = allocate_receive();
        let b = allocate_receive();
        let names = [a, MACH_PORT_NULL, b];
        let mut descriptor = (names.as_ptr() as u64).to_le_bytes().to_vec();
        descriptor.extend_from_slice(&[0, VIRTUAL_COPY, MAKE_SEND as u8, DESCRIPTOR_OOL_PORTS]);
        descriptor.extend_from_slice(&3u32.to_le_bytes());
        let body = complex(&[descriptor], b"ports");
        let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 3, &body);
        assert_eq!(send_bytes(&mut sent), MACH_MSG_SUCCESS);

        let mut buf = vec![0u8; 256];
        assert_eq!(receive_with(port, 0, &mut buf), MACH_MSG_SUCCESS);
        let at = HEADER + BODY;
        assert_eq!(buf[at + 8], 1, "the array is the receiver's to free");
        assert_eq!(buf[at + DESCRIPTOR_DISPOSITION_AT] as u32, MOVE_SEND);
        assert_eq!(buf[at + DESCRIPTOR_TYPE_AT], DESCRIPTOR_OOL_PORTS);
        assert_eq!(word(&buf, at + 12), 3);
        assert_eq!(&buf[at + OOL_DESCRIPTOR..at + OOL_DESCRIPTOR + 5], b"ports");
        let array = long(&buf, at);
        // SAFETY: the array the receive allocated, three names long.
        let arrived = unsafe { std::slice::from_raw_parts(array as *const Name, 3) };
        // A send right to a port this task receives on is named as the port.
        assert_eq!(arrived, &names);
        let refs = |name| {
            let mut refs = 0;
            // SAFETY: a live local for the out-parameter.
            unsafe {
                space::mach_port_get_refs(space::TASK_SELF, name, space::RIGHT_SEND, &mut refs)
            };
            refs
        };
        assert_eq!((refs(a), refs(b)), (1, 1));

        // SAFETY: the received message in `buf`.
        unsafe { mach_msg_destroy(buf.as_mut_ptr().cast()) };
        assert_eq!(
            (refs(a), refs(b)),
            (0, 0),
            "destroying it releases each right"
        );
        assert!(!mapped(array, 12), "and frees the array");
        for name in [port, a, b] {
            space::destroy(name);
        }
    }

    #[test]
    fn a_failed_send_leaves_a_moved_receive_right_under_its_name() {
        let port = allocate_receive();
        let moved = allocate_receive();
        assert_eq!(
            space::mach_port_insert_right(space::TASK_SELF, moved, moved, MAKE_SEND),
            KERN_SUCCESS
        );
        // A guarded port descriptor, which this module refuses, after it.
        let mut guarded = vec![0u8; OOL_DESCRIPTOR];
        guarded[DESCRIPTOR_DISPOSITION_AT] = MOVE_RECEIVE as u8;
        guarded[DESCRIPTOR_TYPE_AT] = 4;
        let body = complex(&[port_descriptor(moved, MOVE_RECEIVE), guarded], &[]);
        let mut sent = message(BITS_COMPLEX | COPY_SEND, port, MACH_PORT_NULL, 1, &body);
        assert_eq!(send_bytes(&mut sent), MACH_SEND_INVALID_TYPE);

        let mut bits = 0;
        // SAFETY: a live local for the out-parameter.
        unsafe { space::mach_port_type(space::TASK_SELF, moved, &mut bits) };
        let both = space::type_of(space::RIGHT_RECEIVE) | space::type_of(space::RIGHT_SEND);
        assert_eq!(bits & both, both, "the receive right and its send right");
        assert_eq!(
            send_plain(moved, MACH_PORT_NULL, COPY_SEND, 9),
            MACH_MSG_SUCCESS
        );
        assert!(take(moved, 1000).is_some(), "and it still receives");
        space::destroy(moved);
        space::destroy(port);
    }

    #[test]
    fn a_fileport_crosses_in_a_message_and_opens_the_same_file() {
        let mut ends = [0i32; 2];
        // SAFETY: a writable two-element descriptor array.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let mut fileport = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        assert_eq!(
            unsafe { super::super::fileport::fileport_makeport(ends[1], &mut fileport) },
            0
        );
        // SAFETY: this test's own descriptor, which the fileport duplicated.
        unsafe { libc::close(ends[1]) };

        let service = allocate_receive();
        let arrived = carry(service, fileport, MOVE_SEND);
        assert_eq!(
            super::super::fileport::fileport_makefd(fileport),
            -1,
            "the right moved"
        );
        let fd = super::super::fileport::fileport_makefd(arrived);
        assert!(fd >= 0);
        // SAFETY: one byte from a live local, then one into one.
        unsafe {
            assert_eq!(libc::write(fd, b"y".as_ptr().cast(), 1), 1);
            let mut byte = 0u8;
            assert_eq!(libc::read(ends[0], (&raw mut byte).cast(), 1), 1);
            assert_eq!(byte, b'y');
            libc::close(fd);
            libc::close(ends[0]);
        }
        space::mach_port_deallocate(space::TASK_SELF, arrived);
        space::destroy(service);
    }

    #[test]
    fn a_send_to_a_name_that_is_not_a_right_fails_rather_than_going_nowhere() {
        let mut sent = message(0, 0x7fff_0000, MACH_PORT_NULL, 1, &[]);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_SEND_INVALID_DEST);
    }

    /// Too small a buffer destroys the message unless the caller said it would
    /// come back, in which case the message waits for the bigger buffer.
    #[test]
    fn a_message_too_large_for_the_buffer_is_kept_only_when_the_caller_asked() {
        let port = allocate_receive();
        let payload = [0u8; 64];
        let mut sent = message(0, port, MACH_PORT_NULL, 5, &payload);
        let send_once = |bytes: &mut Vec<u8>| {
            // SAFETY: a whole message of the size in its header.
            unsafe {
                mach_msg(
                    bytes.as_mut_ptr().cast(),
                    SEND_MSG,
                    bytes.len() as u32,
                    0,
                    MACH_PORT_NULL,
                    0,
                    MACH_PORT_NULL,
                )
            }
        };
        assert_eq!(send_once(&mut sent), MACH_MSG_SUCCESS);

        let mut small = vec![0u8; HEADER + 8];
        // SAFETY: `small.len()` writable bytes.
        let rc = unsafe {
            mach_msg(
                small.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT | RCV_LARGE,
                0,
                small.len() as u32,
                port,
                100,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_RCV_TOO_LARGE);
        assert_eq!(
            word(&small, 4) as usize,
            HEADER + payload.len(),
            "the size the caller needs"
        );

        let mut big = vec![0u8; 256];
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                big.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                big.len() as u32,
                port,
                100,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS, "the held message was still there");
        assert_eq!(word(&big, 20) as i32, 5);

        // Without `MACH_RCV_LARGE` the message goes away instead.
        assert_eq!(send_once(&mut sent), MACH_MSG_SUCCESS);
        // SAFETY: `small.len()` writable bytes.
        let rc = unsafe {
            mach_msg(
                small.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                small.len() as u32,
                port,
                100,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_RCV_TOO_LARGE);
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                big.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                big.len() as u32,
                port,
                50,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_RCV_TIMED_OUT, "it was destroyed, not queued");

        space::destroy(port);
    }

    /// A port set has no queue of its own: a receive on one answers with a
    /// message from a member, and says which member it came from.
    #[test]
    fn a_receive_on_a_port_set_names_the_member_it_arrived_on() {
        let mut set = MACH_PORT_NULL;
        // SAFETY: a live local for the out-parameter.
        unsafe {
            super::super::space::mach_port_allocate(
                space::TASK_SELF,
                space::RIGHT_PORT_SET,
                &mut set,
            )
        };
        let first = allocate_receive();
        let second = allocate_receive();
        super::super::space::mach_port_insert_member(space::TASK_SELF, first, set);
        super::super::space::mach_port_insert_member(space::TASK_SELF, second, set);

        let mut sent = message(0, second, MACH_PORT_NULL, 42, &[]);
        // SAFETY: a whole message of the size in its header.
        unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };

        let mut buf = vec![0u8; 256];
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                set,
                1000,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        assert_eq!(word(&buf, 20) as i32, 42);
        assert_eq!(word(&buf, 12), second, "the member, not the set");

        space::destroy(set);
        space::destroy(first);
        space::destroy(second);
    }

    #[test]
    fn a_migs_reply_port_is_one_per_thread_and_survives_until_it_is_thrown_away() {
        let first = mig_get_reply_port();
        assert_ne!(first, MACH_PORT_NULL);
        assert_eq!(mig_get_reply_port(), first);
        mig_dealloc_reply_port(first);
        let second = mig_get_reply_port();
        assert_ne!(second, first);

        let other = std::thread::spawn(|| mig_get_reply_port()).join().unwrap();
        assert_ne!(other, second, "a reply port belongs to one thread");
        mig_dealloc_reply_port(second);
    }

    /// Receive one message from `port` into a fresh buffer, or `None` on timeout.
    fn take(port: Name, timeout_ms: u32) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 256];
        // SAFETY: 256 writable bytes.
        let rc = unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                buf.len() as u32,
                port,
                timeout_ms,
                MACH_PORT_NULL,
            )
        };
        (rc == MACH_MSG_SUCCESS).then_some(buf)
    }

    fn request_no_senders(port: Name, notify: Name) {
        // SAFETY: a null `previous` is allowed.
        let rc = unsafe {
            space::mach_port_request_notification(
                space::TASK_SELF,
                port,
                space::NOTIFY_NO_SENDERS,
                0,
                notify,
                MAKE_SEND_ONCE,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    }

    #[test]
    fn the_last_send_right_going_away_is_reported_to_the_notify_port() {
        let port = allocate_receive();
        let notify = allocate_receive();
        let first = space::insert_send(space::address_of(port).unwrap());
        let second = space::insert_send(space::address_of(port).unwrap());
        assert_eq!(first, second, "one name for one port");
        request_no_senders(port, notify);

        assert!(take(notify, 200).is_none(), "a sender is still held");
        space::mach_port_deallocate(space::TASK_SELF, first);
        assert!(take(notify, 200).is_none(), "one of two references remains");
        space::mach_port_deallocate(space::TASK_SELF, first);

        let told = take(notify, 2000).expect("a no-senders notification");
        assert_eq!(word(&told, 20) as i32, 0o106, "MACH_NOTIFY_NO_SENDERS");
        assert_eq!(
            word(&told, 4) as usize,
            HEADER + 8 + 4,
            "a notification's size"
        );
        assert_eq!(word(&told, 12), notify, "it arrived on the notify port");
        assert_eq!(word(&told, 8), MACH_PORT_NULL, "and has nobody to reply to");
        assert_eq!(word(&told, HEADER + 8), 1, "one right was ever made");

        space::destroy(port);
        space::destroy(notify);
    }

    /// A right inside a queued message is a sender, which is what keeps a port
    /// that was just handed to a client from being declared abandoned before the
    /// client has looked at the message.
    #[test]
    fn a_send_right_in_flight_still_counts_as_a_sender() {
        let port = allocate_receive();
        let notify = allocate_receive();
        let mailbox = allocate_receive();
        let held = space::insert_send(space::address_of(port).unwrap());
        assert_eq!(
            held, port,
            "the send right is under the receive right's name"
        );
        request_no_senders(port, notify);

        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&1u32.to_le_bytes());
        descriptor.extend_from_slice(&held.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&[0, 0, MOVE_SEND as u8, DESCRIPTOR_PORT]);
        let mut sent = message(BITS_COMPLEX, mailbox, MACH_PORT_NULL, 9, &descriptor);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        let mut bits = 0;
        // SAFETY: a live local for the out-parameter.
        unsafe { space::mach_port_type(space::TASK_SELF, held, &mut bits) };
        assert_eq!(
            bits,
            space::type_of(space::RIGHT_RECEIVE),
            "the sender gave its send right away"
        );
        assert!(
            take(notify, 300).is_none(),
            "the right is in the mailbox, not gone"
        );

        let arrived = take(mailbox, 1000).expect("the message");
        let received = word(&arrived, HEADER + BODY);
        assert_eq!(received, port, "it arrives under the port's one name");
        assert!(take(notify, 300).is_none(), "now the receiver holds it");

        space::mach_port_deallocate(space::TASK_SELF, received);
        assert!(take(notify, 2000).is_some(), "and now nobody does");

        space::destroy(port);
        space::destroy(notify);
        space::destroy(mailbox);
    }

    /// The case this exists for: the holder of the right is another process, and
    /// it exiting is the only thing that releases it.
    #[test]
    fn a_holder_process_that_exits_is_reported_as_no_senders() {
        let port = allocate_receive();
        let notify = allocate_receive();
        let address = space::address_of(port).unwrap();
        request_no_senders(port, notify);

        let claim = wire::claim(address).expect("a claim");
        // SAFETY: the child calls only async-signal-safe functions and never
        // returns into the test harness.
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::usleep(300_000);
                libc::_exit(0);
            }
        }
        assert!(child > 0, "fork");
        // The child's copy is the only one left.
        drop(claim);
        assert!(take(notify, 100).is_none(), "the child still holds it");
        let mut status = 0;
        // SAFETY: the child just forked, and a live local for the status.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(take(notify, 2000).is_some(), "the holder is gone");

        space::destroy(port);
        space::destroy(notify);
    }

    /// How a crash reporter hands over its exception port: the client creates it,
    /// keeps a send right, and moves the receive right to its handler - which
    /// then asks to be told when the client's right is gone.
    #[test]
    fn a_moved_receive_right_keeps_the_senders_it_already_had() {
        let port = allocate_receive();
        let notify = allocate_receive();
        let mailbox = allocate_receive();
        let address = space::address_of(port).unwrap();
        let held = space::insert_send(address);

        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&1u32.to_le_bytes());
        descriptor.extend_from_slice(&port.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&[0, 0, MOVE_RECEIVE as u8, DESCRIPTOR_PORT]);
        let mut sent = message(BITS_COMPLEX, mailbox, MACH_PORT_NULL, 11, &descriptor);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        let arrived = take(mailbox, 1000).expect("the message");
        let moved = word(&arrived, HEADER + BODY);
        assert!(space::receiver(moved).is_some(), "a receive right again");

        request_no_senders(moved, notify);
        assert!(
            take(notify, 300).is_none(),
            "the sender's right is still held"
        );
        space::mach_port_deallocate(space::TASK_SELF, held);
        assert!(take(notify, 2000).is_some(), "and then it is not");

        space::destroy(moved);
        space::destroy(notify);
        space::destroy(mailbox);
    }

    /// A crash reporter registers its handler's port and lets go of its own
    /// right at once, because the kernel keeps one.
    #[test]
    fn a_registered_exception_port_is_a_sender_until_it_is_replaced() {
        const MASK: u32 = 1 << 9;
        let port = allocate_receive();
        let notify = allocate_receive();
        let held = space::insert_send(space::address_of(port).unwrap());
        super::super::task::task_set_exception_ports(space::TASK_SELF, MASK, held, 1, 0);
        request_no_senders(port, notify);

        space::mach_port_deallocate(space::TASK_SELF, held);
        assert!(
            take(notify, 300).is_none(),
            "the registration holds the port"
        );
        super::super::task::task_set_exception_ports(space::TASK_SELF, MASK, MACH_PORT_NULL, 0, 0);
        assert!(take(notify, 2000).is_some(), "until it is cleared");

        space::destroy(port);
        space::destroy(notify);
    }

    /// `MACH_RCV_TRAILER_TYPE(0) | MACH_RCV_TRAILER_ELEMENTS(AUDIT)`.
    const RCV_AUDIT: i32 = 3 << 24;

    fn send_plain(remote: Name, local: Name, bits: u32, id: i32) -> i32 {
        let mut sent = message(bits, remote, local, id, &[]);
        // SAFETY: `sent` is a whole message of the size in its header.
        unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        }
    }

    fn receive_with(port: Name, option: i32, buf: &mut [u8]) -> i32 {
        // SAFETY: `buf` is writable for its whole length.
        unsafe {
            mach_msg(
                buf.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT | option,
                0,
                buf.len() as u32,
                port,
                1000,
                MACH_PORT_NULL,
            )
        }
    }

    /// The trailer a server reads its client's pid from, as Chromium's
    /// `MachPortRendezvousServer` does.
    #[test]
    fn an_audit_trailer_names_the_sending_process() {
        let port = allocate_receive();
        assert_eq!(
            send_plain(port, MACH_PORT_NULL, COPY_SEND, 7),
            MACH_MSG_SUCCESS
        );
        let mut buf = vec![0xffu8; 256];
        assert_eq!(receive_with(port, RCV_AUDIT, &mut buf), MACH_MSG_SUCCESS);
        let size = word(&buf, 4) as usize;
        assert_eq!(size, HEADER);
        assert_eq!(word(&buf, size), TRAILER_FORMAT_0, "msgh_trailer_type");
        assert_eq!(word(&buf, size + 4), 52, "sizeof(mach_msg_audit_trailer_t)");
        let token = super::super::info::audit_token(starnix::process::me());
        assert_eq!(
            word(&buf, size + 12),
            token.val[1],
            "msgh_sender is the euid"
        );
        assert_eq!(word(&buf, size + 16), token.val[2], "and the egid");
        let audit: Vec<u32> = (0..8).map(|i| word(&buf, size + 20 + i * 4)).collect();
        assert_eq!(audit, token.val);
        assert_eq!(audit[5], std::process::id(), "the pid is the fifth word");

        // Each message dequeued takes the port's next sequence number.
        send_plain(port, MACH_PORT_NULL, COPY_SEND, 8);
        let mut second = vec![0u8; 256];
        assert_eq!(receive_with(port, RCV_AUDIT, &mut second), MACH_MSG_SUCCESS);
        assert_eq!(word(&second, size + 8), word(&buf, size + 8) + 1);
        space::destroy(port);
    }

    /// A buffer that holds the message but not the trailer asked for is too
    /// small, as on XNU.
    #[test]
    fn a_requested_trailer_must_fit_the_buffer() {
        let port = allocate_receive();
        send_plain(port, MACH_PORT_NULL, COPY_SEND, 9);
        let mut buf = vec![0u8; HEADER + TRAILER];
        assert_eq!(
            receive_with(port, RCV_AUDIT | RCV_LARGE, &mut buf),
            MACH_RCV_TOO_LARGE
        );
        let mut buf = vec![0u8; HEADER + 52];
        assert_eq!(receive_with(port, RCV_AUDIT, &mut buf), MACH_MSG_SUCCESS);
        space::destroy(port);
    }

    /// A server that drops a request destroys the reply right, and the
    /// client waiting on its reply port hears `MACH_NOTIFY_SEND_ONCE` from
    /// the kernel instead of waiting forever.
    #[test]
    fn a_dropped_request_tells_its_client_the_reply_is_not_coming() {
        let service = allocate_receive();
        let reply_port = allocate_receive();
        let bits = COPY_SEND | MAKE_SEND_ONCE << BITS_LOCAL_SHIFT;
        assert_eq!(send_plain(service, reply_port, bits, 100), MACH_MSG_SUCCESS);

        let mut request = vec![0u8; 256];
        assert_eq!(receive_with(service, 0, &mut request), MACH_MSG_SUCCESS);
        // SAFETY: the message just received, header and all.
        unsafe { mach_msg_destroy(request.as_mut_ptr().cast()) };

        let mut notice = vec![0xffu8; 256];
        assert_eq!(
            receive_with(reply_port, RCV_AUDIT, &mut notice),
            MACH_MSG_SUCCESS
        );
        assert_eq!(word(&notice, 20) as i32, NOTIFY_SEND_ONCE);
        assert_eq!(word(&notice, 4) as usize, HEADER);
        assert_eq!(word(&notice, 8), MACH_PORT_NULL, "no reply port");
        let audit: Vec<u32> = (0..8).map(|i| word(&notice, HEADER + 20 + i * 4)).collect();
        assert_eq!(audit, [0; 8], "KERNEL_AUDIT_TOKEN_VALUE");
        assert_eq!(
            [word(&notice, HEADER + 12), word(&notice, HEADER + 16)],
            trailer::KERNEL_SECURITY_TOKEN
        );
        space::destroy(service);
        space::destroy(reply_port);
    }

    /// The reply itself spends the right, which owes nobody a notification.
    #[test]
    fn an_answered_request_sends_no_send_once_notice() {
        let service = allocate_receive();
        let reply_port = allocate_receive();
        let bits = COPY_SEND | MAKE_SEND_ONCE << BITS_LOCAL_SHIFT;
        assert_eq!(send_plain(service, reply_port, bits, 100), MACH_MSG_SUCCESS);
        let mut request = vec![0u8; 256];
        assert_eq!(receive_with(service, 0, &mut request), MACH_MSG_SUCCESS);
        let answer_to = word(&request, 8);
        assert_eq!(
            send_plain(answer_to, MACH_PORT_NULL, MOVE_SEND_ONCE, 200),
            MACH_MSG_SUCCESS
        );

        let mut reply = vec![0u8; 256];
        assert_eq!(receive_with(reply_port, 0, &mut reply), MACH_MSG_SUCCESS);
        assert_eq!(word(&reply, 20), 200);
        let mut nothing = vec![0u8; 256];
        // SAFETY: `nothing` is writable for its whole length.
        let rc = unsafe {
            mach_msg(
                nothing.as_mut_ptr().cast(),
                RCV_MSG | RCV_TIMEOUT,
                0,
                nothing.len() as u32,
                reply_port,
                50,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_RCV_TIMED_OUT);
        space::destroy(service);
        space::destroy(reply_port);
    }

    /// Send `name` under `disposition` as the one port descriptor of a message
    /// to `service`, and answer with the name the receiver got.
    fn carry(service: Name, name: Name, disposition: u32) -> Name {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&name.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, disposition as u8, DESCRIPTOR_PORT]);
        let mut sent = message(BITS_COMPLEX | COPY_SEND, service, MACH_PORT_NULL, 5, &body);
        // SAFETY: a whole message of the size in its header.
        let rc = unsafe {
            mach_msg(
                sent.as_mut_ptr().cast(),
                SEND_MSG,
                sent.len() as u32,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(rc, MACH_MSG_SUCCESS);
        let mut buf = vec![0u8; 256];
        assert_eq!(receive_with(service, 0, &mut buf), MACH_MSG_SUCCESS);
        word(&buf, HEADER + BODY)
    }

    /// A task port crosses as the task it names: this task's own arrives as
    /// `mach_task_self()`, as a Chromium child's does in its parent.
    #[test]
    fn a_task_port_crosses_in_a_message() {
        let service = allocate_receive();
        assert_eq!(
            carry(service, space::TASK_SELF, COPY_SEND),
            space::TASK_SELF
        );
        space::destroy(service);
    }

    /// A named memory entry crosses with its object, and the name that
    /// arrives maps the same pages - Chromium's shared memory regions, which
    /// its child processes are handed at startup.
    #[test]
    fn a_memory_entry_crosses_in_a_message_and_maps_the_same_pages() {
        use super::super::memory::{mach_make_memory_entry_64, mach_vm_map};
        let service = allocate_receive();
        let mut size = 4096u64;
        let mut entry = MACH_PORT_NULL;
        // MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE.
        let permission = 0x0002_0000 | 1 | 2;
        // SAFETY: two writable locals.
        let kr = unsafe {
            mach_make_memory_entry_64(space::TASK_SELF, &mut size, 0, permission, &mut entry, 0)
        };
        assert_eq!(kr, KERN_SUCCESS);
        let arrived = carry(service, entry, COPY_SEND);
        assert_ne!(arrived, MACH_PORT_DEAD);
        assert!(space::memory_entry(arrived).is_some());

        let map = |name: Name| {
            let mut address = 0u64;
            // SAFETY: a writable local; VM_FLAGS_ANYWHERE, VM_INHERIT_NONE.
            let kr = unsafe {
                mach_vm_map(
                    space::TASK_SELF,
                    &mut address,
                    size,
                    0,
                    1,
                    name,
                    0,
                    0,
                    3,
                    3,
                    2,
                )
            };
            assert_eq!(kr, KERN_SUCCESS);
            address
        };
        let (first, second) = (map(entry), map(arrived));
        // SAFETY: two mappings of the entry's page.
        unsafe {
            (first as *mut u32).write(0x5ca1_ab1e);
            assert_eq!((second as *const u32).read(), 0x5ca1_ab1e);
            super::super::vm::vm_deallocate(space::TASK_SELF, first, size);
            super::super::vm::vm_deallocate(space::TASK_SELF, second, size);
        }
        space::mach_port_deallocate(space::TASK_SELF, arrived);
        space::mach_port_deallocate(space::TASK_SELF, entry);
        space::destroy(service);
    }

    /// Mojo's `RequestSendDeadNameNotification`: when the receive right a
    /// send right names is destroyed, the send right becomes a dead name and
    /// the notify port is told which, with a reference for it to drop.
    #[test]
    fn a_send_right_whose_port_is_destroyed_becomes_a_dead_name() {
        let port = allocate_receive();
        let address = space::address_of(port).unwrap();
        // Out of this space, so the send right is a right of its own, as it
        // is in any task but the receiver's.
        let receiver = space::move_receive(port).expect("a receive right");
        let send = space::insert_send(address);
        let notify = allocate_receive();
        let mut previous = MACH_PORT_NULL;
        // SAFETY: a writable local for the previous right.
        let kr = unsafe {
            space::mach_port_request_notification(
                space::TASK_SELF,
                send,
                space::NOTIFY_DEAD_NAME,
                0,
                notify,
                MAKE_SEND_ONCE,
                &mut previous,
            )
        };
        assert_eq!(kr, KERN_SUCCESS);
        assert!(take(notify, 100).is_none(), "the port is still alive");

        drop(receiver);
        let notice = take(notify, 2000).expect("a dead-name notification");
        assert_eq!(word(&notice, 20) as i32, space::NOTIFY_DEAD_NAME);
        assert_eq!(word(&notice, 4) as usize, HEADER + 12);
        assert_eq!(word(&notice, HEADER + 8), send, "not_port");
        let mut ty = 0;
        // SAFETY: a writable local.
        unsafe { space::mach_port_type(space::TASK_SELF, send, &mut ty) };
        assert_eq!(ty, space::type_of(space::RIGHT_DEAD_NAME));
        let mut refs = 0;
        // SAFETY: as above.
        unsafe {
            space::mach_port_get_refs(space::TASK_SELF, send, space::RIGHT_DEAD_NAME, &mut refs)
        };
        assert_eq!(refs, 2, "the right's own and the notification's");

        // Asking again about a name already dead is refused.
        // SAFETY: as above.
        let kr = unsafe {
            space::mach_port_request_notification(
                space::TASK_SELF,
                send,
                space::NOTIFY_DEAD_NAME,
                0,
                notify,
                MAKE_SEND_ONCE,
                &mut previous,
            )
        };
        assert_eq!(kr, KERN_INVALID_ARGUMENT);
        space::destroy(send);
        space::destroy(notify);
    }
}
