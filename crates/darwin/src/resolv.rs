//! libresolv: Darwin's BIND 9 stub resolver, the `res_9_*` names `<resolv.h>`
//! renames `res_*` to.
//!
//! The state a caller hands in is Darwin's `struct __res_state`, which callers
//! allocate themselves and read and write directly - the name server list in
//! particular - so the context-taking calls here work on that structure as
//! Apple's libresolv lays it out, and follow its `res_init.c`, `res_query.c`,
//! `res_send.c`, `res_mkquery.c`, `ns_parse.c`, `ns_name.c` and `res_comp.c`.
//! Queries go out over the host's sockets.
//!
//! The configuration is the host's `/etc/resolv.conf`: on a Mac, libresolv
//! asks configd for the system's name servers and search list, and those are
//! the host's here. Where this differs from libresolv:
//!
//! - Bit-string labels (RFC 2673, long since withdrawn) are refused as an
//!   unknown label type.
//! - A query or response hook (`qhook`, `rhook`) a caller installs is not
//!   called.
//! - No socket is kept open between calls, so `RES_STAYOPEN` saves nothing,
//!   and a TCP exchange gives up after `retrans` seconds of silence rather
//!   than waiting on the server forever.
//! - `sortlist` lines are not read; nothing here sorts addresses by them.

use libc::c_int;
use std::ffi::{CStr, c_char, c_void};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

unsafe extern "C" fn res_9_init() -> c_int {
    static RES_INIT_SYM: LazyLock<usize> = LazyLock::new(|| {
        let lresolv_names = [c"libresolv.so", c"libresolv.dylib"];
        for resolv in &lresolv_names {
            unsafe { libc::dlopen(resolv.as_ptr(), libc::RTLD_LAZY) };
        }
        unsafe {
            let sym = libc::dlsym(libc::RTLD_DEFAULT, c"res_init".as_ptr());
            std::mem::transmute(sym)
        }
    });
    if *RES_INIT_SYM != 0 {
        unsafe {
            let res_init: unsafe extern "C" fn() -> c_int = std::mem::transmute(*RES_INIT_SYM);
            res_init()
        }
    } else {
        // FIXME (ACCURACY): does nothing if res_init is not found
        0
    }
}

unsafe extern "C" fn res_9_close() {
    // FIXME (ACCURACY): unimplemented!
}

const MAXNS: usize = 3;
const MAXDNSRCH: usize = 6;
const MAXDFLSRCH: usize = 3;
const MAXRESOLVSORT: usize = 10;
const LOCALDOMAINPARTS: usize = 2;
const RES_TIMEOUT: c_int = 5;
const RES_DFLRETRY: c_int = 2;
const RES_MAXNDOTS: c_int = 15;
const RES_MAXRETRANS: c_int = 30;
const RES_MAXRETRY: c_int = 5;
const RES_MAXTIME: u16 = 65535;
const NAMESERVER_PORT: u16 = 53;

// `options`
const RES_INIT: u64 = 0x0000_0001;
const RES_DEBUG: u64 = 0x0000_0002;
const RES_USEVC: u64 = 0x0000_0008;
const RES_IGNTC: u64 = 0x0000_0020;
const RES_RECURSE: u64 = 0x0000_0040;
const RES_DEFNAMES: u64 = 0x0000_0080;
const RES_STAYOPEN: u64 = 0x0000_0100;
const RES_DNSRCH: u64 = 0x0000_0200;
const RES_INSECURE1: u64 = 0x0000_0400;
const RES_INSECURE2: u64 = 0x0000_0800;
const RES_NOALIASES: u64 = 0x0000_1000;
const RES_USE_INET6: u64 = 0x0000_2000;
const RES_ROTATE: u64 = 0x0000_4000;
const RES_NOCHECKNAME: u64 = 0x0000_8000;
const RES_BLAST: u64 = 0x0002_0000;
const RES_NOTLDQUERY: u64 = 0x0010_0000;
const RES_USE_DNSSEC: u64 = 0x0020_0000;
const RES_USE_DNAME: u64 = 0x1000_0000;
const RES_USE_EDNS0: u64 = 0x4000_0000;
const RES_NO_NIBBLE2: u64 = 0x8000_0000;
const RES_DEFAULT: u64 = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH | RES_NO_NIBBLE2;

// `_flags`
const RES_F_VC: u32 = 0x1;
const RES_F_CONN: u32 = 0x2;
const RES_F_EDNS0ERR: u32 = 0x4;
const RES_F_LASTMASK: u32 = 0xf0;
const RES_F_LASTSHIFT: u32 = 4;

// `h_errno`
const NETDB_INTERNAL: c_int = -1;
const HOST_NOT_FOUND: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;

// `dns_res_send` statuses, `res_private.h`
const DNS_RES_STATUS_TIMEOUT: c_int = -1001;
const DNS_RES_STATUS_INVALID_REPLY: c_int = -1006;
const DNS_RES_STATUS_CONNECTION_REFUSED: c_int = -1007;
const DNS_RES_STATUS_CONNECTION_FAILED: c_int = -1009;
const DNS_RES_STATUS_SYSTEM_ERROR: c_int = -1010;

// The wire format, `<arpa/nameser.h>`
const HFIXEDSZ: usize = 12;
const QFIXEDSZ: usize = 4;
const RRFIXEDSZ: usize = 10;
const PACKETSZ: usize = 512;
const MAXPACKET: usize = 1024;
const NS_MAXDNAME: usize = 1025;
const NS_MAXCDNAME: usize = 255;
const NS_CMPRSFLGS: u8 = 0xc0;
const NS_S_QD: c_int = 0;
const NS_S_MAX: c_int = 4;
const QUERY: c_int = 0;
const IQUERY: c_int = 1;
const NS_NOTIFY_OP: c_int = 4;
const NS_O_UPDATE: u8 = 5;
const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;
const T_NULL: u16 = 10;
const T_OPT: u16 = 41;
const NS_OPT_DNSSEC_OK: u16 = 0x8000;

/// Darwin's address families, as `sin_family` spells them.
const DARWIN_AF_INET: u8 = 2;
const DARWIN_AF_INET6: u8 = 30;

/// Darwin's `struct sockaddr_in`.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct SockaddrIn {
    len: u8,
    family: u8,
    port: [u8; 2],
    addr: [u8; 4],
    zero: [u8; 8],
}

/// Darwin's `struct sockaddr_in6`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SockaddrIn6 {
    len: u8,
    family: u8,
    port: [u8; 2],
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// `union res_sockaddr_union`
#[repr(C)]
#[derive(Clone, Copy)]
union SockaddrUnion {
    sin: SockaddrIn,
    sin6: SockaddrIn6,
    space: [u8; 128],
}

impl SockaddrUnion {
    fn family(&self) -> u8 {
        // SAFETY: every member starts with the length and family bytes.
        unsafe { self.space[1] }
    }
}

/// `struct __res_state_ext`, libresolv's private extension, which holds the
/// name servers that do not fit a `sockaddr_in`.
#[repr(C)]
struct ResStateExt {
    nsaddrs: [SockaddrUnion; MAXNS],
    sort_list: [ExtSort; MAXRESOLVSORT],
    nsuffix: [u8; 64],
    bsuffix: [u8; 64],
    nsuffix2: [u8; 64],
    conf_sys_notify_token: c_int,
    conf_mtim: [i64; 2],
    conf_stat: i64,
    reload_period: u16,
}

#[repr(C)]
struct ExtSort {
    af: c_int,
    addr: [u8; 16],
    mask: [u8; 16],
}

/// `struct __res_state`, as `<resolv.h>` lays it out for a 64-bit guest.
#[repr(C)]
pub struct ResState {
    retrans: c_int,
    retry: c_int,
    options: u64,
    nscount: c_int,
    nsaddr_list: [SockaddrIn; MAXNS],
    id: u16,
    dnsrch: [*mut c_char; MAXDNSRCH + 1],
    defdname: [c_char; 256],
    pfcode: u64,
    /// `unsigned ndots:4, nsort:4`
    ndots_nsort: u8,
    unused: [u8; 3],
    sort_list: [[u32; 2]; MAXRESOLVSORT],
    qhook: *mut c_void,
    rhook: *mut c_void,
    res_h_errno: c_int,
    vcsock: c_int,
    flags: u32,
    pad: u32,
    // `_u._ext`
    ext_nscount: u16,
    nstimes: [u16; MAXNS],
    nssocks: [c_int; MAXNS],
    ext: *mut ResStateExt,
    rnd: *mut u8,
}

/// `ns_msg`
#[repr(C)]
pub struct NsMsg {
    msg: *const u8,
    eom: *const u8,
    id: u16,
    flags: u16,
    counts: [u16; NS_S_MAX as usize],
    sections: [*const u8; NS_S_MAX as usize],
    sect: c_int,
    rrnum: c_int,
    msg_ptr: *const u8,
}

/// `ns_rr`
#[repr(C)]
pub struct NsRr {
    name: [c_char; NS_MAXDNAME],
    kind: u16,
    rr_class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: *const u8,
}

const _: () = {
    use std::mem::offset_of;
    assert!(size_of::<SockaddrIn>() == 16);
    assert!(size_of::<SockaddrIn6>() == 28);
    assert!(size_of::<SockaddrUnion>() == 128);
    assert!(size_of::<ResState>() == 552);
    assert!(offset_of!(ResState, nscount) == 16);
    assert!(offset_of!(ResState, nsaddr_list) == 20);
    assert!(offset_of!(ResState, id) == 68);
    assert!(offset_of!(ResState, dnsrch) == 72);
    assert!(offset_of!(ResState, defdname) == 128);
    assert!(offset_of!(ResState, pfcode) == 384);
    assert!(offset_of!(ResState, sort_list) == 396);
    assert!(offset_of!(ResState, qhook) == 480);
    assert!(offset_of!(ResState, res_h_errno) == 496);
    assert!(offset_of!(ResState, ext_nscount) == 512);
    assert!(offset_of!(ResState, ext) == 536);
    assert!(size_of::<NsMsg>() == 80);
    assert!(size_of::<NsRr>() == 1048);
    assert!(offset_of!(NsRr, kind) == 1026);
    assert!(offset_of!(NsRr, rdata) == 1040);
};

/// `_ns_flagdata`, which the `ns_msg_getflag` macro indexes: the mask and
/// shift of each header flag, in `ns_flag` order.
#[repr(C)]
struct FlagData([[c_int; 2]; 16]);

static NS_FLAGDATA: FlagData = FlagData([
    [0x8000, 15], // qr
    [0x7800, 11], // opcode
    [0x0400, 10], // aa
    [0x0200, 9],  // tc
    [0x0100, 8],  // rd
    [0x0080, 7],  // ra
    [0x0040, 6],  // z
    [0x0020, 5],  // ad
    [0x0010, 4],  // cd
    [0x000f, 0],  // rcode
    [0x0000, 0],  // expansion (1/6)
    [0x0000, 0],
    [0x0000, 0],
    [0x0000, 0],
    [0x0000, 0],
    [0x0000, 0],
]);

/// `__h_errno_set`: the context's status and the process's `h_errno`.
fn set_h_errno(statp: &mut ResState, status: c_int) {
    statp.res_h_errno = status;
    crate::net::resolve::set_h_errno(status);
}

fn get16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn get32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn fail<T>(errno: c_int) -> Option<T> {
    crate::errno::set(errno);
    None
}

// Names: `ns_name.c`.

/// `labellen` for a plain label; `None` for a compression pointer or an
/// extended label type.
fn label_length(byte: u8) -> Option<usize> {
    (byte & NS_CMPRSFLGS == 0).then_some(byte as usize)
}

/// `ns_name_unpack`: the uncompressed wire name at `src` in `msg`, and how
/// many bytes of `msg` it took there. `None` is `EMSGSIZE`.
fn name_unpack(msg: &[u8], src: usize, dstsiz: usize) -> Option<(Vec<u8>, usize)> {
    let eom = msg.len();
    if src >= eom {
        return fail(libc::EMSGSIZE);
    }
    let mut dst = Vec::new();
    let mut srcp = src;
    let mut len = None;
    let mut checked = 0;
    loop {
        let n = msg[srcp];
        srcp += 1;
        if n == 0 {
            break;
        }
        match n & NS_CMPRSFLGS {
            0 => {
                let l = n as usize;
                if dst.len() + l + 1 >= dstsiz || srcp + l >= eom {
                    return fail(libc::EMSGSIZE);
                }
                checked += l + 1;
                dst.push(n);
                dst.extend_from_slice(&msg[srcp..srcp + l]);
                srcp += l;
            }
            NS_CMPRSFLGS => {
                if srcp >= eom {
                    return fail(libc::EMSGSIZE);
                }
                if len.is_none() {
                    len = Some(srcp - src + 1);
                }
                let target = (((n & 0x3f) as usize) << 8) | msg[srcp] as usize;
                if target >= eom {
                    return fail(libc::EMSGSIZE);
                }
                srcp = target;
                checked += 2;
                // Having looked at the whole message, there must be a loop.
                if checked >= eom {
                    return fail(libc::EMSGSIZE);
                }
            }
            _ => return fail(libc::EMSGSIZE),
        }
    }
    dst.push(0);
    Some((dst, len.unwrap_or_else(|| srcp - src)))
}

/// `special`: what a label escapes with a backslash.
fn special(c: u8) -> bool {
    matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$')
}

/// `ns_name_ntop`: the presentation form of an uncompressed wire name, with
/// its NUL, in at most `dstsiz` bytes. `None` is `EMSGSIZE`.
fn name_ntop(src: &[u8], dstsiz: usize) -> Option<Vec<u8>> {
    let mut dst = Vec::new();
    let mut cp = 0;
    loop {
        let n = *src.get(cp)?;
        cp += 1;
        if n == 0 {
            break;
        }
        let Some(l) = label_length(n) else {
            return fail(libc::EMSGSIZE);
        };
        if !dst.is_empty() {
            if dst.len() >= dstsiz {
                return fail(libc::EMSGSIZE);
            }
            dst.push(b'.');
        }
        if dst.len() + l >= dstsiz {
            return fail(libc::EMSGSIZE);
        }
        for &c in src.get(cp..cp + l)? {
            if special(c) {
                if dst.len() + 1 >= dstsiz {
                    return fail(libc::EMSGSIZE);
                }
                dst.extend_from_slice(&[b'\\', c]);
            } else if !(0x21..0x7f).contains(&c) {
                if dst.len() + 3 >= dstsiz {
                    return fail(libc::EMSGSIZE);
                }
                dst.extend_from_slice(&[b'\\', b'0' + c / 100, b'0' + c % 100 / 10, b'0' + c % 10]);
            } else {
                if dst.len() >= dstsiz {
                    return fail(libc::EMSGSIZE);
                }
                dst.push(c);
            }
        }
        cp += l;
    }
    if dst.is_empty() {
        if dst.len() >= dstsiz {
            return fail(libc::EMSGSIZE);
        }
        dst.push(b'.');
    }
    if dst.len() >= dstsiz {
        return fail(libc::EMSGSIZE);
    }
    dst.push(0);
    Some(dst)
}

/// `ns_name_pton`: the wire form of a presentation name, which may be at
/// most `dstsiz` bytes. `None` is with `errno` set.
fn name_pton(src: &[u8], dstsiz: usize) -> Option<Vec<u8>> {
    let mut dst = vec![0u8];
    let mut label = 0;
    let mut escaped = false;
    let mut i = 0;
    let digit = |c: Option<&u8>| {
        c.filter(|c| c.is_ascii_digit())
            .map(|c| (c - b'0') as usize)
    };
    while let Some(&c) = src.get(i) {
        i += 1;
        let mut c = c;
        if escaped {
            if c == b'[' {
                // A bit-string label.
                return fail(libc::EINVAL);
            }
            if c.is_ascii_digit() {
                let (Some(tens), Some(ones)) = (digit(src.get(i)), digit(src.get(i + 1))) else {
                    return fail(libc::EMSGSIZE);
                };
                i += 2;
                let n = (c - b'0') as usize * 100 + tens * 10 + ones;
                if n > 255 {
                    return fail(libc::EMSGSIZE);
                }
                c = n as u8;
            }
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
            continue;
        } else if c == b'.' {
            let n = dst.len() - label - 1;
            if n & NS_CMPRSFLGS as usize != 0 || label >= dstsiz {
                return fail(libc::EMSGSIZE);
            }
            dst[label] = n as u8;
            // Fully qualified?
            if src.get(i).is_none() {
                if n != 0 {
                    if dst.len() >= dstsiz {
                        return fail(libc::EMSGSIZE);
                    }
                    dst.push(0);
                }
                if dst.len() > NS_MAXCDNAME {
                    return fail(libc::EMSGSIZE);
                }
                return Some(dst);
            }
            if n == 0 || src.get(i) == Some(&b'.') {
                return fail(libc::EMSGSIZE);
            }
            label = dst.len();
            dst.push(0);
            continue;
        }
        if dst.len() >= dstsiz {
            return fail(libc::EMSGSIZE);
        }
        dst.push(c);
    }
    let n = dst.len() - label - 1;
    if n & NS_CMPRSFLGS as usize != 0 || label >= dstsiz {
        return fail(libc::EMSGSIZE);
    }
    dst[label] = n as u8;
    if n != 0 {
        if dst.len() >= dstsiz {
            return fail(libc::EMSGSIZE);
        }
        dst.push(0);
    }
    if dst.len() > NS_MAXCDNAME {
        return fail(libc::EMSGSIZE);
    }
    Some(dst)
}

/// `ns_name_skip`: where the name at `at` ends.
fn name_skip(msg: &[u8], at: usize) -> Option<usize> {
    let eom = msg.len();
    let mut cp = at;
    while cp < eom {
        let n = msg[cp];
        cp += 1;
        if n == 0 {
            break;
        }
        match n & NS_CMPRSFLGS {
            0 => cp += n as usize,
            NS_CMPRSFLGS => {
                cp += 1;
                break;
            }
            _ => return fail(libc::EMSGSIZE),
        }
    }
    if cp > eom {
        return fail(libc::EMSGSIZE);
    }
    Some(cp)
}

/// `dn_expand`: the presentation form of the name at `src`, with the root
/// spelled as an empty string, and how many bytes it took.
fn expand(msg: &[u8], src: usize, dstsiz: usize) -> Option<(Vec<u8>, usize)> {
    let (wire, n) = name_unpack(msg, src, NS_MAXCDNAME)?;
    let mut text = name_ntop(&wire, dstsiz)?;
    if text[0] == b'.' {
        text[0] = 0;
    }
    Some((text, n))
}

/// `ns_samename`, on names without their NULs.
fn same_name(a: &[u8], b: &[u8]) -> Option<bool> {
    /// `ns_makecanon`: trailing dots removed, other than an escaped one, and
    /// one put back.
    fn canon(name: &[u8]) -> Option<Vec<u8>> {
        if name.len() + 2 > NS_MAXDNAME {
            return fail(libc::EMSGSIZE);
        }
        let mut n = name.len();
        while n >= 1 && name[n - 1] == b'.' {
            if n >= 2 && name[n - 2] == b'\\' && (n < 3 || name[n - 3] != b'\\') {
                break;
            }
            n -= 1;
        }
        let mut canon = name[..n].to_vec();
        canon.push(b'.');
        Some(canon)
    }
    Some(canon(a)?.eq_ignore_ascii_case(&canon(b)?))
}

// Messages: `ns_parse.c`.

/// `ns_skiprr`: the bytes `count` records of `section` take from `at`.
fn skip_records(msg: &[u8], at: usize, section: c_int, count: usize) -> Option<usize> {
    let mut ptr = at;
    for _ in 0..count {
        ptr = name_skip(msg, ptr)? + 4;
        if section != NS_S_QD {
            if ptr + 6 > msg.len() {
                return fail(libc::EMSGSIZE);
            }
            ptr += 4;
            ptr += get16(msg, ptr)? as usize + 2;
        }
    }
    if ptr > msg.len() {
        return fail(libc::EMSGSIZE);
    }
    Some(ptr - at)
}

/// The message a handle or a caller's pointers describe, as a slice.
///
/// # Safety
///
/// `msg..eom` is readable.
unsafe fn message<'a>(msg: *const u8, eom: *const u8) -> &'a [u8] {
    let len = (eom as usize).saturating_sub(msg as usize);
    if msg.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's obligation.
    unsafe { std::slice::from_raw_parts(msg, len) }
}

/// `int ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int
/// count)`
///
/// # Safety
///
/// `ptr..eom` is readable.
unsafe extern "C" fn res_9_ns_skiprr(
    ptr: *const u8,
    eom: *const u8,
    section: c_int,
    count: c_int,
) -> c_int {
    // SAFETY: the caller's obligation.
    let msg = unsafe { message(ptr, eom) };
    skip_records(msg, 0, section, count.max(0) as usize).map_or(-1, |n| n as c_int)
}

/// `setsection`
fn set_section(handle: &mut NsMsg, section: c_int) {
    handle.sect = section;
    if section == NS_S_MAX {
        handle.rrnum = -1;
        handle.msg_ptr = std::ptr::null();
    } else {
        handle.rrnum = 0;
        handle.msg_ptr = handle.sections[section as usize];
    }
}

/// `int ns_initparse(const u_char *msg, int msglen, ns_msg *handle)`
///
/// # Safety
///
/// `msg` is readable for `msglen` bytes and `handle` writable.
unsafe extern "C" fn res_9_ns_initparse(
    msg: *const u8,
    msglen: c_int,
    handle: *mut NsMsg,
) -> c_int {
    // SAFETY: the caller's obligation.
    let handle = unsafe { &mut *handle };
    let eom = msg.wrapping_add(msglen.max(0) as usize);
    handle.msg = msg;
    handle.eom = eom;
    // SAFETY: the caller's obligation.
    let bytes = unsafe { message(msg, eom) };
    let Some(header) = bytes.get(..HFIXEDSZ) else {
        crate::errno::set(libc::EMSGSIZE);
        return -1;
    };
    handle.id = u16::from_be_bytes([header[0], header[1]]);
    handle.flags = u16::from_be_bytes([header[2], header[3]]);
    for i in 0..NS_S_MAX as usize {
        handle.counts[i] = u16::from_be_bytes([header[4 + 2 * i], header[5 + 2 * i]]);
    }
    let mut at = HFIXEDSZ;
    for i in 0..NS_S_MAX as usize {
        if handle.counts[i] == 0 {
            handle.sections[i] = std::ptr::null();
        } else {
            let Some(b) = skip_records(bytes, at, i as c_int, handle.counts[i] as usize) else {
                return -1;
            };
            handle.sections[i] = msg.wrapping_add(at);
            at += b;
        }
    }
    if at != bytes.len() {
        crate::errno::set(libc::EMSGSIZE);
        return -1;
    }
    set_section(handle, NS_S_MAX);
    0
}

/// `int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr)`
///
/// # Safety
///
/// `handle` is one `ns_initparse` filled, whose message is still readable,
/// and `rr` is writable.
unsafe extern "C" fn res_9_ns_parserr(
    handle: *mut NsMsg,
    section: c_int,
    rrnum: c_int,
    rr: *mut NsRr,
) -> c_int {
    // SAFETY: the caller's obligations.
    let (handle, rr) = unsafe { (&mut *handle, &mut *rr) };
    let err = |errno| {
        crate::errno::set(errno);
        -1
    };
    if !(0..NS_S_MAX).contains(&section) {
        return err(libc::ENODEV);
    }
    if section != handle.sect {
        set_section(handle, section);
    }
    let rrnum = if rrnum == -1 { handle.rrnum } else { rrnum };
    if rrnum < 0 || rrnum >= handle.counts[section as usize] as c_int {
        return err(libc::ENODEV);
    }
    if rrnum < handle.rrnum {
        set_section(handle, section);
    }
    // SAFETY: the handle's message, which the caller keeps readable.
    let msg = unsafe { message(handle.msg, handle.eom) };
    // `ns_name_unpack`'s first check, which is where libresolv finds a section
    // pointer outside the message: the one an `ns_initparse` that stopped
    // partway through a section never set, say.
    let Some(mut at) = (handle.msg_ptr as usize)
        .checked_sub(handle.msg as usize)
        .filter(|&at| at < msg.len())
    else {
        return err(libc::EMSGSIZE);
    };
    if rrnum > handle.rrnum {
        let Some(b) = skip_records(msg, at, section, (rrnum - handle.rrnum) as usize) else {
            return -1;
        };
        at += b;
        handle.rrnum = rrnum;
    }
    let Some((name, b)) = expand(msg, at, NS_MAXDNAME) else {
        return -1;
    };
    for (to, &from) in rr.name.iter_mut().zip(&name) {
        *to = from as c_char;
    }
    at += b;
    let (Some(kind), Some(class)) = (get16(msg, at), get16(msg, at + 2)) else {
        handle.msg_ptr = handle.msg.wrapping_add(at);
        return err(libc::EMSGSIZE);
    };
    rr.kind = kind;
    rr.rr_class = class;
    at += 4;
    if section == NS_S_QD {
        rr.ttl = 0;
        rr.rdlength = 0;
        rr.rdata = std::ptr::null();
    } else {
        let (Some(ttl), Some(rdlength)) = (get32(msg, at), get16(msg, at + 4)) else {
            handle.msg_ptr = handle.msg.wrapping_add(at);
            return err(libc::EMSGSIZE);
        };
        rr.ttl = ttl;
        rr.rdlength = rdlength;
        at += 6;
        if at + rdlength as usize > msg.len() {
            handle.msg_ptr = handle.msg.wrapping_add(at);
            return err(libc::EMSGSIZE);
        }
        rr.rdata = handle.msg.wrapping_add(at);
        at += rdlength as usize;
    }
    handle.msg_ptr = handle.msg.wrapping_add(at);
    // libresolv's own test, which leaves the handle on the section's last
    // record until the call after it.
    handle.rrnum += 1;
    if handle.rrnum > handle.counts[section as usize] as c_int {
        set_section(handle, section + 1);
    }
    0
}

/// `int dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
/// char *dst, int dstsiz)`
///
/// # Safety
///
/// `msg..eom` is readable and `dst` writable for `dstsiz` bytes.
unsafe extern "C" fn res_9_dn_expand(
    msg: *const u8,
    eom: *const u8,
    src: *const u8,
    dst: *mut c_char,
    dstsiz: c_int,
) -> c_int {
    // SAFETY: the caller's obligation.
    let bytes = unsafe { message(msg, eom) };
    let Some(at) = (src as usize).checked_sub(msg as usize) else {
        crate::errno::set(libc::EMSGSIZE);
        return -1;
    };
    let Some((text, n)) = expand(bytes, at, dstsiz.max(0) as usize) else {
        return -1;
    };
    // SAFETY: `name_ntop` kept within `dstsiz`, NUL included.
    unsafe { std::ptr::copy_nonoverlapping(text.as_ptr().cast(), dst, text.len()) };
    n as c_int
}

/// `int ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char
/// *src, char *dst, size_t dstsiz)`: [`res_9_dn_expand`] without the root's
/// special case.
///
/// # Safety
///
/// As [`res_9_dn_expand`].
unsafe extern "C" fn res_9_ns_name_uncompress(
    msg: *const u8,
    eom: *const u8,
    src: *const u8,
    dst: *mut c_char,
    dstsiz: usize,
) -> c_int {
    // SAFETY: the caller's obligation.
    let bytes = unsafe { message(msg, eom) };
    let Some(at) = (src as usize).checked_sub(msg as usize) else {
        crate::errno::set(libc::EMSGSIZE);
        return -1;
    };
    let Some((wire, n)) = name_unpack(bytes, at, NS_MAXCDNAME) else {
        return -1;
    };
    let Some(text) = name_ntop(&wire, dstsiz) else {
        return -1;
    };
    // SAFETY: `name_ntop` kept within `dstsiz`, NUL included.
    unsafe { std::ptr::copy_nonoverlapping(text.as_ptr().cast(), dst, text.len()) };
    n as c_int
}

/// `int dn_skipname(const u_char *ptr, const u_char *eom)`
///
/// # Safety
///
/// `ptr..eom` is readable.
unsafe extern "C" fn res_9_dn_skipname(ptr: *const u8, eom: *const u8) -> c_int {
    // SAFETY: the caller's obligation.
    let bytes = unsafe { message(ptr, eom) };
    name_skip(bytes, 0).map_or(-1, |n| n as c_int)
}

// Configuration: `res_init.c`.

/// Memory the guest's `free` takes back, as `res_ndestroy` hands it there.
fn guest_calloc(size: usize) -> *mut c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: plain allocation; a guest's `free` is the host's here.
    return unsafe { libc::calloc(1, size) };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: plain allocation from the guest's own heap.
    return unsafe { crate::malloc::calloc(1, size) };
}

fn guest_free(ptr: *mut c_void) {
    #[cfg(target_os = "macos")]
    // SAFETY: memory `guest_calloc` gave.
    unsafe {
        libc::free(ptr)
    };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: memory `guest_calloc` gave.
    unsafe {
        crate::malloc::free(ptr)
    };
}

/// A name server as the state records it.
fn sockaddr(addr: SocketAddr) -> SockaddrUnion {
    let mut out = SockaddrUnion { space: [0; 128] };
    match addr {
        SocketAddr::V4(v4) => {
            out.sin = SockaddrIn {
                len: 16,
                family: DARWIN_AF_INET,
                port: v4.port().to_be_bytes(),
                addr: v4.ip().octets(),
                zero: [0; 8],
            };
        }
        SocketAddr::V6(v6) => {
            out.sin6 = SockaddrIn6 {
                len: 28,
                family: DARWIN_AF_INET6,
                port: v6.port().to_be_bytes(),
                flowinfo: v6.flowinfo().to_be(),
                addr: v6.ip().octets(),
                scope_id: v6.scope_id(),
            };
        }
    }
    out
}

/// The host's spelling of a recorded name server, `None` for a family
/// nothing can be sent to.
fn socket_addr(addr: &SockaddrUnion) -> Option<SocketAddr> {
    // SAFETY: the family says which member is there.
    unsafe {
        match addr.family() {
            DARWIN_AF_INET => Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr.sin.addr),
                u16::from_be_bytes(addr.sin.port),
            ))),
            DARWIN_AF_INET6 => Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6.addr),
                u16::from_be_bytes(addr.sin6.port),
                u32::from_be(addr.sin6.flowinfo),
                addr.sin6.scope_id,
            ))),
            _ => None,
        }
    }
}

/// `res_setservers`
fn set_servers(statp: &mut ResState, servers: &[SocketAddr]) {
    nclose(statp);
    statp.ext_nscount = 0;
    let mut n = 0;
    for &server in servers.iter().take(MAXNS) {
        let addr = sockaddr(server);
        if !statp.ext.is_null() {
            // SAFETY: `ext` is the extension `res_ninit` allocated.
            unsafe { (*statp.ext).nsaddrs[n] = addr };
        }
        match server {
            // SAFETY: just written as an IPv4 address.
            SocketAddr::V4(_) => statp.nsaddr_list[n] = unsafe { addr.sin },
            SocketAddr::V6(_) => statp.nsaddr_list[n].family = 0,
        }
        n += 1;
    }
    statp.nscount = n as c_int;
}

/// A `nameserver` line's address, as `getaddrinfo` with `AI_NUMERICHOST`
/// reads it.
fn numeric_host(text: &str) -> Option<SocketAddr> {
    let (host, scope) = match text.split_once('%') {
        Some((host, scope)) => (host, Some(scope)),
        None => (text, None),
    };
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) if scope.is_none() => Some(SocketAddr::new(v4.into(), NAMESERVER_PORT)),
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => {
            let scope = match scope {
                None => 0,
                Some(scope) => match scope.parse::<u32>() {
                    Ok(index) => index,
                    Err(_) => {
                        let name = std::ffi::CString::new(scope).ok()?;
                        // SAFETY: a NUL-terminated interface name.
                        unsafe { libc::if_nametoindex(name.as_ptr()) }
                    }
                },
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                v6,
                NAMESERVER_PORT,
                0,
                scope,
            )))
        }
    }
}

/// Copy `text` into `defdname` as `strncpy` into it would, NUL-terminated.
fn set_defdname(statp: &mut ResState, text: &[u8]) {
    let n = text.len().min(statp.defdname.len() - 1);
    statp.defdname.fill(0);
    for (to, &from) in statp.defdname.iter_mut().zip(&text[..n]) {
        *to = from as c_char;
    }
}

/// Point `dnsrch` at the blank-separated words of `defdname`, cutting them
/// apart there, as `search` and `LOCALDOMAIN` do: how many there are.
fn split_search(statp: &mut ResState) -> usize {
    let base = statp.defdname.as_mut_ptr();
    let len = statp.defdname.iter().position(|&c| c == 0).unwrap_or(255);
    let mut pp = 0;
    statp.dnsrch[pp] = base;
    pp += 1;
    let mut gap = false;
    let mut cp = 0;
    while cp < len && pp < MAXDNSRCH {
        let c = statp.defdname[cp] as u8;
        if c == b'\n' {
            break;
        } else if c == b' ' || c == b'\t' {
            statp.defdname[cp] = 0;
            gap = true;
        } else if gap {
            statp.dnsrch[pp] = base.wrapping_add(cp);
            pp += 1;
            gap = false;
        }
        cp += 1;
    }
    // A last domain past the limit ends where its word does.
    while cp < len && !matches!(statp.defdname[cp] as u8, b' ' | b'\t' | b'\n') {
        cp += 1;
    }
    if cp < statp.defdname.len() {
        statp.defdname[cp] = 0;
    }
    statp.dnsrch[pp] = std::ptr::null_mut();
    pp
}

/// `res_setoptions`
fn set_options(statp: &mut ResState, options: &str) {
    let number = |value: &str| -> c_int {
        let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().unwrap_or(0)
    };
    for word in options.split([' ', '\t']).filter(|word| !word.is_empty()) {
        if let Some(value) = word.strip_prefix("ndots:") {
            let ndots = number(value).min(RES_MAXNDOTS);
            statp.ndots_nsort = (statp.ndots_nsort & 0xf0) | ndots as u8;
        } else if let Some(value) = word.strip_prefix("timeout:") {
            statp.retrans = number(value).min(RES_MAXRETRANS);
        } else if let Some(value) = word.strip_prefix("attempts:") {
            statp.retry = number(value).min(RES_MAXRETRY);
        } else if word.starts_with("debug") {
            statp.options |= RES_DEBUG;
        } else if word.starts_with("no_tld_query") || word.starts_with("no-tld-query") {
            statp.options |= RES_NOTLDQUERY;
        } else if word.starts_with("inet6") {
            statp.options |= RES_USE_INET6;
        } else if word.starts_with("insecure1") {
            statp.options |= RES_INSECURE1;
        } else if word.starts_with("insecure2") {
            statp.options |= RES_INSECURE2;
        } else if word.starts_with("rotate") {
            statp.options |= RES_ROTATE;
        } else if word.starts_with("usevc") {
            statp.options |= RES_USEVC;
        } else if word.starts_with("no-check-names") {
            statp.options |= RES_NOCHECKNAME;
        } else if let Some(value) = word.strip_prefix("reload-period:") {
            if !statp.ext.is_null() {
                // SAFETY: `ext` is the extension `res_ninit` allocated.
                unsafe { (*statp.ext).reload_period = number(value) as u16 };
            }
        } else if word.starts_with("edns0") {
            statp.options |= RES_USE_EDNS0;
        } else if word.starts_with("dname") {
            statp.options |= RES_USE_DNAME;
        } else if let Some(value) = word.strip_prefix("nibble:") {
            if !statp.ext.is_null() {
                // SAFETY: as above.
                set_suffix(unsafe { &mut (*statp.ext).nsuffix }, value);
            }
        } else if let Some(value) = word.strip_prefix("nibble2:") {
            if !statp.ext.is_null() {
                // SAFETY: as above.
                set_suffix(unsafe { &mut (*statp.ext).nsuffix2 }, value);
            }
        } else if let Some(value) = word.strip_prefix("v6revmode:") {
            if value.starts_with("single") {
                statp.options |= RES_NO_NIBBLE2;
            } else if value.starts_with("both") {
                statp.options &= !RES_NO_NIBBLE2;
            }
        }
    }
}

fn set_suffix(to: &mut [u8; 64], value: &str) {
    let n = value.len().min(to.len() - 1);
    to.fill(0);
    to[..n].copy_from_slice(&value.as_bytes()[..n]);
}

/// The guest's value for an environment variable.
fn guest_env(name: &CStr) -> Option<Vec<u8>> {
    // SAFETY: a NUL-terminated name.
    let value = unsafe { crate::env::getenv(name.as_ptr()) };
    // SAFETY: `getenv` answers null or a C string.
    (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_bytes().to_vec())
}

/// `__res_vinit_from_file`, on the host's `resolv.conf`.
fn vinit(statp: &mut ResState, conf: &str) -> c_int {
    set_h_errno(statp, 0);
    // `res_build_start`, on the configd path a Mac takes, stamps the version
    // libresolv keeps in `_pad`; the host's configuration stands in for
    // configd's here.
    statp.pad = 9;
    statp.retrans = RES_TIMEOUT;
    statp.retry = RES_DFLRETRY;
    statp.options = RES_DEFAULT;
    statp.id = getrandom::u32().unwrap_or(0) as u16;
    statp.nscount = 0;
    statp.ndots_nsort = 1;
    statp.pfcode = 0;
    statp.vcsock = -1;
    statp.flags = 0;
    statp.qhook = std::ptr::null_mut();
    statp.rhook = std::ptr::null_mut();
    statp.ext_nscount = 0;
    statp.ext = guest_calloc(size_of::<ResStateExt>()).cast();
    let mut maxns = MAXNS;
    if statp.ext.is_null() {
        // libresolv keeps going, and leaves the failure for the caller to
        // find in `h_errno` and in a context with no name servers.
        set_h_errno(statp, NETDB_INTERNAL);
        maxns = 0;
    } else {
        // SAFETY: just allocated, zeroed.
        let ext = unsafe { &mut *statp.ext };
        ext.conf_sys_notify_token = -1;
        set_suffix(&mut ext.nsuffix, "ip6.arpa");
        set_suffix(&mut ext.nsuffix2, "ip6.int");
        ext.reload_period = 2;
    }
    let defaults = [
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), NAMESERVER_PORT),
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), NAMESERVER_PORT),
    ];
    set_servers(statp, &defaults);

    let mut haveenv = false;
    let mut havesearch = false;
    if crate::credentials::issetugid() == 0
        && let Some(domain) = guest_env(c"LOCALDOMAIN")
    {
        set_defdname(statp, &domain);
        haveenv = true;
        // A search list is had only if the value names a second domain.
        havesearch = split_search(statp) > 1;
    }

    let mut servers = Vec::new();
    for line in conf.lines() {
        if line.starts_with([';', '#']) {
            continue;
        }
        let keyword = |name: &str| {
            line.strip_prefix(name)
                .filter(|rest| rest.starts_with([' ', '\t']))
                .map(|rest| rest.trim_start_matches([' ', '\t']))
        };
        if let Some(rest) = keyword("domain") {
            if haveenv || rest.is_empty() {
                continue;
            }
            let word = rest.split([' ', '\t', '\n']).next().unwrap_or("");
            set_defdname(statp, word.as_bytes());
            havesearch = false;
        } else if let Some(rest) = keyword("search") {
            if haveenv || rest.is_empty() {
                continue;
            }
            set_defdname(statp, rest.as_bytes());
            split_search(statp);
            havesearch = true;
        } else if let Some(rest) = keyword("nameserver") {
            if servers.len() >= maxns {
                continue;
            }
            let end = rest.find([';', '#', ' ', '\t', '\n']).unwrap_or(rest.len());
            if let Some(server) = numeric_host(&rest[..end]) {
                servers.push(server);
            }
        } else if let Some(rest) = keyword("options") {
            set_options(statp, rest);
        }
    }
    for (n, &server) in servers.iter().enumerate() {
        let addr = sockaddr(server);
        if !statp.ext.is_null() {
            // SAFETY: `ext` is the extension allocated above.
            unsafe { (*statp.ext).nsaddrs[n] = addr };
        }
        match server {
            // SAFETY: just written as an IPv4 address.
            SocketAddr::V4(_) => statp.nsaddr_list[n] = unsafe { addr.sin },
            SocketAddr::V6(_) => statp.nsaddr_list[n].family = 0,
        }
    }
    if !servers.is_empty() {
        statp.nscount = servers.len() as c_int;
    }

    if statp.defdname[0] == 0 {
        let mut host = [0 as c_char; 256];
        // SAFETY: a buffer of the length given, one short to keep a NUL.
        if unsafe { libc::gethostname(host.as_mut_ptr(), host.len() - 1) } == 0 {
            // SAFETY: NUL-terminated, the last byte never written.
            let host = unsafe { CStr::from_ptr(host.as_ptr()) }.to_bytes();
            if let Some(dot) = host.iter().position(|&c| c == b'.') {
                let domain = host[dot + 1..].to_vec();
                set_defdname(statp, &domain);
            }
        }
    }
    if !havesearch {
        // The local domain and each parent of it with at least
        // `LOCALDOMAINPARTS` labels left.
        let base = statp.defdname.as_mut_ptr();
        statp.dnsrch[0] = base;
        let mut pp = 1;
        let len = statp.defdname.iter().position(|&c| c == 0).unwrap_or(255);
        let mut dots = statp.defdname[..len]
            .iter()
            .filter(|&&c| c as u8 == b'.')
            .count();
        let mut cp = 0;
        while pp < MAXDFLSRCH && dots >= LOCALDOMAINPARTS {
            cp += statp.defdname[cp..len]
                .iter()
                .position(|&c| c as u8 == b'.')
                .unwrap_or(0)
                + 1;
            statp.dnsrch[pp] = base.wrapping_add(cp);
            pp += 1;
            dots -= 1;
        }
        statp.dnsrch[pp] = std::ptr::null_mut();
    }

    if crate::credentials::issetugid() != 0 {
        statp.options |= RES_NOALIASES;
    } else if let Some(options) = guest_env(c"RES_OPTIONS") {
        set_options(statp, &String::from_utf8_lossy(&options));
    }
    statp.options |= RES_INIT;
    statp.res_h_errno
}

/// `int res_ninit(res_state statp)`
///
/// # Safety
///
/// `statp` is null or a writable `struct __res_state`.
unsafe extern "C" fn res_9_ninit(statp: *mut ResState) -> c_int {
    if statp.is_null() {
        return -1;
    }
    // SAFETY: the caller's obligation; zero is a valid state throughout.
    let statp = unsafe {
        std::ptr::write_bytes(statp, 0, 1);
        &mut *statp
    };
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    vinit(statp, &conf)
}

/// `res_nclose`: close what the context holds open.
fn nclose(statp: &mut ResState) {
    if statp.vcsock >= 0 {
        // SAFETY: a descriptor the context says it owns.
        unsafe { libc::close(statp.vcsock) };
        statp.vcsock = -1;
        statp.flags &= !(RES_F_VC | RES_F_CONN);
    }
    for ns in 0..(statp.ext_nscount as usize).min(MAXNS) {
        if statp.nssocks[ns] != -1 {
            // SAFETY: as above.
            unsafe { libc::close(statp.nssocks[ns]) };
            statp.nssocks[ns] = -1;
        }
    }
}

/// `void res_nclose(res_state statp)`
///
/// # Safety
///
/// `statp` is a `struct __res_state`.
unsafe extern "C" fn res_9_nclose(statp: *mut ResState) {
    // SAFETY: the caller's obligation.
    nclose(unsafe { &mut *statp });
}

/// `int res_getservers(res_state statp, union res_sockaddr_union *set, int
/// cnt)`: the first `cnt` of the context's name servers into `set`, from the
/// extension where there is one - which is where an IPv6 server fits - and the
/// number the context has, which may be more than were copied.
///
/// `res_init.c`: a server of any family but these two is copied as a zero
/// family.
///
/// # Safety
///
/// `statp` is a `struct __res_state`, and `set` has room for `cnt` entries.
unsafe extern "C" fn res_9_getservers(
    statp: *mut ResState,
    set: *mut SockaddrUnion,
    cnt: c_int,
) -> c_int {
    // SAFETY: the caller's obligation.
    let statp = unsafe { &*statp };
    let count = statp.nscount.clamp(0, MAXNS as c_int).min(cnt.max(0)) as usize;
    for i in 0..count {
        // SAFETY: `set` has room for `cnt` entries, and `i` is below it.
        let out = unsafe { &mut *set.add(i) };
        let from: *const u8 = match statp.ext.is_null() {
            // SAFETY: the extension `res_ninit` allocated.
            false => unsafe { (&raw const (*statp.ext).nsaddrs[i]).cast() },
            true => (&raw const statp.nsaddr_list[i]).cast(),
        };
        // SAFETY: both members start with the length and family bytes.
        let family = unsafe { *from.add(1) };
        let size = match family {
            DARWIN_AF_INET => size_of::<SockaddrIn>(),
            // `nsaddr_list` holds no `sockaddr_in6`: `res_setservers` stores
            // one with a zero family there instead.
            DARWIN_AF_INET6 => size_of::<SockaddrIn6>(),
            _ => {
                // SAFETY: a writable `res_sockaddr_union`.
                out.sin.family = 0;
                continue;
            }
        };
        // SAFETY: `size` bytes of the source member, into the union.
        unsafe { std::ptr::copy_nonoverlapping(from, (&raw mut *out).cast::<u8>(), size) };
    }
    statp.nscount
}

/// `void res_setservers(res_state statp, const union res_sockaddr_union *set,
/// int cnt)`: replace the context's name servers with the IPv4 and IPv6 ones
/// among the first `cnt` of `set`, up to `MAXNS`, closing its sockets and
/// forgetting what it had measured of the old ones.
///
/// # Safety
///
/// `statp` is a `struct __res_state`, and `set` holds `cnt` entries.
unsafe extern "C" fn res_9_setservers(statp: *mut ResState, set: *const SockaddrUnion, cnt: c_int) {
    // SAFETY: the caller's obligation.
    let statp = unsafe { &mut *statp };
    nclose(statp);
    statp.ext_nscount = 0;
    let mut nserv = 0;
    for i in 0..cnt.max(0) as usize {
        if nserv == MAXNS {
            break;
        }
        // SAFETY: `set` holds `cnt` entries.
        let entry = unsafe { &*set.add(i) };
        let size = match entry.family() {
            DARWIN_AF_INET => size_of::<SockaddrIn>(),
            DARWIN_AF_INET6 => size_of::<SockaddrIn6>(),
            _ => continue,
        };
        if !statp.ext.is_null() {
            // SAFETY: `size` bytes of the entry into the extension's slot.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&raw const *entry).cast::<u8>(),
                    (&raw mut (*statp.ext).nsaddrs[nserv]).cast::<u8>(),
                    size,
                )
            };
        }
        match size <= size_of::<SockaddrIn>() {
            // SAFETY: the IPv4 member of the entry.
            true => statp.nsaddr_list[nserv] = unsafe { entry.sin },
            false => statp.nsaddr_list[nserv].family = 0,
        }
        nserv += 1;
    }
    statp.nscount = nserv as c_int;
}

/// `void res_ndestroy(res_state statp)`: close it, and free what `res_ninit`
/// allocated.
///
/// # Safety
///
/// `statp` is a `struct __res_state`.
unsafe extern "C" fn res_9_ndestroy(statp: *mut ResState) {
    // SAFETY: the caller's obligation.
    let statp = unsafe { &mut *statp };
    nclose(statp);
    if !statp.ext.is_null() {
        guest_free(statp.ext.cast());
        statp.ext = std::ptr::null_mut();
    }
    if !statp.rnd.is_null() {
        guest_free(statp.rnd.cast());
        statp.rnd = std::ptr::null_mut();
    }
    statp.options &= !RES_INIT;
}

// Queries: `res_mkquery.c`.

/// `res_nmkquery`, into `buf`: the query's length.
fn mkquery(
    statp: &mut ResState,
    op: c_int,
    dname: &[u8],
    class: c_int,
    kind: c_int,
    data: Option<&[u8]>,
    buf: &mut [u8],
) -> Option<usize> {
    if buf.len() < HFIXEDSZ {
        return None;
    }
    buf[..HFIXEDSZ].fill(0);
    statp.id = getrandom::u32().unwrap_or(0) as u16;
    buf[..2].copy_from_slice(&(getrandom::u32().unwrap_or(0) as u16).to_ne_bytes());
    buf[2] = ((op as u8 & 0xf) << 3) | u8::from(statp.options & RES_RECURSE != 0);
    let mut cp = HFIXEDSZ;
    let ep = buf.len();
    match op {
        QUERY | NS_NOTIFY_OP => {
            if ep - cp < QFIXEDSZ {
                return None;
            }
            let name = name_pton(dname, ep - cp - QFIXEDSZ)?;
            buf[cp..cp + name.len()].copy_from_slice(&name);
            cp += name.len();
            buf[cp..cp + 2].copy_from_slice(&(kind as u16).to_be_bytes());
            buf[cp + 2..cp + 4].copy_from_slice(&(class as u16).to_be_bytes());
            cp += 4;
            buf[4..6].copy_from_slice(&1u16.to_be_bytes());
            let Some(data) = data.filter(|_| op != QUERY) else {
                return Some(cp);
            };
            // A record for the completion domain.
            if ep - cp < RRFIXEDSZ {
                return None;
            }
            let name = name_pton(data, ep - cp - RRFIXEDSZ)?;
            buf[cp..cp + name.len()].copy_from_slice(&name);
            cp += name.len();
            buf[cp..cp + 2].copy_from_slice(&T_NULL.to_be_bytes());
            buf[cp + 2..cp + 4].copy_from_slice(&(class as u16).to_be_bytes());
            buf[cp + 4..cp + 10].fill(0);
            cp += 10;
            buf[10..12].copy_from_slice(&1u16.to_be_bytes());
            Some(cp)
        }
        IQUERY => {
            let data = data.unwrap_or(&[]);
            if ep - cp < 1 + RRFIXEDSZ + data.len() {
                return None;
            }
            buf[cp] = 0;
            cp += 1;
            buf[cp..cp + 2].copy_from_slice(&(kind as u16).to_be_bytes());
            buf[cp + 2..cp + 4].copy_from_slice(&(class as u16).to_be_bytes());
            buf[cp + 4..cp + 8].fill(0);
            buf[cp + 8..cp + 10].copy_from_slice(&(data.len() as u16).to_be_bytes());
            cp += 10;
            buf[cp..cp + data.len()].copy_from_slice(data);
            cp += data.len();
            buf[6..8].copy_from_slice(&1u16.to_be_bytes());
            Some(cp)
        }
        _ => None,
    }
}

/// `res_nopt`: an EDNS0 OPT record offering `anslen` bytes of UDP answer.
fn add_opt(statp: &ResState, n0: usize, buf: &mut [u8], anslen: usize) -> Option<usize> {
    if buf.len() - n0 < 1 + RRFIXEDSZ {
        return None;
    }
    let flags = match statp.options & RES_USE_DNSSEC != 0 {
        true => NS_OPT_DNSSEC_OK,
        false => 0,
    };
    let rr = &mut buf[n0..n0 + 1 + RRFIXEDSZ];
    rr[0] = 0;
    rr[1..3].copy_from_slice(&T_OPT.to_be_bytes());
    rr[3..5].copy_from_slice(&(anslen.min(0xffff) as u16).to_be_bytes());
    rr[5] = NOERROR;
    rr[6] = 0;
    rr[7..9].copy_from_slice(&flags.to_be_bytes());
    rr[9..11].fill(0);
    let arcount = get16(buf, 10)? + 1;
    buf[10..12].copy_from_slice(&arcount.to_be_bytes());
    Some(n0 + 1 + RRFIXEDSZ)
}

/// `int res_nmkquery(res_state statp, int op, const char *dname, int class,
/// int type, const u_char *data, int datalen, const u_char *newrr, u_char
/// *buf, int buflen)`
///
/// # Safety
///
/// `statp` is a `struct __res_state`, `dname` a C string, `data` readable
/// for `datalen` bytes when not null, and `buf` writable for `buflen`.
unsafe extern "C" fn res_9_nmkquery(
    statp: *mut ResState,
    op: c_int,
    dname: *const c_char,
    class: c_int,
    kind: c_int,
    data: *const u8,
    datalen: c_int,
    _newrr: *const u8,
    buf: *mut u8,
    buflen: c_int,
) -> c_int {
    if buf.is_null() || buflen < HFIXEDSZ as c_int || dname.is_null() {
        return -1;
    }
    // SAFETY: the caller's obligations.
    let (statp, dname, buf) = unsafe {
        (
            &mut *statp,
            CStr::from_ptr(dname).to_bytes(),
            std::slice::from_raw_parts_mut(buf, buflen as usize),
        )
    };
    let data = (!data.is_null()).then(|| {
        // SAFETY: the caller's obligation.
        let data = unsafe { std::slice::from_raw_parts(data, datalen.max(0) as usize) };
        // `QUERY` and `NOTIFY` read it as a name, which ends at its NUL.
        match op {
            IQUERY => data,
            _ => data.split(|&c| c == 0).next().unwrap_or(data),
        }
    });
    mkquery(statp, op, dname, class, kind, data, buf).map_or(-1, |n| n as c_int)
}

// Sending: `res_send.c`.

/// `get_nsaddr`: the address the caller may have written into
/// `nsaddr_list`, and otherwise the extension's, which holds what does not
/// fit there.
fn server_addr(statp: &ResState, ns: usize) -> SockaddrUnion {
    if statp.nsaddr_list[ns].family == 0 && !statp.ext.is_null() {
        // SAFETY: `ext` is the extension `res_ninit` allocated.
        unsafe { (*statp.ext).nsaddrs[ns] }
    } else {
        let mut addr = SockaddrUnion { space: [0; 128] };
        addr.sin = statp.nsaddr_list[ns];
        addr
    }
}

/// `sock_eq`
fn same_server(a: &SockaddrUnion, b: &SockaddrUnion) -> bool {
    a.family() == b.family() && socket_addr(a) == socket_addr(b)
}

/// `res_ourserver_p`
fn our_server(statp: &ResState, from: SocketAddr) -> bool {
    (0..(statp.nscount.max(0) as usize).min(MAXNS)).any(|ns| {
        match (socket_addr(&server_addr(statp, ns)), from) {
            (Some(SocketAddr::V4(srv)), SocketAddr::V4(from)) => {
                srv.port() == from.port() && (srv.ip().is_unspecified() || srv.ip() == from.ip())
            }
            (Some(SocketAddr::V6(srv)), SocketAddr::V6(from)) if !statp.ext.is_null() => {
                srv.port() == from.port()
                    && (srv.scope_id() == 0 || srv.scope_id() == from.scope_id())
                    && (srv.ip().is_unspecified() || srv.ip() == from.ip())
            }
            _ => false,
        }
    })
}

/// `res_nameinquery`
fn name_in_query(name: &[u8], kind: u16, class: u16, msg: &[u8]) -> Option<bool> {
    let qdcount = get16(msg, 4)?;
    let mut cp = HFIXEDSZ;
    for _ in 0..qdcount {
        let (tname, n) = expand(msg, cp, NS_MAXDNAME)?;
        cp += n;
        let (ttype, tclass) = (get16(msg, cp)?, get16(msg, cp + 2)?);
        cp += 4;
        let tname = &tname[..tname.len() - 1];
        let tname = tname.split(|&c| c == 0).next().unwrap_or(tname);
        if ttype == kind && tclass == class && same_name(tname, name) == Some(true) {
            return Some(true);
        }
    }
    Some(false)
}

/// `res_queriesmatch`: whether the two messages ask the same questions.
/// `None` is a format error.
fn queries_match(query: &[u8], answer: &[u8]) -> Option<bool> {
    if query.len() < HFIXEDSZ || answer.len() < HFIXEDSZ {
        return None;
    }
    // A dynamic update's reply has only its header.
    let opcode = |msg: &[u8]| (msg[2] >> 3) & 0xf;
    if opcode(query) == NS_O_UPDATE && opcode(answer) == NS_O_UPDATE {
        return Some(true);
    }
    let qdcount = get16(query, 4)?;
    if qdcount != get16(answer, 4)? {
        return Some(false);
    }
    let mut cp = HFIXEDSZ;
    for _ in 0..qdcount {
        let (tname, n) = expand(query, cp, NS_MAXDNAME)?;
        cp += n;
        let (ttype, tclass) = (get16(query, cp)?, get16(query, cp + 2)?);
        cp += 4;
        let tname = tname.split(|&c| c == 0).next().unwrap_or(&[]);
        if name_in_query(tname, ttype, tclass, answer) != Some(true) {
            return Some(false);
        }
    }
    Some(true)
}

fn rcode(msg: &[u8]) -> u8 {
    msg[3] & 0xf
}

/// What one exchange with a server came to.
struct Exchange {
    terrno: c_int,
    status: c_int,
    v_circuit: bool,
    gotsomewhere: bool,
}

fn is_family_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT | libc::EPFNOSUPPORT)
    )
}

/// `send_dg`: -1 to stop, 0 to try the next server, or the answer's length.
fn send_dg(
    statp: &mut ResState,
    query: &[u8],
    ans: &mut [u8],
    ns: usize,
    tries: c_int,
    state: &mut Exchange,
) -> isize {
    let Some(server) = socket_addr(&server_addr(statp, ns)) else {
        return 0;
    };
    let local: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match std::net::UdpSocket::bind(local) {
        Ok(socket) => socket,
        Err(error) if is_family_error(&error) => return 0,
        Err(error) => {
            state.terrno = error.raw_os_error().unwrap_or(libc::EIO);
            state.status = DNS_RES_STATUS_SYSTEM_ERROR;
            return -1;
        }
    };
    // Connected, so that a server that is not there answers with ICMP the
    // next read reports, rather than with a timeout.
    let insecure = statp.options & RES_INSECURE1 != 0;
    if !insecure && socket.connect(server).is_err() {
        return 0;
    }
    let sent = match insecure {
        true => socket.send_to(query, server),
        false => socket.send(query),
    };
    if sent.ok() != Some(query.len()) {
        state.status = DNS_RES_STATUS_CONNECTION_FAILED;
        return 0;
    }
    let mut seconds = statp
        .retrans
        .checked_shl(tries.max(0) as u32)
        .unwrap_or(c_int::MAX);
    if ns > 0 && statp.nscount > 0 {
        seconds /= statp.nscount;
    }
    let seconds = seconds.max(1);
    let finish = Instant::now() + Duration::from_secs(seconds as u64);
    loop {
        let left = finish.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            state.gotsomewhere = true;
            state.status = DNS_RES_STATUS_TIMEOUT;
            return 0;
        }
        let (resplen, from) = match socket.recv_from(ans) {
            Ok(received) => received,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                state.gotsomewhere = true;
                state.status = DNS_RES_STATUS_TIMEOUT;
                return 0;
            }
            Err(_) => {
                state.status = DNS_RES_STATUS_CONNECTION_FAILED;
                return 0;
            }
        };
        if resplen == 0 {
            state.status = DNS_RES_STATUS_CONNECTION_FAILED;
            return 0;
        }
        state.gotsomewhere = true;
        if resplen < HFIXEDSZ {
            state.terrno = libc::EMSGSIZE;
            state.status = DNS_RES_STATUS_INVALID_REPLY;
            return 0;
        }
        // An answer to an older query, or from somewhere else: wait on.
        if query[..2] != ans[..2] || (!insecure && !our_server(statp, from)) {
            continue;
        }
        if rcode(ans) == FORMERR && statp.options & RES_USE_EDNS0 != 0 {
            // A server that does not know EDNS0; its FORMERR carries no
            // question to match.
            statp.flags |= RES_F_EDNS0ERR;
            state.status = DNS_RES_STATUS_CONNECTION_REFUSED;
            return 0;
        }
        if statp.options & RES_INSECURE2 == 0 && queries_match(query, ans) != Some(true) {
            state.status = DNS_RES_STATUS_INVALID_REPLY;
            return 0;
        }
        if matches!(rcode(ans), SERVFAIL | NOTIMP | REFUSED) && statp.pfcode == 0 {
            state.status = rcode(ans) as c_int;
            return 0;
        }
        if statp.options & RES_IGNTC == 0 && ans[2] & 0x02 != 0 {
            // Truncated: the rest comes over TCP from the same server.
            state.v_circuit = true;
            return 1;
        }
        return resplen as isize;
    }
}

/// `send_vc`: as [`send_dg`], over TCP.
fn send_vc(
    statp: &mut ResState,
    query: &[u8],
    ans: &mut [u8],
    ns: usize,
    state: &mut Exchange,
) -> isize {
    let Some(server) = socket_addr(&server_addr(statp, ns)) else {
        return 0;
    };
    let patience = Duration::from_secs(statp.retrans.max(1) as u64);
    let errno = |error: &std::io::Error| error.raw_os_error().unwrap_or(libc::EIO);
    let mut connreset = false;
    'same_ns: loop {
        let mut stream = match std::net::TcpStream::connect_timeout(&server, patience) {
            Ok(stream) => stream,
            Err(error) if is_family_error(&error) => return 0,
            Err(error) => {
                state.terrno = errno(&error);
                state.status = DNS_RES_STATUS_CONNECTION_REFUSED;
                return 0;
            }
        };
        let _ = stream.set_read_timeout(Some(patience));
        let _ = stream.set_write_timeout(Some(patience));
        let mut message = (query.len() as u16).to_be_bytes().to_vec();
        message.extend_from_slice(query);
        if let Err(error) = stream.write_all(&message) {
            state.terrno = errno(&error);
            state.status = DNS_RES_STATUS_CONNECTION_FAILED;
            return 0;
        }
        loop {
            let mut length = [0u8; 2];
            if let Err(error) = stream.read_exact(&mut length) {
                state.terrno = errno(&error);
                // A long-running process's connection may be reset when the
                // server restarts: ask the same server once more.
                if state.terrno == libc::ECONNRESET && !connreset {
                    connreset = true;
                    continue 'same_ns;
                }
                state.status = DNS_RES_STATUS_CONNECTION_FAILED;
                return 0;
            }
            let resplen = u16::from_be_bytes(length) as usize;
            let len = resplen.min(ans.len());
            if len < HFIXEDSZ {
                state.terrno = libc::EMSGSIZE;
                state.status = DNS_RES_STATUS_INVALID_REPLY;
                return 0;
            }
            if let Err(error) = stream.read_exact(&mut ans[..len]) {
                state.terrno = errno(&error);
                state.status = DNS_RES_STATUS_CONNECTION_FAILED;
                return 0;
            }
            if resplen > ans.len() {
                // Keep the stream in step past what did not fit.
                ans[2] |= 0x02;
                let _ = std::io::copy(
                    &mut (&mut stream).take((resplen - ans.len()) as u64),
                    &mut std::io::sink(),
                );
            }
            // An answer to a query an earlier caller gave up on.
            if query[..2] != ans[..2] {
                continue;
            }
            return resplen as isize;
        }
    }
}

/// `dns_res_send`: the answer's length, or `Err` with `errno` set.
fn send(statp: &mut ResState, query: &[u8], ans: &mut [u8]) -> Result<usize, ()> {
    let nscount = (statp.nscount.max(0) as usize).min(MAXNS);
    if nscount == 0 || statp.ext.is_null() {
        crate::errno::set(libc::ESRCH);
        return Err(());
    }
    if ans.len() < HFIXEDSZ {
        crate::errno::set(libc::EINVAL);
        return Err(());
    }
    let mut state = Exchange {
        terrno: libc::ETIMEDOUT,
        status: 0,
        v_circuit: statp.options & RES_USEVC != 0 || query.len() > PACKETSZ,
        gotsomewhere: false,
    };
    // SAFETY: `ext` is the extension `res_ninit` allocated.
    let ext = unsafe { &mut *statp.ext };
    // A list the caller changed since the last query is taken afresh.
    if statp.ext_nscount != 0 {
        let changed = statp.ext_nscount as usize != nscount
            || (0..nscount).any(|ns| {
                let mut listed = SockaddrUnion { space: [0; 128] };
                listed.sin = statp.nsaddr_list[ns];
                statp.nsaddr_list[ns].family != 0 && !same_server(&listed, &ext.nsaddrs[ns])
            });
        if changed {
            nclose(statp);
            statp.ext_nscount = 0;
        }
    }
    if statp.ext_nscount == 0 {
        for ns in 0..nscount {
            statp.nstimes[ns] = RES_MAXTIME;
            statp.nssocks[ns] = -1;
            if statp.nsaddr_list[ns].family != 0 {
                ext.nsaddrs[ns] = SockaddrUnion { space: [0; 128] };
                ext.nsaddrs[ns].sin = statp.nsaddr_list[ns];
            }
        }
        statp.ext_nscount = nscount as u16;
    }
    if statp.options & RES_ROTATE != 0 && statp.options & RES_BLAST == 0 {
        statp.nsaddr_list[..nscount].rotate_left(1);
        ext.nsaddrs[..nscount].rotate_left(1);
        statp.nssocks[..nscount].rotate_left(1);
        statp.nstimes[..nscount].rotate_left(1);
    }
    let mut tries = 0;
    while tries < statp.retry {
        let mut ns = 0;
        while ns < nscount {
            statp.flags &= !RES_F_LASTMASK;
            statp.flags |= (ns as u32) << RES_F_LASTSHIFT;
            state.status = 0;
            let n = loop {
                let n = match state.v_circuit {
                    true => {
                        // At most one attempt per server over TCP.
                        tries = statp.retry;
                        send_vc(statp, query, ans, ns, &mut state)
                    }
                    false => {
                        let n = send_dg(statp, query, ans, ns, tries, &mut state);
                        if n > 0 && state.v_circuit {
                            continue;
                        }
                        n
                    }
                };
                break n;
            };
            if n < 0 {
                nclose(statp);
                crate::errno::set(state.terrno);
                return Err(());
            }
            if n > 0 {
                if statp.options & RES_STAYOPEN == 0 || state.v_circuit {
                    nclose(statp);
                }
                return Ok(n as usize);
            }
            ns += 1;
        }
        tries += 1;
    }
    nclose(statp);
    let errno = match (state.v_circuit, state.gotsomewhere) {
        (false, false) => libc::ECONNREFUSED,
        (false, true) => libc::ETIMEDOUT,
        (true, _) => state.terrno,
    };
    crate::errno::set(errno);
    Err(())
}

/// `int res_nsend(res_state statp, const u_char *buf, int buflen, u_char
/// *ans, int anssiz)`
///
/// # Safety
///
/// `statp` is a `struct __res_state`, `buf` readable for `buflen` bytes and
/// `ans` writable for `anssiz`.
unsafe extern "C" fn res_9_nsend(
    statp: *mut ResState,
    buf: *const u8,
    buflen: c_int,
    ans: *mut u8,
    anssiz: c_int,
) -> c_int {
    if buf.is_null() || ans.is_null() || buflen < HFIXEDSZ as c_int {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    // SAFETY: the caller's obligations.
    let (statp, query, ans) = unsafe {
        (
            &mut *statp,
            std::slice::from_raw_parts(buf, buflen as usize),
            std::slice::from_raw_parts_mut(ans, anssiz.max(0) as usize),
        )
    };
    send(statp, query, ans).map_or(-1, |n| n as c_int)
}

/// `int res_nquery(res_state statp, const char *name, int class, int type,
/// u_char *answer, int anslen)`: the answer's length, or -1 with `h_errno`
/// saying why.
///
/// # Safety
///
/// `statp` is a `struct __res_state`, `name` a C string, and `answer`
/// writable for `anslen` bytes.
unsafe extern "C" fn res_9_nquery(
    statp: *mut ResState,
    name: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    // SAFETY: the caller's obligations.
    let (statp, name) = unsafe { (&mut *statp, CStr::from_ptr(name).to_bytes()) };
    let answer = match answer.is_null() {
        true => &mut [][..],
        // SAFETY: the caller's obligation.
        false => unsafe { std::slice::from_raw_parts_mut(answer, anslen.max(0) as usize) },
    };
    let oflags = statp.flags;
    let mut retried = false;
    loop {
        if answer.len() >= 4 {
            answer[3] &= 0xf0;
        }
        let mut buf = [0u8; MAXPACKET];
        let mut n = mkquery(statp, QUERY, name, class, kind, None, &mut buf);
        if let Some(len) = n
            && statp.flags & RES_F_EDNS0ERR == 0
            && statp.options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0
        {
            n = add_opt(statp, len, &mut buf, answer.len());
        }
        let Some(n) = n else {
            set_h_errno(statp, NO_RECOVERY);
            return -1;
        };
        let Ok(n) = send(statp, &buf[..n], answer) else {
            // A server that choked on EDNS0: ask once more without it.
            // libresolv's test stays true after its retry, which would ask
            // forever of servers that then stop answering at all.
            if statp.options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0
                && (oflags ^ statp.flags) & RES_F_EDNS0ERR != 0
                && !retried
            {
                statp.flags |= RES_F_EDNS0ERR;
                retried = true;
                continue;
            }
            set_h_errno(statp, TRY_AGAIN);
            return -1;
        };
        let rcode = rcode(answer);
        let ancount = get16(answer, 6).unwrap_or(0);
        if rcode != NOERROR || ancount == 0 {
            set_h_errno(
                statp,
                match rcode {
                    NXDOMAIN => HOST_NOT_FOUND,
                    SERVFAIL => TRY_AGAIN,
                    NOERROR => NO_DATA,
                    _ => NO_RECOVERY,
                },
            );
            return -1;
        }
        return n as c_int;
    }
}

exports::exports! {
    functions {
        "res_9_init" => res_9_init,
        "res_9_close" => res_9_close,
        "res_9_ninit" => res_9_ninit,
        "res_9_nclose" => res_9_nclose,
        "res_9_ndestroy" => res_9_ndestroy,
        "res_9_getservers" => res_9_getservers,
        "res_9_setservers" => res_9_setservers,
        "res_9_nquery" => res_9_nquery,
        "res_9_nmkquery" => res_9_nmkquery,
        "res_9_nsend" => res_9_nsend,
        "res_9_ns_initparse" => res_9_ns_initparse,
        "res_9_ns_parserr" => res_9_ns_parserr,
        "res_9_ns_skiprr" => res_9_ns_skiprr,
        "res_9_dn_expand" => res_9_dn_expand,
        "res_9_dn_skipname" => res_9_dn_skipname,
        "res_9_ns_name_uncompress" => res_9_ns_name_uncompress,
    }
    data {
        // `_res_9_ns_flagdata`, with Mach-O's underscore.
        "__res_9_ns_flagdata" => &raw const NS_FLAGDATA as usize as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(name: &[c_char]) -> String {
        // SAFETY: a NUL-terminated buffer.
        unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    /// Escapes go both ways, and the root is "." on its own.
    #[test]
    fn names_round_trip_through_the_wire_form() {
        let wire = name_pton(br"a\.b.c\032d.example.", NS_MAXCDNAME).unwrap();
        assert_eq!(wire, b"\x03a.b\x03c d\x07example\x00");
        assert_eq!(
            name_ntop(&wire, NS_MAXDNAME).unwrap(),
            b"a\\.b.c\\032d.example\0"
        );
        assert_eq!(
            name_pton(b"example", NS_MAXCDNAME).unwrap(),
            b"\x07example\x00"
        );
        assert_eq!(name_ntop(b"\x00", NS_MAXDNAME).unwrap(), b".\0");
        assert!(name_pton(b"a..b", NS_MAXCDNAME).is_none(), "an empty label");
        assert!(
            name_pton(&[b'x'; 64], NS_MAXCDNAME).is_none(),
            "a label of 64"
        );
        assert!(name_ntop(&wire, 5).is_none(), "no room");
    }

    /// A pointer is followed, counted as two bytes where it stands, and a
    /// pointer back at itself is a loop rather than a hang.
    #[test]
    fn a_compressed_name_unpacks_and_a_loop_is_refused() {
        let mut msg = vec![0u8; HFIXEDSZ];
        msg.extend_from_slice(b"\x07example\x04test\x00");
        msg.extend_from_slice(b"\x03www\xc0\x0c");
        let (wire, used) = name_unpack(&msg, 26, NS_MAXCDNAME).unwrap();
        assert_eq!(wire, b"\x03www\x07example\x04test\x00");
        assert_eq!(used, 6);
        assert_eq!(
            expand(&msg, 26, NS_MAXDNAME).unwrap().0,
            b"www.example.test\0"
        );
        assert_eq!(name_skip(&msg, 26), Some(32));
        let looped = [&[0u8; HFIXEDSZ][..], b"\xc0\x0c"].concat();
        assert!(name_unpack(&looped, HFIXEDSZ, NS_MAXCDNAME).is_none());
        assert_eq!(
            same_name(b"WWW.Example.test.", b"www.example.test"),
            Some(true)
        );
        assert_eq!(same_name(br"a\.", b"a"), Some(false));
    }

    /// An answer to `www.example.test A`: one question, a CNAME and an A.
    fn response(id: [u8; 2], question: &[u8]) -> Vec<u8> {
        let mut msg = id.to_vec();
        msg.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        msg.extend_from_slice(question);
        // www.example.test CNAME example.test
        msg.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x10]);
        // example.test A 192.0.2.7
        msg.extend_from_slice(&[0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 192, 0, 2, 7]);
        msg
    }

    const QUESTION: &[u8] = b"\x03www\x07example\x04test\x00\x00\x01\x00\x01";

    #[test]
    fn a_message_parses_record_by_record() {
        let msg = response([0x12, 0x34], QUESTION);
        // SAFETY: zero is a valid handle and record.
        let mut handle: NsMsg = unsafe { std::mem::zeroed() };
        let mut rr: NsRr = unsafe { std::mem::zeroed() };
        // SAFETY: a message this test owns, and live outputs.
        unsafe {
            assert_eq!(
                res_9_ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle),
                0
            );
            assert_eq!(
                (handle.id, handle.flags, handle.counts),
                (0x1234, 0x8180, [1, 2, 0, 0])
            );
            assert_eq!(res_9_ns_parserr(&mut handle, NS_S_QD, 0, &mut rr), 0);
            assert_eq!(
                (text(&rr.name), rr.kind, rr.rdata),
                ("www.example.test".into(), 1, std::ptr::null())
            );
            // Out of order: the second answer first, then the first.
            assert_eq!(res_9_ns_parserr(&mut handle, 1, 1, &mut rr), 0);
            assert_eq!(
                (text(&rr.name).as_str(), rr.kind, rr.ttl, rr.rdlength),
                ("example.test", 1, 3600, 4)
            );
            assert_eq!(std::slice::from_raw_parts(rr.rdata, 4), [192, 0, 2, 7]);
            assert_eq!(res_9_ns_parserr(&mut handle, 1, 0, &mut rr), 0);
            assert_eq!((text(&rr.name).as_str(), rr.kind), ("www.example.test", 5));
            let mut target = [0 as c_char; NS_MAXDNAME];
            let n = res_9_dn_expand(
                msg.as_ptr(),
                msg.as_ptr().add(msg.len()),
                rr.rdata,
                target.as_mut_ptr(),
                NS_MAXDNAME as c_int,
            );
            assert_eq!((n, text(&target).as_str()), (2, "example.test"));

            assert_eq!(res_9_ns_parserr(&mut handle, 1, 2, &mut rr), -1);
            assert_eq!(crate::errno::get(), libc::ENODEV);
            assert_eq!(res_9_ns_parserr(&mut handle, 4, 0, &mut rr), -1);
            assert_eq!(crate::errno::get(), libc::ENODEV);
            // A count the records do not fill.
            let short = &msg[..msg.len() - 3];
            assert_eq!(
                res_9_ns_initparse(short.as_ptr(), short.len() as c_int, &mut handle),
                -1
            );
            assert_eq!(crate::errno::get(), libc::EMSGSIZE);
        }
    }

    fn fresh_state() -> Box<ResState> {
        // SAFETY: zero is what `res_ninit` starts from.
        Box::new(unsafe { std::mem::zeroed() })
    }

    /// `res_getservers` answers from the extension, so an IPv6 server comes
    /// back whole; `res_setservers` keeps only the families it knows.
    #[test]
    fn servers_are_read_back_and_replaced_as_res_init_c_does() {
        let mut statp = fresh_state();
        let conf = "nameserver 192.0.2.1\nnameserver 2001:db8::53\n";
        assert_eq!(vinit(&mut statp, conf), 0);
        let mut set = [SockaddrUnion { space: [0xee; 128] }; 3];
        // SAFETY: a state `vinit` filled, and room for three.
        assert_eq!(
            unsafe { res_9_getservers(&mut *statp, set.as_mut_ptr(), 3) },
            2
        );
        // SAFETY: the members `res_getservers` wrote.
        let (first, second) = unsafe { (set[0].sin, set[1].sin6) };
        assert_eq!(
            (first.family, first.addr, first.port),
            (2, [192, 0, 2, 1], 53u16.to_be_bytes())
        );
        assert_eq!(second.family, DARWIN_AF_INET6);
        assert_eq!(
            second.addr,
            "2001:db8::53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        // SAFETY: untouched past the servers there are.
        assert_eq!(unsafe { set[2].space[1] }, 0xee);
        // Fewer slots than servers: as many as fit, and the count there is.
        let mut one = [SockaddrUnion { space: [0; 128] }; 1];
        // SAFETY: as above.
        assert_eq!(
            unsafe { res_9_getservers(&mut *statp, one.as_mut_ptr(), 1) },
            2
        );

        let unknown = SockaddrUnion { space: [0; 128] };
        let replacement = [unknown, set[1], set[0]];
        // SAFETY: a state, and three entries.
        unsafe { res_9_setservers(&mut *statp, replacement.as_ptr(), 3) };
        assert_eq!(statp.nscount, 2, "the zero family is passed over");
        assert_eq!(
            statp.nsaddr_list[0].family, 0,
            "an IPv6 server does not fit"
        );
        assert_eq!(statp.nsaddr_list[1].addr, [192, 0, 2, 1]);
        assert_eq!(
            socket_addr(&server_addr(&statp, 0)),
            Some("[2001:db8::53]:53".parse().unwrap())
        );
        // SAFETY: a state `vinit` filled.
        unsafe { res_9_ndestroy(&mut *statp) };
    }

    #[test]
    fn the_configuration_is_read_as_libresolv_reads_it() {
        let mut statp = fresh_state();
        let conf = "# comment\nnameserver 192.0.2.1\nnameserver 2001:db8::53\n\
                    nameserver 192.0.2.3 # trailing\nnameserver 192.0.2.4\n\
                    search corp.example.test example.test\noptions ndots:3 timeout:2 attempts:9 rotate\n";
        assert_eq!(vinit(&mut statp, conf), 0);
        assert_eq!(statp.nscount, 3, "MAXNS");
        assert_eq!(
            (statp.nsaddr_list[0].family, statp.nsaddr_list[0].addr),
            (2, [192, 0, 2, 1])
        );
        assert_eq!(statp.nsaddr_list[0].port, 53u16.to_be_bytes());
        assert_eq!(
            statp.nsaddr_list[1].family, 0,
            "an IPv6 server does not fit"
        );
        assert_eq!(
            socket_addr(&server_addr(&statp, 1)),
            Some("[2001:db8::53]:53".parse().unwrap())
        );
        assert_eq!(statp.nsaddr_list[2].addr, [192, 0, 2, 3]);
        // SAFETY: `dnsrch` points into `defdname`.
        let search: Vec<String> = statp
            .dnsrch
            .iter()
            .take_while(|p| !p.is_null())
            .map(|&p| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
            .collect();
        assert_eq!(search, ["corp.example.test", "example.test"]);
        assert_eq!(
            (statp.ndots_nsort & 0xf, statp.retrans, statp.retry),
            (3, 2, RES_MAXRETRY)
        );
        assert_eq!(
            statp.options & (RES_ROTATE | RES_INIT | RES_DEFAULT),
            RES_ROTATE | RES_INIT | RES_DEFAULT
        );
        assert_eq!(statp.vcsock, -1);
        // SAFETY: a state `vinit` filled.
        unsafe { res_9_ndestroy(&mut *statp) };
        assert!(statp.ext.is_null());

        // With no servers named, the local one; a domain gives its parents
        // with two labels or more to search.
        let mut statp = fresh_state();
        vinit(&mut statp, "domain a.b.example.test\n");
        assert_eq!(statp.nscount, 2);
        assert_eq!(statp.nsaddr_list[0].addr, [0, 0, 0, 0]);
        let search: Vec<String> = statp
            .dnsrch
            .iter()
            .take_while(|p| !p.is_null())
            // SAFETY: as above.
            .map(|&p| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            search,
            ["a.b.example.test", "b.example.test", "example.test"]
        );
        // SAFETY: as above.
        unsafe { res_9_ndestroy(&mut *statp) };
    }

    /// A name server on loopback, answering `www.example.test A` over UDP -
    /// truncated when `truncate` - and over TCP; any other name is NXDOMAIN.
    fn serve(truncate: bool) -> (u16, std::thread::JoinHandle<()>) {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        let answer = move |query: &[u8]| {
            let question = &query[HFIXEDSZ..];
            let question = &question[..question.len().min(QUESTION.len())];
            if question == QUESTION {
                response([query[0], query[1]], QUESTION)
            } else {
                let mut msg = vec![query[0], query[1], 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
                msg.extend_from_slice(&query[HFIXEDSZ..]);
                msg
            }
        };
        let server = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            let mut reply = answer(&buf[..n]);
            if truncate {
                reply.truncate(HFIXEDSZ + QUESTION.len());
                reply[2] |= 0x02;
                reply[7] = 0;
            }
            udp.send_to(&reply, from).unwrap();
            if truncate {
                let (mut stream, _) = tcp.accept().unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query = vec![0u8; u16::from_be_bytes(length) as usize];
                stream.read_exact(&mut query).unwrap();
                let reply = answer(&query);
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        (port, server)
    }

    /// `res_ninit`, then the server written over the first one, as callers
    /// that pick their own servers do.
    fn state_for(port: u16) -> Box<ResState> {
        let mut statp = fresh_state();
        // SAFETY: a writable state.
        assert_eq!(unsafe { res_9_ninit(&mut *statp) }, 0);
        statp.nsaddr_list[0] = SockaddrIn {
            len: 16,
            family: DARWIN_AF_INET,
            port: port.to_be_bytes(),
            addr: [127, 0, 0, 1],
            zero: [0; 8],
        };
        statp.nscount = 1;
        statp.retry = 1;
        statp.retrans = 2;
        statp
    }

    fn first_address(answer: &[u8]) -> [u8; 4] {
        // SAFETY: zero is a valid handle and record.
        let mut handle: NsMsg = unsafe { std::mem::zeroed() };
        let mut rr: NsRr = unsafe { std::mem::zeroed() };
        // SAFETY: an answer this test owns, and live outputs.
        unsafe {
            assert_eq!(
                res_9_ns_initparse(answer.as_ptr(), answer.len() as c_int, &mut handle),
                0
            );
            for i in 0..handle.counts[1] as c_int {
                assert_eq!(res_9_ns_parserr(&mut handle, 1, i, &mut rr), 0);
                if rr.kind == 1 {
                    return std::slice::from_raw_parts(rr.rdata, 4).try_into().unwrap();
                }
            }
        }
        panic!("no address in the answer");
    }

    #[test]
    fn a_query_is_answered_by_the_server_the_caller_chose() {
        for truncate in [false, true] {
            let (port, server) = serve(truncate);
            let mut statp = state_for(port);
            let mut answer = [0u8; 512];
            // SAFETY: a state `res_ninit` filled, and a buffer of the size given.
            let n = unsafe {
                res_9_nquery(
                    &mut *statp,
                    c"www.example.test".as_ptr(),
                    1,
                    1,
                    answer.as_mut_ptr(),
                    512,
                )
            };
            server.join().unwrap();
            assert!(n > HFIXEDSZ as c_int, "truncate: {truncate}");
            assert_eq!(first_address(&answer[..n as usize]), [192, 0, 2, 7]);
            // SAFETY: as above.
            unsafe { res_9_ndestroy(&mut *statp) };
        }
    }

    #[test]
    fn a_name_that_does_not_exist_is_host_not_found() {
        let (port, server) = serve(false);
        let mut statp = state_for(port);
        let mut answer = [0u8; 512];
        // SAFETY: as above.
        let n = unsafe {
            res_9_nquery(
                &mut *statp,
                c"nowhere.example.test".as_ptr(),
                1,
                1,
                answer.as_mut_ptr(),
                512,
            )
        };
        server.join().unwrap();
        assert_eq!((n, statp.res_h_errno), (-1, HOST_NOT_FOUND));
        assert_eq!(
            rcode(&answer),
            NXDOMAIN,
            "the answer is still there to read"
        );
        // SAFETY: as above.
        unsafe { res_9_ndestroy(&mut *statp) };
    }

    /// No server at all: the refusal comes back at once, not after a
    /// timeout.
    #[test]
    fn a_server_that_is_not_there_is_refused_quickly() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut statp = state_for(port);
        let mut answer = [0u8; 512];
        let start = Instant::now();
        // SAFETY: as above.
        let n = unsafe {
            res_9_nquery(
                &mut *statp,
                c"www.example.test".as_ptr(),
                1,
                1,
                answer.as_mut_ptr(),
                512,
            )
        };
        assert_eq!((n, statp.res_h_errno), (-1, TRY_AGAIN));
        assert_eq!(crate::errno::get(), libc::ECONNREFUSED);
        assert!(start.elapsed() < Duration::from_secs(2));
        // SAFETY: as above.
        unsafe { res_9_ndestroy(&mut *statp) };
    }
}
