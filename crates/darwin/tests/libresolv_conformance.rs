//! libresolv conformance: the cases of Apple's own libresolv test suite
//! (apple-oss-distributions/libresolv at libresolv-96, `tests/libresolv_test.c`),
//! ported one for one and run against what a guest binds, plus adaptations of
//! the ones whose calls are unbound to the context-taking calls that are.
//!
//! The network cases ask the host's name servers about apple.com, as upstream
//! does, so they need a network.
//!
//! ```text
//! cargo test -p darwin --test libresolv_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]
#![allow(clippy::missing_safety_doc)]

mod conformance;

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::net::Ipv4Addr;

use conformance::{Case, Kind, Stop, T, imports};

const UPSTREAM: &str = "libresolv-96 tests/libresolv_test.c";

// `<arpa/nameser.h>` and `<resolv.h>`, as Apple's libresolv-96 has them.

const MAXDNAME: usize = 1025;
const MAXNS: c_int = 3;
const RES_MAXNDOTS: u8 = 15;
const MAXRESOLVSORT: u8 = 10;
const NS_MAXDNAME: usize = 1025;
const QUERY: c_int = 0;
const NS_C_IN: c_int = 1;
const NS_T_A: c_int = 1;
const NS_T_NS: c_int = 2;
const NS_T_SOA: c_int = 6;
const NS_T_MX: c_int = 15;
const NS_T_TXT: c_int = 16;
const NS_T_AAAA: c_int = 28;
const NS_S_AN: c_int = 1;
const NS_F_RCODE: usize = 9;
const NS_R_NOERROR: u16 = 0;
const PATH_RESCONF: &CStr = c"/etc/resolv.conf";
const MDNS_HANDLE_NAME: &CStr = c"*MDNS*";

const DNS_PRINT_ALL: u16 = 0x0001
    | 0x0002
    | 0x0004
    | 0x0008
    | 0x0010
    | 0x0020
    | 0x0040
    | 0x0080
    | 0x0100
    | 0x0200
    | 0x0400
    | 0x0800
    | 0x1000
    | 0x2000;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    len: u8,
    family: u8,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ext {
    nscount: u16,
    nstimes: [u16; 3],
    nssocks: [c_int; 3],
    ext: *mut c_void,
}

#[repr(C)]
union ExtUnion {
    pad: [u8; 72 - 4 * 4 - 3 * 8],
    ext: Ext,
}

/// `struct __res_state`.
#[repr(C)]
struct ResState {
    retrans: c_int,
    retry: c_int,
    options: c_ulong,
    nscount: c_int,
    nsaddr_list: [SockaddrIn; 3],
    id: u16,
    dnsrch: [*mut c_char; 7],
    defdname: [c_char; 256],
    pfcode: c_ulong,
    /// `unsigned ndots:4, nsort:4`, the first in the low bits.
    ndots_nsort: u8,
    unused: [c_char; 3],
    sort_list: [[u32; 2]; 10],
    qhook: *mut c_void,
    rhook: *mut c_void,
    res_h_errno: c_int,
    vcsock: c_int,
    flags: u32,
    pad: u32,
    u: ExtUnion,
    rnd: *mut u8,
}

const _: () = assert!(size_of::<ResState>() == 552);

/// `ns_msg`
#[repr(C)]
struct NsMsg {
    msg: *const u8,
    eom: *const u8,
    id: u16,
    flags: u16,
    counts: [u16; 4],
    sections: [*const u8; 4],
    sect: c_int,
    rrnum: c_int,
    msg_ptr: *const u8,
}

/// `ns_rr`
#[repr(C)]
struct NsRr {
    name: [c_char; NS_MAXDNAME],
    kind: u16,
    rr_class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: *const u8,
}

fn zeroed<V>() -> V {
    // SAFETY: each type this is used for is plain data, valid zeroed.
    unsafe { std::mem::zeroed() }
}

/// `ns_rr_name`
fn rr_name(rr: &NsRr) -> String {
    // SAFETY: `ns_parserr` writes a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(rr.name.as_ptr()) }.to_string_lossy();
    match name.is_empty() {
        true => ".".to_string(),
        false => name.into_owned(),
    }
}

/// The record's data as `inet_ntoa` prints its first four bytes.
fn rr_addr(rr: &NsRr) -> String {
    // SAFETY: `ns_parserr` points `rdata` into the message; the test copies
    // four bytes out of it whatever the record's length, as upstream does.
    let bytes = unsafe { std::ptr::read_unaligned(rr.rdata.cast::<[u8; 4]>()) };
    Ipv4Addr::from(bytes).to_string()
}

type FlagData = [[c_int; 2]; 16];

/// `ns_msg_getflag`, through the `_ns_flagdata` the macro reads.
fn msg_getflag(flagdata: *const FlagData, msg: &NsMsg, flag: usize) -> u16 {
    // SAFETY: the table Darwin publishes, `ns_f_max` entries long and more.
    let [mask, shift] = unsafe { (*flagdata)[flag] };
    ((msg.flags as c_int & mask) >> shift) as u16
}

struct Record {
    dname: &'static CStr,
    kind: c_int,
}

const RECORDS: [Record; 6] = [
    Record {
        dname: c"apple.com",
        kind: NS_T_A,
    },
    Record {
        dname: c"apple.com",
        kind: NS_T_AAAA,
    },
    Record {
        dname: c"apple.com",
        kind: NS_T_SOA,
    },
    Record {
        dname: c"apple.com",
        kind: NS_T_MX,
    },
    Record {
        dname: c"apple.com",
        kind: NS_T_TXT,
    },
    Record {
        dname: c"apple.com",
        kind: NS_T_NS,
    },
];

type QueryFn = unsafe extern "C" fn(*const c_char, c_int, c_int, *mut u8, c_int) -> c_int;
type NQueryFn =
    unsafe extern "C" fn(*mut ResState, *const c_char, c_int, c_int, *mut u8, c_int) -> c_int;
type InitParseFn = unsafe extern "C" fn(*const u8, c_int, *mut NsMsg) -> c_int;
type ParseRrFn = unsafe extern "C" fn(*mut NsMsg, c_int, c_int, *mut NsRr) -> c_int;
type SprintRrFn = unsafe extern "C" fn(
    *const NsMsg,
    *const NsRr,
    *const c_char,
    *const c_char,
    *mut c_char,
    usize,
) -> c_int;
type UncompressFn =
    unsafe extern "C" fn(*const u8, *const u8, *const u8, *mut c_char, usize) -> c_int;
type MkQueryFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    c_int,
    c_int,
    *const u8,
    c_int,
    *const u8,
    *mut u8,
    c_int,
) -> c_int;
type NMkQueryFn = unsafe extern "C" fn(
    *mut ResState,
    c_int,
    *const c_char,
    c_int,
    c_int,
    *const u8,
    c_int,
    *const u8,
    *mut u8,
    c_int,
) -> c_int;
type SendFn = unsafe extern "C" fn(*const u8, c_int, *mut u8, c_int) -> c_int;
type NSendFn = unsafe extern "C" fn(*mut ResState, *const u8, c_int, *mut u8, c_int) -> c_int;
type StateFn = unsafe extern "C" fn(*mut ResState) -> c_int;
type VoidStateFn = unsafe extern "C" fn(*mut ResState);
type Get16Fn = unsafe extern "C" fn(*const u8) -> u32;
type Get32Fn = unsafe extern "C" fn(*const u8) -> c_ulong;
type Put16Fn = unsafe extern "C" fn(u32, *mut u8);
type Put32Fn = unsafe extern "C" fn(c_ulong, *mut u8);
type ResInitFn = unsafe extern "C" fn() -> c_int;
type ResStateFn = unsafe extern "C" fn() -> *mut ResState;
type DnsOpenFn = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type DnsFreeFn = unsafe extern "C" fn(*mut c_void);
type DnsCountFn = unsafe extern "C" fn(*mut c_void) -> u32;
type DnsDomainFn = unsafe extern "C" fn(*mut c_void, u32) -> *mut c_char;
type DnsQueryFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    u32,
    u32,
    *mut c_char,
    u32,
    *mut c_void,
    *mut u32,
) -> i32;
type DnsParseFn = unsafe extern "C" fn(*const c_char, u32) -> *mut c_void;
type DnsFreeReplyFn = unsafe extern "C" fn(*mut c_void);
type DnsPrintFn = unsafe extern "C" fn(*const c_void, *mut c_void, u16);
type DnsLookupFn = unsafe extern "C" fn(*mut c_void, *const c_char, u32, u32) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);

/// `atf_tc_fail("no valid result")`, after the `switch (h_errno)` every
/// branch of which fails the same way.
fn no_valid_result() -> Result<(), Stop> {
    imports! { h_errno: *const c_int = "_h_errno"; }
    let code = h_errno.get()?;
    // SAFETY: the `int` Darwin publishes.
    Err(Stop::Fail(format!(
        "no valid result (h_errno {})",
        unsafe { *code }
    )))
}

/// The answer section of a response, checked as `test_res_search_a` and
/// `check_answer` check it: every record an A record for apple.com at
/// 17.253.144.10.
fn check_answer(t: &mut T, answer: &mut [u8; MAXDNAME], sprint: bool) -> Result<(), Stop> {
    imports! {
        initparse: InitParseFn = "_res_9_ns_initparse";
        parserr: ParseRrFn = "_res_9_ns_parserr";
        sprintrr: SprintRrFn = "_res_9_ns_sprintrr";
        flagdata: *const FlagData = "__res_9_ns_flagdata";
    }
    let mut msg: NsMsg = zeroed();
    // Upstream's test, as written: `ns_initparse` is handed the whole buffer
    // rather than the response's length, which it reports as a message with
    // bytes after its end - and only success fails the test.
    // SAFETY: a buffer of the length given, and a handle to fill.
    if unsafe { (initparse.get()?)(answer.as_ptr(), MAXDNAME as c_int, &mut msg) } == 0 {
        return Err(Stop::Fail("ns_initparse".into()));
    }
    if msg_getflag(flagdata.get()?, &msg, NS_F_RCODE) != NS_R_NOERROR {
        return Err(Stop::Fail("nxdomain".into()));
    }
    for i in 0..msg.counts[NS_S_AN as usize] as c_int {
        let mut rr: NsRr = zeroed();
        // SAFETY: the handle parsed above, and a record to fill.
        if unsafe { (parserr.get()?)(&mut msg, NS_S_AN, i, &mut rr) } != 0 {
            return Err(Stop::Fail("parsing msg to rr".into()));
        }
        match rr.kind as c_int {
            NS_T_A => {
                if sprint {
                    let mut outname = [0 as c_char; MAXDNAME];
                    // SAFETY: as upstream calls it, into a buffer of the size given.
                    unsafe {
                        (sprintrr.get()?)(
                            &msg,
                            &rr,
                            std::ptr::null(),
                            std::ptr::null(),
                            outname.as_mut_ptr(),
                            outname.len(),
                        )
                    };
                }
                t.require(rr_name(&rr) == "apple.com", || {
                    format!("server name is not correct: {}", rr_name(&rr))
                })?;
                let addr = rr_addr(&rr);
                t.check(addr == "17.253.144.10", || {
                    format!("unexpected server adress {addr}")
                });
            }
            _ => {
                return Err(Stop::Fail(format!(
                    "unexpected response (type {})",
                    rr.kind
                )));
            }
        }
    }
    Ok(())
}

/// `test_res_search`'s loop over the six records, given what makes the query.
fn search_records(
    t: &mut T,
    sprint: bool,
    mut ask: impl FnMut(&Record, &mut [u8; MAXDNAME]) -> Result<c_int, Stop>,
) -> Result<(), Stop> {
    imports! {
        initparse: InitParseFn = "_res_9_ns_initparse";
        parserr: ParseRrFn = "_res_9_ns_parserr";
        sprintrr: SprintRrFn = "_res_9_ns_sprintrr";
        flagdata: *const FlagData = "__res_9_ns_flagdata";
    }
    for record in &RECORDS {
        let mut answer = [0u8; MAXDNAME];
        let result = ask(record, &mut answer)?;
        if result < 0 {
            return no_valid_result();
        }
        if result as usize > MAXDNAME {
            // A response libresolv truncates into the buffer, which
            // `ns_initparse` then cannot get through - Apple's as well.
            t.note(format!(
                "the response for type {} is {result} bytes, longer than the test's {MAXDNAME}-byte buffer",
                record.kind
            ));
        }
        let mut msg: NsMsg = zeroed();
        // SAFETY: as in `check_answer`.
        if unsafe { (initparse.get()?)(answer.as_ptr(), MAXDNAME as c_int, &mut msg) } == 0 {
            return Err(Stop::Fail("ns_initparse".into()));
        }
        if msg_getflag(flagdata.get()?, &msg, NS_F_RCODE) != NS_R_NOERROR {
            return Err(Stop::Fail("nxdomain".into()));
        }
        let mut valid = false;
        for m in 0..msg.counts[NS_S_AN as usize] as c_int {
            let mut rr: NsRr = zeroed();
            // SAFETY: as in `check_answer`.
            if unsafe { (parserr.get()?)(&mut msg, NS_S_AN, m, &mut rr) } != 0 {
                return Err(Stop::Fail("parsing msg to rr".into()));
            }
            if rr.kind as c_int == record.kind {
                valid = true;
                if sprint {
                    let mut outname = [0 as c_char; MAXDNAME];
                    // SAFETY: as in `check_answer`.
                    unsafe {
                        (sprintrr.get()?)(
                            &msg,
                            &rr,
                            std::ptr::null(),
                            std::ptr::null(),
                            outname.as_mut_ptr(),
                            outname.len(),
                        )
                    };
                }
                let want = record.dname.to_string_lossy();
                t.require(rr_name(&rr) == want, || {
                    format!(
                        "server name is not correct: {} for type {}",
                        rr_name(&rr),
                        record.kind
                    )
                })?;
                break;
            }
        }
        if !valid {
            return Err(Stop::Fail(format!(
                "no valid result found for type {}",
                record.kind
            )));
        }
    }
    Ok(())
}

/// `test_res_search_mx`'s body, given what makes the query and reads a
/// 16-bit field.
fn search_mx(
    t: &mut T,
    ask: impl FnOnce(&mut [u8; MAXDNAME]) -> Result<c_int, Stop>,
    get16: impl Fn(*const u8) -> Result<u32, Stop>,
) -> Result<(), Stop> {
    imports! {
        initparse: InitParseFn = "_res_9_ns_initparse";
        parserr: ParseRrFn = "_res_9_ns_parserr";
        uncompress: UncompressFn = "_res_9_ns_name_uncompress";
        flagdata: *const FlagData = "__res_9_ns_flagdata";
    }
    let mut answer = [0u8; MAXDNAME];
    if ask(&mut answer)? < 0 {
        return no_valid_result();
    }
    let mut msg: NsMsg = zeroed();
    // SAFETY: as in `check_answer`.
    if unsafe { (initparse.get()?)(answer.as_ptr(), MAXDNAME as c_int, &mut msg) } == 0 {
        return Err(Stop::Fail("ns_initparse".into()));
    }
    if msg_getflag(flagdata.get()?, &msg, NS_F_RCODE) != NS_R_NOERROR {
        return Err(Stop::Fail("nxdomain".into()));
    }
    t.require(msg.counts[NS_S_AN as usize] > 0, || {
        "ns_msg_count(msg, ns_s_an) > 0".into()
    })?;
    for i in 0..msg.counts[NS_S_AN as usize] as c_int {
        let mut rr: NsRr = zeroed();
        // SAFETY: as in `check_answer`.
        if unsafe { (parserr.get()?)(&mut msg, NS_S_AN, i, &mut rr) } != 0 {
            return Err(Stop::Fail("parsing msg to rr".into()));
        }
        match rr.kind as c_int {
            NS_T_MX => {
                let _pref = get16(rr.rdata)?;
                let mut outname = [0 as c_char; MAXDNAME];
                // SAFETY: the exchange name two bytes into the record, inside
                // the message the handle bounds.
                let result = unsafe {
                    (uncompress.get()?)(
                        msg.msg,
                        msg.eom,
                        rr.rdata.add(2),
                        outname.as_mut_ptr(),
                        outname.len(),
                    )
                };
                if result < 0 {
                    return Err(Stop::Fail("uncompressing name to printable".into()));
                }
            }
            _ => {
                return Err(Stop::Fail(format!(
                    "unexpected response (type {})",
                    rr.kind
                )));
            }
        }
    }
    Ok(())
}

/// `check_res_state_init`
fn check_res_state_init(t: &mut T, statp: &ResState) -> Result<(), Stop> {
    t.require(statp.retrans >= 0, || {
        format!("retrans >= 0: {}", statp.retrans)
    })?;
    t.require(statp.retry >= 0, || format!("retry >= 0: {}", statp.retry))?;
    t.require((0..=MAXNS).contains(&statp.nscount), || {
        format!("nscount in 0..=MAXNS: {}", statp.nscount)
    })?;
    let ndots = statp.ndots_nsort & 0xf;
    let nsort = statp.ndots_nsort >> 4;
    t.require(ndots <= RES_MAXNDOTS, || {
        format!("ndots <= RES_MAXNDOTS: {ndots}")
    })?;
    t.require(nsort <= MAXRESOLVSORT, || {
        format!("nsort <= MAXRESOLVSORT: {nsort}")
    })?;
    for i in 0..3 {
        t.require(statp.unused[i] == 0, || {
            format!("unused[{i}] == 0: {}", statp.unused[i])
        })?;
    }
    t.require(statp.qhook.is_null(), || "qhook == NULL".into())?;
    t.require(statp.rhook.is_null(), || "rhook == NULL".into())?;
    t.require(statp.res_h_errno == 0, || {
        format!("res_h_errno == 0: {}", statp.res_h_errno)
    })?;
    t.require(statp.vcsock == -1, || {
        format!("_vcsock == -1: {}", statp.vcsock)
    })?;
    t.require(statp.pad == 9, || {
        format!("_pad == 9 (the version): {}", statp.pad)
    })?;
    // SAFETY: the `_ext` arm, which `res_ninit` fills.
    let ext_nscount = unsafe { statp.u.ext.nscount };
    t.require(ext_nscount as c_int <= MAXNS, || {
        format!("_u._ext.nscount <= MAXNS: {ext_nscount}")
    })?;
    Ok(())
}

/// A context from `res_ninit`, for the adaptations.
struct Context {
    state: Box<ResState>,
    ndestroy: VoidStateFn,
}

impl Context {
    fn new() -> Result<Context, Stop> {
        imports! {
            ninit: StateFn = "_res_9_ninit";
            ndestroy: VoidStateFn = "_res_9_ndestroy";
        }
        let mut state: Box<ResState> = Box::new(zeroed());
        // SAFETY: a writable `struct __res_state`.
        if unsafe { (ninit.get()?)(&mut *state) } != 0 {
            return Err(Stop::Fail("res_ninit".into()));
        }
        Ok(Context {
            state,
            ndestroy: ndestroy.get()?,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context `res_ninit` set up.
        unsafe { (self.ndestroy)(&mut *self.state) };
    }
}

// The cases, in upstream's order.

fn test_res_query(t: &mut T) -> Result<(), Stop> {
    imports! { query: QueryFn = "_res_9_query"; }
    for record in &RECORDS {
        let mut answer = [0u8; MAXDNAME];
        // SAFETY: a name, and a buffer of the length given.
        let result = unsafe {
            (query.get()?)(
                record.dname.as_ptr(),
                NS_C_IN,
                record.kind,
                answer.as_mut_ptr(),
                MAXDNAME as c_int,
            )
        };
        t.require(result != -1, || {
            format!("no valid result for type {}", record.kind)
        })?;
    }
    Ok(())
}

fn adapted_res_query(t: &mut T) -> Result<(), Stop> {
    imports! { nquery: NQueryFn = "_res_9_nquery"; }
    let mut cx = Context::new()?;
    for record in &RECORDS {
        let mut answer = [0u8; MAXDNAME];
        // SAFETY: a context, a name, and a buffer of the length given.
        let result = unsafe {
            (nquery.get()?)(
                &mut *cx.state,
                record.dname.as_ptr(),
                NS_C_IN,
                record.kind,
                answer.as_mut_ptr(),
                MAXDNAME as c_int,
            )
        };
        t.require(result != -1, || {
            format!("no valid result for type {}", record.kind)
        })?;
    }
    Ok(())
}

fn test_res_search(t: &mut T) -> Result<(), Stop> {
    imports! { search: QueryFn = "_res_9_search"; }
    search_records(t, true, |record, answer| {
        // SAFETY: a name, and a buffer of the length given.
        Ok(unsafe {
            (search.get()?)(
                record.dname.as_ptr(),
                NS_C_IN,
                record.kind,
                answer.as_mut_ptr(),
                MAXDNAME as c_int,
            )
        })
    })
}

fn adapted_res_search(t: &mut T) -> Result<(), Stop> {
    imports! { nquery: NQueryFn = "_res_9_nquery"; }
    let mut cx = Context::new()?;
    search_records(t, false, |record, answer| {
        // SAFETY: as in `adapted_res_query`.
        Ok(unsafe {
            (nquery.get()?)(
                &mut *cx.state,
                record.dname.as_ptr(),
                NS_C_IN,
                record.kind,
                answer.as_mut_ptr(),
                MAXDNAME as c_int,
            )
        })
    })
}

fn test_res_search_a(t: &mut T) -> Result<(), Stop> {
    imports! { search: QueryFn = "_res_9_search"; }
    let mut answer = [0u8; MAXDNAME];
    // SAFETY: as in `test_res_search`.
    let result = unsafe {
        (search.get()?)(
            c"apple.com".as_ptr(),
            NS_C_IN,
            NS_T_A,
            answer.as_mut_ptr(),
            MAXDNAME as c_int,
        )
    };
    if result < 0 {
        return no_valid_result();
    }
    check_answer(t, &mut answer, true)
}

fn adapted_res_search_a(t: &mut T) -> Result<(), Stop> {
    imports! { nquery: NQueryFn = "_res_9_nquery"; }
    let mut cx = Context::new()?;
    let mut answer = [0u8; MAXDNAME];
    // SAFETY: as in `adapted_res_query`.
    let result = unsafe {
        (nquery.get()?)(
            &mut *cx.state,
            c"apple.com".as_ptr(),
            NS_C_IN,
            NS_T_A,
            answer.as_mut_ptr(),
            MAXDNAME as c_int,
        )
    };
    if result < 0 {
        return no_valid_result();
    }
    check_answer(t, &mut answer, false)
}

fn test_res_search_mx(t: &mut T) -> Result<(), Stop> {
    imports! {
        search: QueryFn = "_res_9_search";
        get16: Get16Fn = "_res_9_ns_get16";
    }
    search_mx(
        t,
        |answer| {
            // SAFETY: as in `test_res_search`.
            Ok(unsafe {
                (search.get()?)(
                    c"apple.com".as_ptr(),
                    NS_C_IN,
                    NS_T_MX,
                    answer.as_mut_ptr(),
                    MAXDNAME as c_int,
                )
            })
        },
        // SAFETY: two bytes of record data.
        |cp| Ok(unsafe { (get16.get()?)(cp) }),
    )
}

fn adapted_res_search_mx(t: &mut T) -> Result<(), Stop> {
    imports! { nquery: NQueryFn = "_res_9_nquery"; }
    let mut cx = Context::new()?;
    search_mx(
        t,
        |answer| {
            // SAFETY: as in `adapted_res_query`.
            Ok(unsafe {
                (nquery.get()?)(
                    &mut *cx.state,
                    c"apple.com".as_ptr(),
                    NS_C_IN,
                    NS_T_MX,
                    answer.as_mut_ptr(),
                    MAXDNAME as c_int,
                )
            })
        },
        // `NS_GET16`, the macro form, for the unbound `ns_get16`.
        // SAFETY: two bytes of record data.
        |cp| {
            Ok(
                u16::from_be_bytes(unsafe { std::ptr::read_unaligned(cp.cast::<[u8; 2]>()) })
                    as u32,
            )
        },
    )
}

fn upstream_skips(_t: &mut T) -> Result<(), Stop> {
    Err(Stop::Skip(
        "upstream: not implemented yet expected to be caught by res_query and res_search".into(),
    ))
}

fn test_res_send(t: &mut T) -> Result<(), Stop> {
    imports! {
        mkquery: MkQueryFn = "_res_9_mkquery";
        send: SendFn = "_res_9_send";
    }
    let mut query = [0u8; 1024];
    // SAFETY: a name, and a buffer of the length given.
    let result = unsafe {
        (mkquery.get()?)(
            QUERY,
            c"apple.com".as_ptr(),
            NS_C_IN,
            NS_T_A,
            std::ptr::null(),
            0,
            std::ptr::null(),
            query.as_mut_ptr(),
            query.len() as c_int,
        )
    };
    t.require(result > 0, || format!("res_mkquery: {result}"))?;
    let mut answer = [0u8; MAXDNAME];
    // SAFETY: the query made above, and a buffer of the length given.
    let result = unsafe {
        (send.get()?)(
            query.as_ptr(),
            result,
            answer.as_mut_ptr(),
            MAXDNAME as c_int,
        )
    };
    if result < 0 {
        return no_valid_result();
    }
    check_answer(t, &mut answer, true)
}

fn adapted_res_send(t: &mut T) -> Result<(), Stop> {
    imports! {
        nmkquery: NMkQueryFn = "_res_9_nmkquery";
        nsend: NSendFn = "_res_9_nsend";
    }
    let mut cx = Context::new()?;
    let mut query = [0u8; 1024];
    // SAFETY: as in `test_res_send`, with a context.
    let result = unsafe {
        (nmkquery.get()?)(
            &mut *cx.state,
            QUERY,
            c"apple.com".as_ptr(),
            NS_C_IN,
            NS_T_A,
            std::ptr::null(),
            0,
            std::ptr::null(),
            query.as_mut_ptr(),
            query.len() as c_int,
        )
    };
    t.require(result > 0, || format!("res_nmkquery: {result}"))?;
    let mut answer = [0u8; MAXDNAME];
    // SAFETY: as in `test_res_send`, with a context.
    let result = unsafe {
        (nsend.get()?)(
            &mut *cx.state,
            query.as_ptr(),
            result,
            answer.as_mut_ptr(),
            MAXDNAME as c_int,
        )
    };
    if result < 0 {
        return no_valid_result();
    }
    check_answer(t, &mut answer, false)
}

fn test_ns_get16(t: &mut T) -> Result<(), Stop> {
    imports! { get16: Get16Fn = "_res_9_ns_get16"; }
    let buf = [0x00u8, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00];
    // `short value = ns_get16(buf)`
    // SAFETY: eight bytes.
    let value = unsafe { (get16.get()?)(buf.as_ptr()) } as i16;
    t.check(value == 0, || format!("ns_get16: {value}"));
    // SAFETY: as above.
    let value = unsafe { (get16.get()?)(buf.as_ptr()) } as i16;
    t.check(value + 1 == 1, || format!("ns_get16 + 1: {}", value + 1));
    Ok(())
}

fn test_ns_get32(t: &mut T) -> Result<(), Stop> {
    imports! { get32: Get32Fn = "_res_9_ns_get32"; }
    let buf = [0x00u8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    // `long value = ns_get32(buf)`
    // SAFETY: eight bytes.
    let value = unsafe { (get32.get()?)(buf.as_ptr()) } as i64;
    t.check(value == 0, || format!("ns_get32: {value}"));
    // SAFETY: as above.
    let value = unsafe { (get32.get()?)(buf.as_ptr()) } as i64;
    t.check(value + 1 == 1, || format!("ns_get32 + 1: {}", value + 1));
    Ok(())
}

fn test_ns_put16(t: &mut T) -> Result<(), Stop> {
    imports! {
        put16: Put16Fn = "_res_9_ns_put16";
        get16: Get16Fn = "_res_9_ns_get16";
    }
    let mut buf = [0x00u8, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00];
    // SAFETY: eight bytes.
    unsafe { (put16.get()?)(0x0042, buf.as_mut_ptr()) };
    // SAFETY: as above.
    let value = unsafe { (get16.get()?)(buf.as_ptr()) };
    t.check(value == 0x0042, || {
        format!("ns_get16 after ns_put16: {value:#x}")
    });
    Ok(())
}

fn test_ns_put32(t: &mut T) -> Result<(), Stop> {
    imports! {
        put32: Put32Fn = "_res_9_ns_put32";
        get32: Get32Fn = "_res_9_ns_get32";
    }
    let mut buf = [0x00u8, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00];
    // SAFETY: eight bytes.
    unsafe { (put32.get()?)(0x0000_0042, buf.as_mut_ptr()) };
    // SAFETY: as above.
    let value = unsafe { (get32.get()?)(buf.as_ptr()) };
    t.check(value == 0x0042, || {
        format!("ns_get32 after ns_put32: {value:#x}")
    });
    Ok(())
}

/// `dump_tmp_resolvconf` and `_dns_open_tmp`.
fn dns_open_tmp(dns_open: DnsOpenFn) -> *mut c_void {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("libresolv_test_resolvconf_{}", std::process::id()));
    if std::fs::write(
        &path,
        "nameserver 1.1.1.1\noptions debug\nsearch apple.com\n",
    )
    .is_err()
    {
        return std::ptr::null_mut();
    }
    let c = CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path.
    let handle = unsafe { dns_open(c.as_ptr()) };
    let _ = std::fs::remove_file(&path);
    handle
}

fn test_dns_open_null(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
    }
    // SAFETY: null asks for the default configuration.
    let handle = unsafe { (dns_open.get()?)(std::ptr::null()) };
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    // SAFETY: the handle opened above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

fn test_dns_open_resolvconf(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
    }
    // SAFETY: a NUL-terminated path.
    let handle = unsafe { (dns_open.get()?)(PATH_RESCONF.as_ptr()) };
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    // SAFETY: the handle opened above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

fn test_dns_search_list_count(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
        count: DnsCountFn = "_dns_search_list_count";
    }
    let handle = dns_open_tmp(dns_open.get()?);
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    // SAFETY: the handle opened above.
    let n = unsafe { (count.get()?)(handle) } as c_int;
    t.require(n > 0, || format!("resourcecount > 0: {n}"))?;
    // SAFETY: as above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

fn test_dns_search_list_domain(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
        count: DnsCountFn = "_dns_search_list_count";
        domain: DnsDomainFn = "_dns_search_list_domain";
        free: FreeFn = "_free";
    }
    let handle = dns_open_tmp(dns_open.get()?);
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    // SAFETY: the handle opened above.
    let n = unsafe { (count.get()?)(handle) } as c_int;
    t.require(n > 0, || format!("resourcecount > 0: {n}"))?;
    for i in 0..n {
        // SAFETY: as above.
        let name = unsafe { (domain.get()?)(handle, i as u32) };
        t.require(!name.is_null(), || format!("resourcename {i} != NULL"))?;
        // SAFETY: a string the call allocated for the caller.
        unsafe { (free.get()?)(name.cast()) };
    }
    // SAFETY: as above.
    let past = unsafe { (domain.get()?)(handle, n as u32 + 1) };
    t.require(past.is_null(), || {
        "resourcename past the end == NULL".into()
    })?;
    // SAFETY: as above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

/// `stdout`, which a Darwin program spells `__stdoutp`.
fn guest_stdout() -> Result<*mut c_void, Stop> {
    imports! { stdoutp: *const *mut c_void = "___stdoutp"; }
    // SAFETY: the `FILE *` cell Darwin publishes.
    Ok(unsafe { *stdoutp.get()? })
}

fn test_dns_query(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
        query: DnsQueryFn = "_dns_query";
        parse: DnsParseFn = "_dns_parse_packet";
        print: DnsPrintFn = "_dns_print_reply";
        free_reply: DnsFreeReplyFn = "_dns_free_reply";
    }
    let mut answer = [0 as c_char; 1025];
    let mut from = [0u8; 16];
    let mut fromlen = from.len() as u32;
    // SAFETY: null asks for the default configuration.
    let handle = unsafe { (dns_open.get()?)(std::ptr::null()) };
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    for record in &RECORDS {
        // SAFETY: the handle, a name, a buffer of the length given, and a
        // `struct sockaddr` with its length.
        let result = unsafe {
            (query.get()?)(
                handle,
                record.dname.as_ptr(),
                NS_C_IN as u32,
                record.kind as u32,
                answer.as_mut_ptr(),
                answer.len() as u32,
                from.as_mut_ptr().cast(),
                &mut fromlen,
            )
        };
        t.require(result > 0, || {
            format!("dns_query for type {}: {result}", record.kind)
        })?;
        // SAFETY: the response just written.
        let reply = unsafe { (parse.get()?)(answer.as_ptr(), result as u32) };
        t.require(!reply.is_null(), || "reply != NULL".into())?;
        // SAFETY: the reply parsed above, and the guest's `stdout`.
        unsafe { (print.get()?)(reply, guest_stdout()?, DNS_PRINT_ALL) };
        // SAFETY: as above.
        unsafe { (free_reply.get()?)(reply) };
    }
    // SAFETY: the handle opened above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

fn test_dns_search(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
        search: DnsQueryFn = "_dns_search";
        parse: DnsParseFn = "_dns_parse_packet";
        print: DnsPrintFn = "_dns_print_reply";
        free_reply: DnsFreeReplyFn = "_dns_free_reply";
    }
    let mut answer = [0 as c_char; 1025];
    let mut from = [0u8; 16];
    let mut fromlen = from.len() as u32;
    let handle = dns_open_tmp(dns_open.get()?);
    t.require(!handle.is_null(), || "handle != NULL".into())?;
    // SAFETY: as in `test_dns_query`.
    let result = unsafe {
        (search.get()?)(
            handle,
            c"www.apple.com".as_ptr(),
            NS_C_IN as u32,
            NS_T_A as u32,
            answer.as_mut_ptr(),
            answer.len() as u32,
            from.as_mut_ptr().cast(),
            &mut fromlen,
        )
    } as u32;
    t.require(result != 0, || "dns_search for www.apple.com".into())?;
    // SAFETY: as in `test_dns_query`.
    let reply = unsafe { (parse.get()?)(answer.as_ptr(), result) };
    t.require(!reply.is_null(), || "reply != NULL".into())?;
    // SAFETY: as in `test_dns_query`.
    unsafe { (print.get()?)(reply, guest_stdout()?, DNS_PRINT_ALL) };
    // SAFETY: as above.
    unsafe { (free_reply.get()?)(reply) };

    // A subdomain that should not exist.
    // SAFETY: as above.
    let result = unsafe {
        (search.get()?)(
            handle,
            c"itisunlikelytohaveabraeburnsubdomain.apple.com".as_ptr(),
            NS_C_IN as u32,
            NS_T_A as u32,
            answer.as_mut_ptr(),
            answer.len() as u32,
            from.as_mut_ptr().cast(),
            &mut fromlen,
        )
    } as u32;
    t.require(result != 0, || {
        "dns_search for a name that does not exist".into()
    })?;
    // SAFETY: as above.
    let reply = unsafe { (parse.get()?)(answer.as_ptr(), result) };
    t.require(reply.is_null(), || "reply == NULL".into())?;
    // SAFETY: the handle opened above.
    unsafe { (dns_free.get()?)(handle) };
    Ok(())
}

fn test_dns_lookup(t: &mut T) -> Result<(), Stop> {
    imports! {
        dns_open: DnsOpenFn = "_dns_open";
        dns_free: DnsFreeFn = "_dns_free";
        lookup: DnsLookupFn = "_dns_lookup";
        print: DnsPrintFn = "_dns_print_reply";
        free_reply: DnsFreeReplyFn = "_dns_free_reply";
    }
    for name in [
        std::ptr::null(),
        PATH_RESCONF.as_ptr(),
        MDNS_HANDLE_NAME.as_ptr(),
    ] {
        // SAFETY: null, or a NUL-terminated name.
        let handle = unsafe { (dns_open.get()?)(name) };
        if handle.is_null() {
            return Err(Stop::Fail("failed to open dns_handle".into()));
        }
        for record in &RECORDS {
            // SAFETY: the handle and a name.
            let reply = unsafe {
                (lookup.get()?)(
                    handle,
                    record.dname.as_ptr(),
                    NS_C_IN as u32,
                    record.kind as u32,
                )
            };
            t.require(!reply.is_null(), || {
                format!("reply != NULL for type {}", record.kind)
            })?;
            // SAFETY: as in `test_dns_query`.
            unsafe { (print.get()?)(reply, guest_stdout()?, DNS_PRINT_ALL) };
            // SAFETY: as above.
            unsafe { (free_reply.get()?)(reply) };
        }
        // SAFETY: the handle opened above.
        unsafe { (dns_free.get()?)(handle) };
    }
    Ok(())
}

fn test_res_init_multi(t: &mut T) -> Result<(), Stop> {
    imports! {
        res_state: ResStateFn = "___res_9_state";
        res_init: ResInitFn = "_res_9_init";
    }
    // `&_res`
    // SAFETY: `__res_state` answers this thread's context.
    let statp = unsafe { &mut *(res_state.get()?)() };
    t.require(statp.nscount == 0, || {
        format!("nscount == 0 before res_init: {}", statp.nscount)
    })?;
    // SAFETY: no arguments.
    unsafe { (res_init.get()?)() };
    if statp.nscount == 0 {
        return Err(Stop::Skip(
            "this machine has no nameservers configured".into(),
        ));
    }
    for _ in 0..5 {
        // SAFETY: as above.
        unsafe { (res_init.get()?)() };
    }
    t.require(statp.nscount <= MAXNS, || {
        format!("nscount <= MAXNS: {}", statp.nscount)
    })?;
    Ok(())
}

fn test_res_init_threads(t: &mut T) -> Result<(), Stop> {
    imports! {
        res_state: ResStateFn = "___res_9_state";
        res_init: ResInitFn = "_res_9_init";
    }
    let (res_state, res_init) = (res_state.get()?, res_init.get()?);
    // SAFETY: as in `test_res_init_multi`.
    let statp = unsafe { res_state() };
    // `thread_state_grabber`
    let thread = std::thread::spawn(move || {
        let mut t = T::default();
        // SAFETY: as in `test_res_init_multi`, on the new thread.
        let statp = unsafe { res_state() };
        // SAFETY: as above.
        unsafe { res_init() };
        // SAFETY: the context `__res_state` answered.
        let checked = check_res_state_init(&mut t, unsafe { &*statp }).map_err(|stop| match stop {
            Stop::Fail(what) => what,
            _ => "stopped".to_string(),
        });
        (statp as usize, checked)
    });
    let (threadp, checked) = thread
        .join()
        .map_err(|_| Stop::Fail("the thread panicked".into()))?;
    t.require(checked.is_ok(), || {
        format!("on the thread: {}", checked.clone().unwrap_err())
    })?;
    t.require(threadp != statp as usize, || {
        "each thread gets its own state".into()
    })?;
    // SAFETY: as above.
    unsafe { res_init() };
    // SAFETY: as above.
    check_res_state_init(t, unsafe { &*statp })
}

fn test_res_ninit(t: &mut T) -> Result<(), Stop> {
    imports! {
        res_state: ResStateFn = "___res_9_state";
        ninit: StateFn = "_res_9_ninit";
        ndestroy: VoidStateFn = "_res_9_ndestroy";
    }
    // SAFETY: as in `test_res_init_multi`.
    let statp = unsafe { (res_state.get()?)() };
    // SAFETY: the context, every byte of it written as garbage.
    unsafe { std::ptr::write_bytes(statp, 0xff, 1) };
    // SAFETY: as above.
    unsafe { (ninit.get()?)(statp) };
    // SAFETY: as above.
    check_res_state_init(t, unsafe { &*statp })?;
    // SAFETY: the context `res_ninit` set up.
    unsafe { (ndestroy.get()?)(statp) };
    Ok(())
}

fn adapted_res_ninit(t: &mut T) -> Result<(), Stop> {
    imports! {
        ninit: StateFn = "_res_9_ninit";
        ndestroy: VoidStateFn = "_res_9_ndestroy";
    }
    let mut state: Box<std::mem::MaybeUninit<ResState>> = Box::new(std::mem::MaybeUninit::uninit());
    let statp = state.as_mut_ptr();
    // SAFETY: a context of the right size, every byte of it garbage.
    unsafe { std::ptr::write_bytes(statp, 0xff, 1) };
    // SAFETY: as above.
    unsafe { (ninit.get()?)(statp) };
    // SAFETY: as above.
    check_res_state_init(t, unsafe { &*statp })?;
    // SAFETY: the context `res_ninit` set up.
    unsafe { (ndestroy.get()?)(statp) };
    Ok(())
}

const NET: u64 = 60;

static CASES: &[Case] = &[
    Case {
        name: "test_res_query",
        kind: Kind::Upstream,
        source: "res_query each of six records",
        timeout_secs: NET,
        run: test_res_query,
    },
    Case {
        name: "test_res_search",
        kind: Kind::Upstream,
        source: "res_search, ns_initparse, ns_parserr",
        timeout_secs: NET,
        run: test_res_search,
    },
    Case {
        name: "test_res_search_a",
        kind: Kind::Upstream,
        source: "res_search A, checked",
        timeout_secs: NET,
        run: test_res_search_a,
    },
    Case {
        name: "test_res_search_mx",
        kind: Kind::Upstream,
        source: "res_search MX, ns_name_uncompress",
        timeout_secs: NET,
        run: test_res_search_mx,
    },
    Case {
        name: "test_res_mkquery",
        kind: Kind::Upstream,
        source: "atf_tc_skip upstream",
        timeout_secs: 10,
        run: upstream_skips,
    },
    Case {
        name: "test_res_send",
        kind: Kind::Upstream,
        source: "res_mkquery, res_send, check_answer",
        timeout_secs: NET,
        run: test_res_send,
    },
    Case {
        name: "test_res_init",
        kind: Kind::Upstream,
        source: "atf_tc_skip upstream",
        timeout_secs: 10,
        run: upstream_skips,
    },
    Case {
        name: "test_dn_comp",
        kind: Kind::Upstream,
        source: "atf_tc_skip upstream",
        timeout_secs: 10,
        run: upstream_skips,
    },
    Case {
        name: "test_dn_expand",
        kind: Kind::Upstream,
        source: "atf_tc_skip upstream",
        timeout_secs: 10,
        run: upstream_skips,
    },
    Case {
        name: "test_dn_skipname",
        kind: Kind::Upstream,
        source: "atf_tc_skip upstream",
        timeout_secs: 10,
        run: upstream_skips,
    },
    Case {
        name: "test_ns_get16",
        kind: Kind::Upstream,
        source: "ns_get16",
        timeout_secs: 10,
        run: test_ns_get16,
    },
    Case {
        name: "test_ns_get32",
        kind: Kind::Upstream,
        source: "ns_get32",
        timeout_secs: 10,
        run: test_ns_get32,
    },
    Case {
        name: "test_ns_put16",
        kind: Kind::Upstream,
        source: "ns_put16",
        timeout_secs: 10,
        run: test_ns_put16,
    },
    Case {
        name: "test_ns_put32",
        kind: Kind::Upstream,
        source: "ns_put32",
        timeout_secs: 10,
        run: test_ns_put32,
    },
    Case {
        name: "test_dns_open_null",
        kind: Kind::Upstream,
        source: "dns_open(NULL)",
        timeout_secs: 10,
        run: test_dns_open_null,
    },
    Case {
        name: "test_dns_open_resolvconf",
        kind: Kind::Upstream,
        source: "dns_open(_PATH_RESCONF)",
        timeout_secs: 10,
        run: test_dns_open_resolvconf,
    },
    Case {
        name: "test_dns_search_list_count",
        kind: Kind::Upstream,
        source: "dns_search_list_count",
        timeout_secs: 10,
        run: test_dns_search_list_count,
    },
    Case {
        name: "test_dns_search_list_domain",
        kind: Kind::Upstream,
        source: "dns_search_list_domain",
        timeout_secs: 10,
        run: test_dns_search_list_domain,
    },
    Case {
        name: "test_dns_query",
        kind: Kind::Upstream,
        source: "dns_query, dns_parse_packet",
        timeout_secs: NET,
        run: test_dns_query,
    },
    Case {
        name: "test_dns_search",
        kind: Kind::Upstream,
        source: "dns_search",
        timeout_secs: NET,
        run: test_dns_search,
    },
    Case {
        name: "test_dns_lookup",
        kind: Kind::Upstream,
        source: "dns_lookup on three handles",
        timeout_secs: NET,
        run: test_dns_lookup,
    },
    Case {
        name: "test_res_init_multi",
        kind: Kind::Upstream,
        source: "rdar://135369694",
        timeout_secs: 10,
        run: test_res_init_multi,
    },
    Case {
        name: "test_res_init_threads",
        kind: Kind::Upstream,
        source: "_res per thread",
        timeout_secs: 10,
        run: test_res_init_threads,
    },
    Case {
        name: "test_res_ninit",
        kind: Kind::Upstream,
        source: "rdar://131556571",
        timeout_secs: 10,
        run: test_res_ninit,
    },
    Case {
        name: "test_res_query/nquery",
        kind: Kind::Adapted,
        source: "test_res_query; res_ninit + res_nquery for res_query",
        timeout_secs: NET,
        run: adapted_res_query,
    },
    Case {
        name: "test_res_search/nquery",
        kind: Kind::Adapted,
        source: "test_res_search; res_nquery for res_search (the name has a dot, so a search asks it as is first); ns_sprintrr, which only prints, left out",
        timeout_secs: NET,
        run: adapted_res_search,
    },
    Case {
        name: "test_res_search_a/nquery",
        kind: Kind::Adapted,
        source: "test_res_search_a; as above",
        timeout_secs: NET,
        run: adapted_res_search_a,
    },
    Case {
        name: "test_res_search_mx/nquery",
        kind: Kind::Adapted,
        source: "test_res_search_mx; as above, and NS_GET16 for ns_get16",
        timeout_secs: NET,
        run: adapted_res_search_mx,
    },
    Case {
        name: "test_res_send/nsend",
        kind: Kind::Adapted,
        source: "test_res_send; res_ninit + res_nmkquery + res_nsend; ns_sprintrr left out",
        timeout_secs: NET,
        run: adapted_res_send,
    },
    Case {
        name: "test_res_ninit/local",
        kind: Kind::Adapted,
        source: "test_res_ninit; a context of its own for &_res",
        timeout_secs: 10,
        run: adapted_res_ninit,
    },
];

#[test]
fn libresolv_conformance() {
    conformance::run("libresolv_conformance", "libresolv", UPSTREAM, CASES);
}
