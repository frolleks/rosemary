//! CFNetwork's `CFHost`, after Apple's `CFHost.c` (CFNetwork, `Host/`): a host
//! name resolved to its addresses.
//!
//! A host with no client resolves synchronously, `CFHostStartInfoResolution`
//! returning with the answer. One with a client resolves on a thread of its
//! own, and the answer reaches the client's callback through a run loop source
//! on every run loop and mode the host is scheduled in - which is where Apple's
//! `_GetAddrInfoCallBack` runs it.
//!
//! The lookup a name makes, `kCFHostAddresses`, is the one implemented. A
//! reverse lookup (`kCFHostNames` from an address) and `kCFHostReachability`
//! are refused with `EINVAL` rather than answered with something made up.

// The C spellings are the interface; renaming them would only hide it.
#![allow(non_snake_case)]

use std::ffi::{CString, c_void};
use std::sync::{Arc, Mutex};

use corefoundation::base::CFTypeRef;
use objc::object::Id;
use objc::sel::Sel;

use crate::define::methods;

/// `CFHostInfoType`
const ADDRESSES: i32 = 0;

/// `kCFStreamErrorDomainPOSIX`
const DOMAIN_POSIX: isize = 1;
/// `kCFStreamErrorDomainNetDB`, `CFHost.h`'s domain for a `getaddrinfo` status.
const DOMAIN_NETDB: isize = 12;
/// `kCFStreamErrorDomainSystemConfiguration`, its neighbour in `CFHost.h`.
const DOMAIN_SYSTEM_CONFIGURATION: isize = 13;
/// Darwin's `EINVAL`.
const EINVAL: i32 = 22;
/// Darwin's `EAI_SYSTEM`.
const EAI_SYSTEM: i32 = 11;

/// `CFStreamError`
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct StreamError {
    domain: isize,
    error: i32,
}

/// `CFHostClientCallBack`
type ClientCallBack = unsafe extern "C" fn(CFTypeRef, i32, *const StreamError, *mut c_void);

/// `CFHostClientContext`
#[repr(C)]
#[derive(Clone, Copy)]
struct ClientContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFTypeRef>,
}

/// The object a `CFHostRef` is.
#[repr(C)]
struct Body {
    isa: *const c_void,
    /// From `Arc::into_raw`, so the resolver thread can hold the state too.
    host: *const Host,
}

struct Host {
    state: Mutex<State>,
}

/// What a finished `getaddrinfo` found: Darwin `sockaddr`s, or the error.
type Answer = Result<Vec<Vec<u8>>, StreamError>;

/// The lookup in progress: one at a time, as in Apple's.
struct Lookup {
    /// Which start this is, so a cancelled lookup's thread is ignored.
    generation: u64,
    /// The run loop source its answer is delivered through, retained.
    source: CFTypeRef,
    /// The answer, once the thread has it; `None` for a cancel, which Apple
    /// delivers through a source of its own too.
    answer: Option<Answer>,
    cancel: bool,
}

struct State {
    /// `kCFHostNames`: the name, as a retained one-element array.
    names: CFTypeRef,
    name: Option<CString>,
    /// `kCFHostAddresses` once resolved: an array the host owns, or null for a
    /// resolution that found nothing (Apple's `kCFNull`).
    addresses: Option<CFTypeRef>,
    error: StreamError,
    lookup: Option<Lookup>,
    generation: u64,
    callback: Option<ClientCallBack>,
    client: Option<ClientContext>,
    /// Each run loop and mode, both retained.
    schedules: Vec<(CFTypeRef, CFTypeRef)>,
}

// SAFETY: the raw pointers are CF objects, whose reference counts and run
// loop operations are thread-safe; everything else is behind the mutex.
unsafe impl Send for State {}

fn class() -> &'static objc::class::Class {
    let class = corefoundation::base::register(c"__NSCFHost", None, size_of::<Body>(), true);
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        methods!(class, {
            "dealloc" => dealloc, c"v16@0:8";
        });
    });
    class
}

/// The state behind a `CFHostRef`, or `None` for anything else.
fn host_of<'a>(object: CFTypeRef) -> Option<&'a Host> {
    if object.is_null() {
        return None;
    }
    let class = class();
    // SAFETY: an object this runtime allocated.
    let is_host = unsafe { objc::object::class_of(object as Id) }
        .is_some_and(|c| c.chain().any(|x| std::ptr::eq(x, class)));
    // SAFETY: a `Body`, checked above, whose `host` lives as long as it.
    is_host.then(|| unsafe { &*(*(object as *const Body)).host })
}

fn lock(host: &Host) -> std::sync::MutexGuard<'_, State> {
    host.state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The UTF-8 text of a string object.
fn text(string: CFTypeRef) -> Option<String> {
    // SAFETY: null or an object this runtime allocated.
    unsafe { corefoundation::string::as_string(string) }
        .map(|s| String::from_utf16_lossy(&s.utf16()))
}

/// `CFHostRef CFHostCreateWithName(CFAllocatorRef, CFStringRef hostname)`
unsafe extern "C" fn CFHostCreateWithName(_allocator: CFTypeRef, hostname: CFTypeRef) -> CFTypeRef {
    let name = text(hostname).and_then(|name| CString::new(name).ok());
    let names = corefoundation::collections::new_array(
        &[hostname],
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    let host = Arc::new(Host {
        state: Mutex::new(State {
            names,
            name,
            addresses: None,
            error: StreamError::default(),
            lookup: None,
            generation: 0,
            callback: None,
            client: None,
            schedules: Vec::new(),
        }),
    });
    // SAFETY: `Body` is the registered layout.
    let body: *mut Body = unsafe { corefoundation::base::allocate(class()) };
    // SAFETY: a fresh allocation.
    unsafe { (*body).host = Arc::into_raw(host) };
    body as CFTypeRef
}

/// The addresses of a finished lookup, as the array `CFHostGetAddressing`
/// answers: each a `CFData` of a Darwin `sockaddr`, IPv4 and IPv6 only.
fn address_array(addresses: &[Vec<u8>]) -> CFTypeRef {
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 30;
    let data: Vec<CFTypeRef> = addresses
        .iter()
        .filter(|a| a.len() > 1 && matches!(a[1], AF_INET | AF_INET6))
        .map(|a| corefoundation::collections::new_data(a.clone()))
        .collect();
    let array = corefoundation::collections::new_array(
        &data,
        corefoundation::callbacks::Policy::from_type_callbacks(),
        true,
    );
    for object in data {
        // SAFETY: the array retained each.
        unsafe { corefoundation::api::CFRelease(object) };
    }
    array
}

/// Resolve `name` as Apple's `_CreateMasterAddressLookup` asks: stream sockets,
/// `AI_ADDRCONFIG`, either family.
fn resolve(name: &CString) -> Answer {
    darwin::net::resolve::addresses(
        name,
        libc::AF_UNSPEC,
        libc::SOCK_STREAM,
        libc::AI_ADDRCONFIG,
    )
    .map_err(|failure| match failure.eai {
        EAI_SYSTEM => StreamError {
            domain: DOMAIN_POSIX,
            error: failure.errno,
        },
        eai => StreamError {
            domain: DOMAIN_NETDB,
            error: eai,
        },
    })
}

/// Record an answer as `_GetAddrInfoCallBack` does: the addresses, or null
/// and the error, replacing whatever an earlier resolution left.
fn record(state: &mut State, answer: Answer) {
    if let Some(old) = state.addresses.take()
        && !old.is_null()
    {
        // SAFETY: the array the host owned.
        unsafe { corefoundation::api::CFRelease(old) };
    }
    match answer {
        Ok(addresses) => {
            state.error = StreamError::default();
            state.addresses = Some(address_array(&addresses));
        }
        Err(error) => {
            state.error = error;
            state.addresses = Some(std::ptr::null());
        }
    }
}

/// Take a lookup's source off every schedule, invalidate it and let it go.
fn end_lookup(state: &mut State) -> Option<Lookup> {
    let lookup = state.lookup.take()?;
    // SAFETY: the source this host made, and run loops and modes it retains.
    unsafe {
        for &(run_loop, mode) in &state.schedules {
            corefoundation::api::CFRunLoopRemoveSource(run_loop, lookup.source, mode);
        }
        corefoundation::api::CFRunLoopSourceInvalidate(lookup.source);
        corefoundation::api::CFRelease(lookup.source);
    }
    Some(lookup)
}

/// The perform of a lookup's source, on a run loop the host is scheduled in:
/// the answer recorded and the client called, or for a cancel, the client
/// called with the error as it stands - `_GetAddrInfoCallBack` and
/// `_HostCancel`.
unsafe extern "C" fn deliver(info: *mut c_void) {
    let object = info as CFTypeRef;
    let Some(host) = host_of(object) else {
        return;
    };
    let (callback, error, client_info) = {
        let mut state = lock(host);
        let ready = state
            .lookup
            .as_ref()
            .is_some_and(|lookup| lookup.cancel || lookup.answer.is_some());
        if !ready {
            return;
        }
        let lookup = end_lookup(&mut state).expect("checked above");
        if let Some(answer) = lookup.answer {
            record(&mut state, answer);
        }
        (state.callback, state.error, state.client.map(|c| c.info))
    };
    if let Some(callback) = callback {
        // SAFETY: the client's callback and context, as it registered them.
        unsafe {
            callback(
                object,
                ADDRESSES,
                &error,
                client_info.unwrap_or(std::ptr::null_mut()),
            )
        };
    }
    // The retain the lookup held, now that it has been delivered.
    // SAFETY: taken in `start_async`.
    unsafe { corefoundation::api::CFRelease(object) };
}

/// A source delivering to `object`'s client, on every schedule the host has.
fn scheduled_source(object: CFTypeRef, state: &State) -> CFTypeRef {
    let context = corefoundation::api::CFRunLoopSourceContext {
        version: 0,
        info: object as *mut c_void,
        retain: std::ptr::null(),
        release: std::ptr::null(),
        copy_description: std::ptr::null(),
        equal: std::ptr::null(),
        hash: std::ptr::null(),
        schedule: std::ptr::null(),
        cancel: std::ptr::null(),
        perform: Some(deliver),
    };
    // SAFETY: a live context; the run loops and modes the host retains.
    unsafe {
        let source = corefoundation::api::CFRunLoopSourceCreate(std::ptr::null(), 0, &context);
        for &(run_loop, mode) in &state.schedules {
            corefoundation::api::CFRunLoopAddSource(run_loop, source, mode);
        }
        source
    }
}

/// Fire a lookup's source and wake every run loop it is on.
fn signal(source: CFTypeRef, schedules: &[(CFTypeRef, CFTypeRef)]) {
    // SAFETY: a source and run loops kept alive by their retains.
    unsafe {
        corefoundation::api::CFRunLoopSourceSignal(source);
        for &(run_loop, _) in schedules {
            corefoundation::api::CFRunLoopWakeUp(run_loop);
        }
    }
}

/// `Boolean CFHostStartInfoResolution(CFHostRef, CFHostInfoType,
/// CFStreamError *error)`
unsafe extern "C" fn CFHostStartInfoResolution(
    object: CFTypeRef,
    info: i32,
    error: *mut StreamError,
) -> u8 {
    let (started, reported) = start(object, info);
    if !error.is_null() {
        // SAFETY: the caller's optional out-pointer.
        unsafe { *error = reported };
    }
    started as u8
}

fn start(object: CFTypeRef, info: i32) -> (bool, StreamError) {
    let Some(host) = host_of(object) else {
        return (false, StreamError::default());
    };
    let mut state = lock(host);
    // Only one lookup at a time.
    if state.lookup.is_some() {
        return (false, state.error);
    }
    let name = match (info, state.name.clone()) {
        (ADDRESSES, Some(name)) => name,
        _ => {
            state.error = StreamError {
                domain: DOMAIN_POSIX,
                error: EINVAL,
            };
            return (false, state.error);
        }
    };
    if state.callback.is_none() {
        // Synchronous: `_HostBlockUntilComplete`, without the private run
        // loop mode it waits in, as nothing else could be waiting there.
        drop(state);
        let answer = resolve(&name);
        let mut state = lock(host);
        record(&mut state, answer);
        return (state.error.error == 0, state.error);
    }
    state.error = StreamError::default();
    state.generation += 1;
    let generation = state.generation;
    let source = scheduled_source(object, &state);
    state.lookup = Some(Lookup {
        generation,
        source,
        answer: None,
        cancel: false,
    });
    // The lookup keeps the host alive until it is delivered or cancelled, as
    // the context of Apple's lookup port retains it.
    // SAFETY: a live object.
    unsafe { corefoundation::api::CFRetain(object) };
    drop(state);

    // SAFETY: a live host whose state the thread shares through the `Arc`.
    let shared = unsafe {
        let raw = (*(object as *const Body)).host;
        Arc::increment_strong_count(raw);
        Arc::from_raw(raw)
    };
    let spawned = std::thread::Builder::new()
        .name("CFHost lookup".into())
        .spawn(move || {
            let answer = resolve(&name);
            let mut state = lock(&shared);
            let Some(lookup) = state.lookup.as_mut().filter(|l| l.generation == generation) else {
                return;
            };
            lookup.answer = Some(answer);
            let source = lookup.source;
            signal(source, &state.schedules);
        });
    if spawned.is_err() {
        let mut state = lock(host);
        end_lookup(&mut state);
        state.error = StreamError {
            domain: DOMAIN_POSIX,
            error: 35, // Darwin's `EAGAIN`
        };
        drop(state);
        // SAFETY: the retain taken above.
        unsafe { corefoundation::api::CFRelease(object) };
        return (
            false,
            StreamError {
                domain: DOMAIN_POSIX,
                error: 35,
            },
        );
    }
    (true, StreamError::default())
}

/// `CFArrayRef CFHostGetAddressing(CFHostRef, Boolean *hasBeenResolved)`: the
/// addresses, which the host owns; null and `false` before a resolution has
/// finished, and null and `true` after one that found nothing.
unsafe extern "C" fn CFHostGetAddressing(object: CFTypeRef, resolved: *mut u8) -> CFTypeRef {
    let found = host_of(object).and_then(|host| lock(host).addresses);
    if !resolved.is_null() {
        // SAFETY: the caller's optional out-pointer.
        unsafe { *resolved = found.is_some() as u8 };
    }
    found.unwrap_or(std::ptr::null())
}

/// `void CFHostCancelInfoResolution(CFHostRef, CFHostInfoType)`
///
/// As Apple's: the lookup is abandoned, and a source standing in for it tells
/// the client on its next turn of the run loop, with the error as it stands -
/// unless the client is removed first, which removes that source too.
unsafe extern "C" fn CFHostCancelInfoResolution(object: CFTypeRef, _info: i32) {
    let Some(host) = host_of(object) else {
        return;
    };
    let mut state = lock(host);
    if state.lookup.as_ref().is_none_or(|lookup| lookup.cancel) {
        return;
    }
    end_lookup(&mut state);
    state.generation += 1;
    let source = scheduled_source(object, &state);
    state.lookup = Some(Lookup {
        generation: state.generation,
        source,
        answer: None,
        cancel: true,
    });
    signal(source, &state.schedules);
}

/// `Boolean CFHostSetClient(CFHostRef, CFHostClientCallBack,
/// CFHostClientContext *)`
///
/// A null callback or context removes the client and abandons any lookup
/// without telling anyone, as Apple's does.
unsafe extern "C" fn CFHostSetClient(
    object: CFTypeRef,
    callback: Option<ClientCallBack>,
    context: *const ClientContext,
) -> u8 {
    let Some(host) = host_of(object) else {
        return 0;
    };
    let mut state = lock(host);
    if let Some(old) = state.client.take()
        && let Some(release) = old.release
        && !old.info.is_null()
    {
        // SAFETY: the client's own release callback, on its own info.
        unsafe { release(old.info) };
    }
    let (Some(callback), false) = (callback, context.is_null()) else {
        let abandoned = end_lookup(&mut state).is_some();
        state.callback = None;
        drop(state);
        if abandoned {
            // The lookup's retain on the host, which nothing will deliver now.
            // SAFETY: taken in `start`.
            unsafe { corefoundation::api::CFRelease(object) };
        }
        return 1;
    };
    // SAFETY: the caller's live context, copied as Apple's copies it.
    let mut client = unsafe { *context };
    if let Some(retain) = client.retain
        && !client.info.is_null()
    {
        // SAFETY: the client's own retain callback.
        client.info = unsafe { retain(client.info) } as *mut c_void;
    }
    state.callback = Some(callback);
    state.client = Some(client);
    1
}

/// `void CFHostScheduleWithRunLoop(CFHostRef, CFRunLoopRef, CFStringRef)`
unsafe extern "C" fn CFHostScheduleWithRunLoop(
    object: CFTypeRef,
    run_loop: CFTypeRef,
    mode: CFTypeRef,
) {
    let Some(host) = host_of(object) else {
        return;
    };
    if run_loop.is_null() || mode.is_null() {
        return;
    }
    let mut state = lock(host);
    if state
        .schedules
        .iter()
        .any(|&(l, m)| l == run_loop && same_mode(m, mode))
    {
        return;
    }
    // SAFETY: live objects, retained for as long as the schedule stands.
    unsafe {
        state.schedules.push((
            corefoundation::api::CFRetain(run_loop),
            corefoundation::api::CFRetain(mode),
        ));
        if let Some(lookup) = &state.lookup {
            corefoundation::api::CFRunLoopAddSource(run_loop, lookup.source, mode);
        }
    }
}

/// `void CFHostUnscheduleFromRunLoop(CFHostRef, CFRunLoopRef, CFStringRef)`
unsafe extern "C" fn CFHostUnscheduleFromRunLoop(
    object: CFTypeRef,
    run_loop: CFTypeRef,
    mode: CFTypeRef,
) {
    let Some(host) = host_of(object) else {
        return;
    };
    let mut state = lock(host);
    let Some(at) = state
        .schedules
        .iter()
        .position(|&(l, m)| l == run_loop && same_mode(m, mode))
    else {
        return;
    };
    let (run_loop, held_mode) = state.schedules.remove(at);
    // SAFETY: the retains the schedule held.
    unsafe {
        if let Some(lookup) = &state.lookup {
            corefoundation::api::CFRunLoopRemoveSource(run_loop, lookup.source, held_mode);
        }
        corefoundation::api::CFRelease(run_loop);
        corefoundation::api::CFRelease(held_mode);
    }
}

/// Modes are compared by name, as `CFEqual` compares two strings.
fn same_mode(a: CFTypeRef, b: CFTypeRef) -> bool {
    a == b || (text(a).is_some() && text(a) == text(b))
}

unsafe extern "C" fn dealloc(receiver: Id, _sel: Sel) {
    let body = receiver as *mut Body;
    // SAFETY: `-dealloc` of a `Body` whose `host` came from `Arc::into_raw`.
    let host = unsafe { Arc::from_raw((*body).host) };
    {
        let mut state = lock(&host);
        end_lookup(&mut state);
        if let Some(client) = state.client.take()
            && let Some(release) = client.release
            && !client.info.is_null()
        {
            // SAFETY: the client's own release callback.
            unsafe { release(client.info) };
        }
        // SAFETY: everything below is a retain this host holds.
        unsafe {
            for (run_loop, mode) in state.schedules.drain(..) {
                corefoundation::api::CFRelease(run_loop);
                corefoundation::api::CFRelease(mode);
            }
            if let Some(addresses) = state.addresses.take()
                && !addresses.is_null()
            {
                corefoundation::api::CFRelease(addresses);
            }
            if !state.names.is_null() {
                corefoundation::api::CFRelease(state.names);
            }
        }
    }
    drop(host);
    objc::arc::finalize(receiver);
}

/// The two `CFStreamErrorDomain` constants `CFHost.h` declares, as the `SInt32`
/// variables a guest reads.
pub fn data_symbols() -> Vec<(String, u64)> {
    [
        ("_kCFStreamErrorDomainNetDB", DOMAIN_NETDB),
        (
            "_kCFStreamErrorDomainSystemConfiguration",
            DOMAIN_SYSTEM_CONFIGURATION,
        ),
    ]
    .into_iter()
    .map(|(name, value)| {
        (
            name.to_string(),
            corefoundation::base::global_cell(name, value as u64),
        )
    })
    .collect()
}

exports::exports! {
    functions {
        "CFHostCreateWithName" => CFHostCreateWithName,
        "CFHostStartInfoResolution" => CFHostStartInfoResolution,
        "CFHostGetAddressing" => CFHostGetAddressing,
        "CFHostCancelInfoResolution" => CFHostCancelInfoResolution,
        "CFHostSetClient" => CFHostSetClient,
        "CFHostScheduleWithRunLoop" => CFHostScheduleWithRunLoop,
        "CFHostUnscheduleFromRunLoop" => CFHostUnscheduleFromRunLoop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> CFTypeRef {
        crate::string::from_str(text) as CFTypeRef
    }

    /// No client: the answer is there when the call returns, as a `sockaddr`
    /// of Darwin's shape.
    #[test]
    fn a_host_without_a_client_resolves_before_returning() {
        crate::bootstrap();
        // SAFETY: the calls' own contracts, on objects made here.
        unsafe {
            let host = CFHostCreateWithName(std::ptr::null(), name("127.0.0.1"));
            let mut resolved = 9u8;
            assert!(CFHostGetAddressing(host, &mut resolved).is_null());
            assert_eq!(resolved, 0);
            let mut error = StreamError {
                domain: 7,
                error: 7,
            };
            assert_eq!(CFHostStartInfoResolution(host, ADDRESSES, &mut error), 1);
            assert_eq!(error, StreamError::default());
            let addresses = CFHostGetAddressing(host, &mut resolved);
            assert_eq!(resolved, 1);
            assert_eq!(corefoundation::api::CFArrayGetCount(addresses), 1);
            let first = corefoundation::api::CFArrayGetValueAtIndex(addresses, 0);
            let bytes = corefoundation::collections::data(first).unwrap();
            // sa_len, AF_INET, port 0, 127.0.0.1
            assert_eq!(&bytes[..8], &[16, 2, 0, 0, 127, 0, 0, 1]);
            corefoundation::api::CFRelease(host);
        }
    }

    static CALLS: Mutex<Vec<(i32, StreamError, usize)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn called(
        _host: CFTypeRef,
        info: i32,
        error: *const StreamError,
        client: *mut c_void,
    ) {
        // SAFETY: the host passes a live error.
        let error = unsafe { *error };
        CALLS.lock().unwrap().push((info, error, client as usize));
    }

    /// Run the current run loop until the callback has been called, or give up.
    fn run_until_called(expected: usize) {
        let mode = corefoundation::string::immortal("kCFRunLoopDefaultMode");
        for _ in 0..200 {
            if CALLS.lock().unwrap().len() >= expected {
                return;
            }
            // SAFETY: the current thread's run loop, in a named mode.
            unsafe { corefoundation::api::CFRunLoopRunInMode(mode, 0.05, 1) };
        }
    }

    /// With a client, the call returns at once and the answer reaches the
    /// callback on the run loop the host is scheduled in; a cancel is
    /// delivered the same way, with the error as it stood.
    #[test]
    fn a_client_hears_the_answer_and_a_cancel_on_its_run_loop() {
        crate::bootstrap();
        let mode = corefoundation::string::immortal("kCFRunLoopDefaultMode");
        // SAFETY: as above, with a context whose info is a plain number.
        unsafe {
            let host = CFHostCreateWithName(std::ptr::null(), name("127.0.0.1"));
            let context = ClientContext {
                version: 0,
                info: 0x5eed as *mut c_void,
                retain: None,
                release: None,
                copy_description: None,
            };
            assert_eq!(CFHostSetClient(host, Some(called), &context), 1);
            let run_loop = corefoundation::api::CFRunLoopGetCurrent();
            CFHostScheduleWithRunLoop(host, run_loop, mode);
            let mut error = StreamError {
                domain: 7,
                error: 7,
            };
            assert_eq!(CFHostStartInfoResolution(host, ADDRESSES, &mut error), 1);
            assert_eq!(error, StreamError::default());
            // A second start while one is in flight is refused.
            assert_eq!(
                CFHostStartInfoResolution(host, ADDRESSES, std::ptr::null_mut()),
                0
            );
            run_until_called(1);
            assert_eq!(
                CALLS.lock().unwrap()[0],
                (ADDRESSES, StreamError::default(), 0x5eed)
            );
            let mut resolved = 0u8;
            let addresses = CFHostGetAddressing(host, &mut resolved);
            assert_eq!(
                (resolved, corefoundation::api::CFArrayGetCount(addresses)),
                (1, 1)
            );

            assert_eq!(
                CFHostStartInfoResolution(host, ADDRESSES, std::ptr::null_mut()),
                1
            );
            CFHostCancelInfoResolution(host, ADDRESSES);
            run_until_called(2);
            assert_eq!(CALLS.lock().unwrap().len(), 2);
            // Nothing more arrives from the abandoned lookup.
            corefoundation::api::CFRunLoopRunInMode(mode, 0.2, 0);
            assert_eq!(CALLS.lock().unwrap().len(), 2);

            CFHostUnscheduleFromRunLoop(host, run_loop, mode);
            assert_eq!(CFHostSetClient(host, None, std::ptr::null()), 1);
            corefoundation::api::CFRelease(host);
        }
    }

    /// A name that cannot resolve reports its `getaddrinfo` status in the
    /// NetDB domain, and resolution counts as done with nothing found.
    #[test]
    fn a_name_that_does_not_resolve_is_a_netdb_error() {
        crate::bootstrap();
        // SAFETY: as above.
        unsafe {
            let host = CFHostCreateWithName(std::ptr::null(), name("rosemary-test.invalid"));
            let mut error = StreamError::default();
            assert_eq!(CFHostStartInfoResolution(host, ADDRESSES, &mut error), 0);
            assert_eq!(error.domain, DOMAIN_NETDB);
            assert_ne!(error.error, 0);
            let mut resolved = 0u8;
            assert!(CFHostGetAddressing(host, &mut resolved).is_null());
            assert_eq!(resolved, 1);
            corefoundation::api::CFRelease(host);
        }
    }
}
