//! libdispatch conformance: Apple's libdispatch tests for sources, timers and
//! the main queue, ported case by case against the `dispatch_*` a guest
//! binds. apple-oss-distributions/libdispatch publishes the library without
//! its `tests/`; these are the same tests as swift-corelibs-libdispatch (the
//! open-source libdispatch, at `main`) carries them.
//!
//! What every port shares with upstream's harness (`bsdtests.c`,
//! `dispatch_test.c`):
//!
//! - `dispatch_main()` drains the main queue until `test_stop()`, which here
//!   ends the case rather than `_exit`ing the process.
//! - Blocks are block literals built here, marked global so `_Block_copy`
//!   keeps them as they are, which is what a block with no captures is.
//! - `test_*` checks are recorded from whichever thread makes them.
//!
//! ```text
//! cargo test -p darwin --test libdispatch_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]

mod conformance;

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use conformance::{Case, Kind, Stop, T, import};

const UPSTREAM: &str = "swift-corelibs-libdispatch tests/ (main)";

const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_USEC: u64 = 1_000;
const DISPATCH_TIME_NOW: u64 = 0;
const DISPATCH_TIME_FOREVER: u64 = u64::MAX;
const DISPATCH_PROC_EXIT: u64 = 0x8000_0000;
const DISPATCH_VNODE_RENAME: u64 = 0x20;

type Source = u64;

/// The entry points the ports call, bound once per case.
struct Api {
    main_q: u64,
    type_timer: u64,
    type_read: u64,
    type_proc: u64,
    type_vnode: u64,
    source_create: unsafe extern "C" fn(u64, u64, u64, u64) -> u64,
    set_timer: unsafe extern "C" fn(u64, u64, u64, u64),
    set_event_handler: unsafe extern "C" fn(u64, u64),
    set_cancel_handler: unsafe extern "C" fn(u64, u64),
    set_registration_handler: unsafe extern "C" fn(u64, u64),
    cancel: unsafe extern "C" fn(u64),
    get_data: unsafe extern "C" fn(u64) -> u64,
    resume: unsafe extern "C" fn(u64),
    suspend: unsafe extern "C" fn(u64),
    release: unsafe extern "C" fn(u64),
    set_context: unsafe extern "C" fn(u64, u64),
    set_finalizer_f: unsafe extern "C" fn(u64, u64),
    time: unsafe extern "C" fn(u64, i64) -> u64,
    global_queue: unsafe extern "C" fn(i64, u64) -> u64,
    queue_create: unsafe extern "C" fn(*const c_char, u64) -> u64,
    group_create: unsafe extern "C" fn() -> u64,
    group_enter: unsafe extern "C" fn(u64),
    group_leave: unsafe extern "C" fn(u64),
    group_wait: unsafe extern "C" fn(u64, u64) -> i64,
    after: unsafe extern "C" fn(u64, u64, u64),
    async_: unsafe extern "C" fn(u64, u64),
    async_f: unsafe extern "C" fn(u64, u64, u64),
    semaphore_create: unsafe extern "C" fn(i64) -> u64,
    semaphore_signal: unsafe extern "C" fn(u64) -> i64,
    semaphore_wait: unsafe extern "C" fn(u64, u64) -> i64,
    kqueue: unsafe extern "C" fn() -> i32,
    kevent: unsafe extern "C" fn(
        i32,
        *const Kevent,
        i32,
        *mut Kevent,
        i32,
        *const libc::timespec,
    ) -> i32,
}

/// Darwin's `struct kevent`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
}

static API: OnceLock<Api> = OnceLock::new();

fn d() -> &'static Api {
    API.get().expect("setup ran")
}

fn bind<F: Copy>(symbol: &'static str) -> Result<F, Stop> {
    import::<F>(symbol).get()
}

fn datum(symbol: &'static str) -> Result<u64, Stop> {
    Ok(import::<*const u8>(symbol).get()? as u64)
}

/// Bind what the ports call, and give libdispatch the block runtime the
/// process would have.
fn setup() -> Result<(), Stop> {
    let api = Api {
        main_q: datum("__dispatch_main_q")?,
        type_timer: datum("__dispatch_source_type_timer")?,
        type_read: datum("__dispatch_source_type_read")?,
        type_proc: datum("__dispatch_source_type_proc")?,
        type_vnode: datum("__dispatch_source_type_vnode")?,
        source_create: bind("_dispatch_source_create")?,
        set_timer: bind("_dispatch_source_set_timer")?,
        set_event_handler: bind("_dispatch_source_set_event_handler")?,
        set_cancel_handler: bind("_dispatch_source_set_cancel_handler")?,
        set_registration_handler: bind("_dispatch_source_set_registration_handler")?,
        cancel: bind("_dispatch_source_cancel")?,
        get_data: bind("_dispatch_source_get_data")?,
        resume: bind("_dispatch_resume")?,
        suspend: bind("_dispatch_suspend")?,
        release: bind("_dispatch_release")?,
        set_context: bind("_dispatch_set_context")?,
        set_finalizer_f: bind("_dispatch_set_finalizer_f")?,
        time: bind("_dispatch_time")?,
        global_queue: bind("_dispatch_get_global_queue")?,
        queue_create: bind("_dispatch_queue_create")?,
        group_create: bind("_dispatch_group_create")?,
        group_enter: bind("_dispatch_group_enter")?,
        group_leave: bind("_dispatch_group_leave")?,
        group_wait: bind("_dispatch_group_wait")?,
        after: bind("_dispatch_after")?,
        async_: bind("_dispatch_async")?,
        async_f: bind("_dispatch_async_f")?,
        semaphore_create: bind("_dispatch_semaphore_create")?,
        semaphore_signal: bind("_dispatch_semaphore_signal")?,
        semaphore_wait: bind("_dispatch_semaphore_wait")?,
        kqueue: bind("_kqueue")?,
        kevent: bind("_kevent")?,
    };
    let (Some(copy), Some(release)) = (
        objc::block::symbol("_Block_copy"),
        objc::block::symbol("_Block_release"),
    ) else {
        return Err(Stop::Skip("no block runtime to copy blocks with".into()));
    };
    darwin::dispatch::block::set_runtime(copy, release);
    let _ = API.set(api);
    Ok(())
}

// A block literal: what clang emits for `^{ ... }`, with the body a Rust
// closure the literal points at.
#[repr(C)]
struct Descriptor {
    reserved: u64,
    size: u64,
}

type Body = Box<dyn Fn() + Send + Sync>;

#[repr(C)]
struct Literal {
    isa: u64,
    flags: i32,
    reserved: i32,
    invoke: unsafe extern "C" fn(*const Literal),
    descriptor: *const Descriptor,
    body: *const Body,
}

static DESCRIPTOR: Descriptor = Descriptor {
    reserved: 0,
    size: size_of::<Literal>() as u64,
};

/// `BLOCK_IS_GLOBAL`.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

unsafe extern "C" fn invoke(block: *const Literal) {
    // SAFETY: a literal `block` built, whose body it leaked.
    unsafe { (*(*block).body)() };
}

fn global_block_class() -> u64 {
    static CLASS: OnceLock<u64> = OnceLock::new();
    *CLASS.get_or_init(|| {
        objc::block::data_symbols()
            .into_iter()
            .find(|(name, _)| name == "__NSConcreteGlobalBlock")
            .map_or(0, |(_, address)| address)
    })
}

/// `^{ body }`.
fn block(body: impl Fn() + Send + Sync + 'static) -> u64 {
    let body: &'static Body = Box::leak(Box::new(Box::new(body) as Body));
    let literal = Box::leak(Box::new(Literal {
        isa: global_block_class(),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke,
        descriptor: &DESCRIPTOR,
        body,
    }));
    literal as *const Literal as u64
}

// What `bsdtests.c` records.
static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILURES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static STOPPED: AtomicBool = AtomicBool::new(false);

fn check(ok: bool, what: impl FnOnce() -> String) {
    match ok {
        true => {
            PASSED.fetch_add(1, Ordering::AcqRel);
        }
        false => FAILURES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(what()),
    }
}

fn test_long(desc: &str, actual: i64, expected: i64) {
    check(actual == expected, || {
        format!("{desc}: {actual}, expected {expected}")
    });
}

fn test_long_less_than(desc: &str, actual: i64, max: i64) {
    check(actual < max, || {
        format!("{desc}: {actual}, expected <{max}")
    });
}

fn test_sizet_less_than_or_equal(desc: &str, actual: u64, max: u64) {
    check(actual <= max, || {
        format!("{desc}: {actual}, expected <={max}")
    });
}

fn test_ptr_notnull(desc: &str, pointer: u64) {
    check(pointer != 0, || format!("{desc}: null"));
}

fn test_errno(desc: &str, actual: i32, expected: i32) {
    check(actual == expected, || {
        format!("{desc}: errno {actual}, expected {expected}")
    });
}

fn test_double_less_than(desc: &str, value: f64, max: f64) {
    check(value < max, || format!("{desc}: {value}, expected <{max}"));
}

/// `test_stop()`: the case is over.
fn test_stop() {
    STOPPED.store(true, Ordering::SeqCst);
}

/// `dispatch_main()`, until `test_stop()`.
fn dispatch_main(limit: Duration) -> Result<(), Stop> {
    let deadline = std::time::Instant::now() + limit;
    while !STOPPED.load(Ordering::SeqCst) {
        darwin::dispatch::queue::drain_main();
        if std::time::Instant::now() > deadline {
            return Err(Stop::Fail(format!(
                "test_stop() not reached within {}s",
                limit.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    Ok(())
}

/// What the case's checks found, as the harness counts them.
fn report(t: &mut T) -> Result<(), Stop> {
    for _ in 0..PASSED.load(Ordering::Acquire) {
        t.check(true, String::new);
    }
    for failure in FAILURES.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        t.check(false, || failure.clone());
    }
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn time(when: u64, delta: i64) -> u64 {
    // SAFETY: bound by `setup`.
    unsafe { (d().time)(when, delta) }
}

fn timer_on(queue: u64) -> Source {
    // SAFETY: a published source type.
    unsafe { (d().source_create)(d().type_timer, 0, 0, queue) }
}

fn global() -> u64 {
    // SAFETY: no pointers.
    unsafe { (d().global_queue)(0, 0) }
}

macro_rules! call {
    ($name:ident($($arg:expr),*)) => {{
        let f = d().$name;
        // SAFETY: bound by `setup`; the arguments are what the C test passes.
        #[allow(unused_unsafe)]
        let result = unsafe { f($($arg),*) };
        result
    }};
}

// dispatch_api.c

unsafe extern "C" fn api_work(_context: *mut c_void) {
    test_stop();
}

fn dispatch_api(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let q = d().main_q;
    test_ptr_notnull("dispatch_get_main_queue", q);
    call!(async_f(d().main_q, 0, api_work as *const () as u64));
    let ran = dispatch_main(Duration::from_secs(10));
    report(t)?;
    ran
}

// dispatch_after.c

unsafe extern "C" fn after_done(_context: *mut c_void) {
    std::thread::sleep(Duration::from_secs(1));
    test_stop();
}

fn dispatch_after(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let main = d().main_q;
    let secs = |s: f64| (s * NSEC_PER_SEC as f64) as i64;
    call!(async_(
        main,
        block(move || {
            let time_a_min = time(0, secs(5.5));
            let time_a = time(0, secs(6.0));
            let time_a_max = time(0, secs(6.5));
            call!(after(
                time_a,
                main,
                block(move || {
                    let now_a = time(0, 0);
                    test_long_less_than(
                        "can't finish faster than 5.5s",
                        0,
                        now_a.wrapping_sub(time_a_min) as i64,
                    );
                    test_long_less_than(
                        "must finish faster than  6.5s",
                        0,
                        time_a_max.wrapping_sub(now_a) as i64,
                    );
                    let time_b_min = time(0, secs(1.5));
                    let time_b = time(0, secs(2.0));
                    let time_b_max = time(0, secs(2.5));
                    call!(after(
                        time_b,
                        main,
                        block(move || {
                            let now_b = time(0, 0);
                            test_long_less_than(
                                "can't finish faster than 1.5s",
                                0,
                                now_b.wrapping_sub(time_b_min) as i64,
                            );
                            test_long_less_than(
                                "must finish faster than  2.5s",
                                0,
                                time_b_max.wrapping_sub(now_b) as i64,
                            );
                            let time_c_min = time(0, 0);
                            let time_c = time(0, 0);
                            let time_c_max = time(0, secs(0.5));
                            call!(after(
                                time_c,
                                main,
                                block(move || {
                                    let now_c = time(0, 0);
                                    test_long_less_than(
                                        "can't finish faster than 0s",
                                        0,
                                        now_c.wrapping_sub(time_c_min) as i64,
                                    );
                                    test_long_less_than(
                                        "must finish faster than .5s",
                                        0,
                                        time_c_max.wrapping_sub(now_c) as i64,
                                    );
                                    call!(async_f(main, 0, after_done as *const () as u64));
                                })
                            ));
                        })
                    ));
                })
            ));
        })
    ));
    let ran = dispatch_main(Duration::from_secs(20));
    report(t)?;
    ran
}

// dispatch_timer.c

static FINALIZED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn timer_fin(context: *mut c_void) {
    check(!context.is_null(), || "finalizer ran: null context".into());
    FINALIZED.store(true, Ordering::SeqCst);
    test_stop();
}

fn dispatch_timer(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let stop_at = 3;
    let main_q = d().main_q;
    for j in 1..=5i64 {
        let s = timer_on(global());
        test_ptr_notnull("dispatch_source_create", s);
        let delta = (j as u64 * NSEC_PER_SEC + NSEC_PER_SEC / 10) as i64;
        call!(set_timer(
            s,
            time(DISPATCH_TIME_NOW, delta),
            DISPATCH_TIME_FOREVER,
            0
        ));
        call!(set_event_handler(
            s,
            block(move || {
                if !FINALIZED.load(Ordering::SeqCst) {
                    test_long_less_than("timer number", j, stop_at);
                }
                call!(release(s));
            })
        ));
        call!(resume(s));
    }
    static I: AtomicI64 = AtomicI64::new(0);
    let s = timer_on(main_q);
    test_ptr_notnull("dispatch_source_create", s);
    call!(set_timer(s, time(DISPATCH_TIME_NOW, 0), NSEC_PER_SEC, 0));
    call!(set_cancel_handler(
        s,
        block(move || {
            test_ptr_notnull("cancel handler run", s);
            call!(release(s));
        })
    ));
    call!(set_event_handler(
        s,
        block(move || {
            let i = I.fetch_add(1, Ordering::SeqCst) + 1;
            if i >= stop_at {
                test_long("i", i, stop_at);
                call!(set_timer(
                    s,
                    time(DISPATCH_TIME_NOW, 0),
                    DISPATCH_TIME_FOREVER,
                    0
                ));
                call!(cancel(s));
            }
        })
    ));
    call!(set_context(s, s));
    call!(set_finalizer_f(s, timer_fin as *const () as u64));
    call!(resume(s));
    let ran = dispatch_main(Duration::from_secs(15));
    report(t)?;
    ran
}

// dispatch_timer_bit31.c

fn dispatch_timer_bit31(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let s = timer_on(d().main_q);
    test_ptr_notnull("dispatch_source_create", s);
    call!(set_timer(
        s,
        time(DISPATCH_TIME_NOW, 0x8000_0000),
        0x8000_0000,
        0
    ));
    let start = now_secs();
    call!(set_event_handler(s, block(move || call!(cancel(s)))));
    call!(set_cancel_handler(
        s,
        block(move || {
            let elapsed = now_secs() - start;
            test_long_less_than("needs to finish faster than 4 seconds", elapsed, 4);
            test_long_less_than("can't finish faster than 2 seconds", 1, elapsed);
            test_stop();
        })
    ));
    call!(resume(s));
    let ran = dispatch_main(Duration::from_secs(10));
    report(t)?;
    ran
}

// dispatch_timer_bit63.c

fn dispatch_timer_bit63(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let interval: u64 = 0x8000_0000_0000_0001;
    let mainq = d().main_q;
    static I: AtomicI64 = AtomicI64::new(0);
    let ds = timer_on(mainq);
    check(ds != 0, || "assert(ds)".into());
    call!(set_event_handler(
        ds,
        block(move || {
            let i = I.fetch_add(1, Ordering::SeqCst);
            check(i < 1, || format!("assert(i < 1): i = {i}"));
        })
    ));
    call!(set_timer(ds, DISPATCH_TIME_NOW, interval, 0));
    call!(resume(ds));
    call!(after(
        time(DISPATCH_TIME_NOW, NSEC_PER_SEC as i64),
        mainq,
        block(test_stop)
    ));
    let ran = dispatch_main(Duration::from_secs(10));
    report(t)?;
    ran
}

// dispatch_timer_set_time.c

fn dispatch_timer_set_time(t: &mut T) -> Result<(), Stop> {
    setup()?;
    static I: AtomicI64 = AtomicI64::new(0);
    let start = now_secs();
    let s = timer_on(d().main_q);
    test_ptr_notnull("dispatch_source_create", s);
    call!(set_timer(
        s,
        time(DISPATCH_TIME_NOW, NSEC_PER_SEC as i64),
        NSEC_PER_SEC,
        0
    ));
    call!(set_cancel_handler(
        s,
        block(move || {
            test_long_less_than("total duration", now_secs() - start, 10);
            test_stop();
            call!(release(s));
        })
    ));
    call!(set_event_handler(
        s,
        block(move || {
            let i = I.fetch_add(1, Ordering::SeqCst) + 1;
            if i >= 15 {
                call!(cancel(s));
            } else if i == 1 {
                call!(set_timer(
                    s,
                    time(DISPATCH_TIME_NOW, 0),
                    NSEC_PER_SEC / 10,
                    0
                ));
            }
        })
    ));
    test_ptr_notnull("dispatch_source_timer_create", s);
    call!(resume(s));
    let ran = dispatch_main(Duration::from_secs(15));
    report(t)?;
    ran
}

// dispatch_timer_short.c

const SHORT_N: usize = 25_000;
const SHORT_DELAY: u64 = NSEC_PER_SEC;
const SHORT_INTERVAL: u64 = 5 * NSEC_PER_USEC;
static SHORT_COUNT: AtomicI64 = AtomicI64::new(0);
static SHORT_STATE: OnceLock<(Vec<u64>, u64, u64)> = OnceLock::new();

unsafe extern "C" fn short_fin(context: *mut c_void) {
    let count = SHORT_COUNT.load(Ordering::SeqCst).max(1) as f64;
    test_long_less_than(
        "Frequency",
        1,
        (SHORT_DELAY as f64 / (count * SHORT_INTERVAL as f64)).ceil() as i64,
    );
    if let Some((timers, q, g)) = SHORT_STATE.get() {
        for &timer in timers {
            call!(cancel(timer));
            call!(release(timer));
        }
        call!(resume(*q));
        call!(release(*q));
        call!(release(*g));
    }
    check(!context.is_null(), || "finalizer ran: null context".into());
    test_stop();
}

fn dispatch_timer_short(t: &mut T) -> Result<(), Stop> {
    setup()?;
    // A large number of timers with a suspended target queue in front of
    // the one measured, <rdar://problem/7401353>.
    let g = call!(group_create());
    let q = call!(queue_create(c"q".as_ptr(), 0));
    let mut timers = Vec::with_capacity(SHORT_N);
    for _ in 0..SHORT_N {
        let timer = timer_on(q);
        call!(set_timer(timer, DISPATCH_TIME_NOW, SHORT_INTERVAL, 0));
        call!(group_enter(g));
        call!(set_registration_handler(
            timer,
            block(move || {
                call!(suspend(timer));
                call!(group_leave(g));
            })
        ));
        call!(resume(timer));
        timers.push(timer);
    }
    // Wait for registration & configuration of all timers.
    call!(group_wait(g, DISPATCH_TIME_FOREVER));
    call!(suspend(q));
    for &timer in &timers {
        call!(resume(timer));
    }
    let _ = SHORT_STATE.set((timers, q, g));

    let s = timer_on(global());
    test_ptr_notnull("dispatch_source_create", s);
    call!(set_timer(s, DISPATCH_TIME_NOW, SHORT_INTERVAL, 0));
    call!(set_event_handler(
        s,
        block(move || {
            if SHORT_COUNT.load(Ordering::SeqCst) == 0 {
                call!(after(
                    time(DISPATCH_TIME_NOW, SHORT_DELAY as i64),
                    global(),
                    block(move || {
                        call!(cancel(s));
                        call!(release(s));
                    })
                ));
            }
            SHORT_COUNT.fetch_add(1, Ordering::SeqCst);
        })
    ));
    call!(set_context(s, s));
    call!(set_finalizer_f(s, short_fin as *const () as u64));
    call!(resume(s));
    let ran = dispatch_main(Duration::from_secs(120));
    report(t)?;
    ran?;
    t.note(format!(
        "{} callbacks in {}s, one every {}us",
        SHORT_COUNT.load(Ordering::SeqCst),
        SHORT_DELAY / NSEC_PER_SEC,
        SHORT_DELAY / SHORT_COUNT.load(Ordering::SeqCst).max(1) as u64 / NSEC_PER_USEC
    ));
    report(t)
}

// dispatch_timer_timeout.c

fn dispatch_timer_timeout(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let mini_interval = 100u64;
    let long_interval = 2_000_000_000u64;
    let timer_queue = call!(queue_create(c"timer_queue".as_ptr(), 0));
    static VALUE: AtomicI64 = AtomicI64::new(5);
    static FIRED: AtomicI64 = AtomicI64::new(0);

    let mini_timer = timer_on(timer_queue);
    call!(set_event_handler(
        mini_timer,
        block(move || {
            FIRED.fetch_add(1, Ordering::SeqCst);
            call!(suspend(timer_queue));
        })
    ));
    call!(set_timer(mini_timer, DISPATCH_TIME_NOW, mini_interval, 0));

    let long_timer = timer_on(global());
    call!(set_event_handler(
        long_timer,
        block(move || {
            VALUE.store(10, Ordering::SeqCst);
            call!(cancel(long_timer));
        })
    ));
    call!(set_timer(
        long_timer,
        time(DISPATCH_TIME_NOW, NSEC_PER_SEC as i64),
        long_interval,
        0
    ));

    call!(resume(mini_timer));
    call!(resume(long_timer));
    std::thread::sleep(Duration::from_secs(6));
    test_long("Checking final value", VALUE.load(Ordering::SeqCst), 10);
    test_long("Mini-timer fired", FIRED.load(Ordering::SeqCst), 1);
    call!(cancel(mini_timer));
    call!(release(mini_timer));
    call!(resume(timer_queue));
    call!(release(timer_queue));
    call!(release(long_timer));
    test_stop();
    report(t)
}

// dispatch_suspend_timer.c

static TWEEDLEDUM: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn suspend_fini(context: *mut c_void) {
    test_ptr_notnull("finalizer ran", context as u64);
    if context as u64 == TWEEDLEDUM.load(Ordering::SeqCst) {
        test_stop();
    }
}

fn dispatch_suspend_timer(t: &mut T) -> Result<(), Stop> {
    setup()?;
    let main_q = d().main_q;
    static I: AtomicI64 = AtomicI64::new(0);
    static I_PRIME: AtomicI64 = AtomicI64::new(0);
    static J: AtomicI64 = AtomicI64::new(0);

    let tweedledee = timer_on(main_q);
    test_ptr_notnull("dispatch_source_timer_create", tweedledee);
    call!(set_timer(
        tweedledee,
        time(DISPATCH_TIME_NOW, NSEC_PER_SEC as i64),
        NSEC_PER_SEC,
        0
    ));
    call!(set_cancel_handler(
        tweedledee,
        block(move || call!(release(tweedledee)))
    ));
    call!(set_event_handler(
        tweedledee,
        block(move || {
            I_PRIME.fetch_add(call!(get_data(tweedledee)) as i64, Ordering::SeqCst);
            if I.fetch_add(1, Ordering::SeqCst) + 1 == 10 {
                call!(cancel(tweedledee));
            }
        })
    ));
    call!(set_context(tweedledee, tweedledee));
    call!(set_finalizer_f(
        tweedledee,
        suspend_fini as *const () as u64
    ));
    call!(resume(tweedledee));

    let tweedledum = timer_on(main_q);
    TWEEDLEDUM.store(tweedledum, Ordering::SeqCst);
    test_ptr_notnull("dispatch_source_timer_create", tweedledum);
    call!(set_timer(
        tweedledum,
        time(
            DISPATCH_TIME_NOW,
            (3 * NSEC_PER_SEC + NSEC_PER_SEC / 2) as i64
        ),
        3 * NSEC_PER_SEC,
        0
    ));
    call!(set_cancel_handler(
        tweedledum,
        block(move || call!(release(tweedledum)))
    ));
    call!(set_event_handler(
        tweedledum,
        block(move || {
            match J.fetch_add(1, Ordering::SeqCst) + 1 {
                1 => call!(suspend(tweedledee)),
                2 => {
                    test_long("tweedledee tick count", I.load(Ordering::SeqCst), 3);
                    test_long(
                        "tweedledee virtual tick count",
                        I_PRIME.load(Ordering::SeqCst),
                        3,
                    );
                    call!(resume(tweedledee));
                }
                _ => {
                    test_long("tweedledee tick count", I.load(Ordering::SeqCst), 7);
                    test_long(
                        "tweedledee virtual tick count",
                        I_PRIME.load(Ordering::SeqCst),
                        9,
                    );
                    call!(cancel(tweedledum));
                }
            }
        })
    ));
    call!(set_context(tweedledum, tweedledum));
    call!(set_finalizer_f(
        tweedledum,
        suspend_fini as *const () as u64
    ));
    call!(resume(tweedledum));
    let ran = dispatch_main(Duration::from_secs(20));
    report(t)?;
    ran
}

// dispatch_drift.c

fn dispatch_drift(t: &mut T) -> Result<(), Stop> {
    setup()?;
    // 100 times a second, for 25 seconds.
    let interval: u64 = 1_000_000_000 / 100;
    let interval_d = interval as f64 / 1_000_000_000.0;
    let target = (25.0 / interval_d) as u32;
    struct Drift {
        count: u32,
        last_jitter: f64,
        drift_sum: f64,
        first: f64,
    }
    static DRIFT: Mutex<Drift> = Mutex::new(Drift {
        count: 0,
        last_jitter: 0.0,
        drift_sum: 0.0,
        first: 0.0,
    });
    let timer = timer_on(d().main_q);
    test_ptr_notnull("dispatch_source_create", timer);
    call!(set_timer(
        timer,
        time(DISPATCH_TIME_NOW, interval as i64),
        interval,
        0
    ));
    call!(set_event_handler(
        timer,
        block(move || {
            let now = now_f64();
            let mut drift = DRIFT.lock().unwrap_or_else(|e| e.into_inner());
            if drift.count == 0 {
                drift.first = now;
            }
            let goal = drift.first + interval_d * f64::from(drift.count);
            let jitter = goal - now;
            drift.drift_sum += jitter - drift.last_jitter;
            drift.count += 1;
            if target <= drift.count {
                let sum = (drift.drift_sum / f64::from(drift.count - 1)).abs();
                test_double_less_than("drift", sum, 0.001);
                test_stop();
            }
            drift.last_jitter = jitter;
        })
    ));
    call!(resume(timer));
    let ran = dispatch_main(Duration::from_secs(40));
    report(t)?;
    ran
}

// dispatch_proc.c

const PID_CNT: usize = 5;
static EVENT_CNT: AtomicI64 = AtomicI64::new(0);

fn spawn_sleep() -> i32 {
    let args = [c"/bin/sleep".as_ptr(), c"2".as_ptr(), std::ptr::null()];
    let mut pid = 0;
    // SAFETY: a NUL-terminated argv, and no file actions or attributes.
    let res = unsafe {
        libc::posix_spawnp(
            &mut pid,
            args[0],
            std::ptr::null(),
            std::ptr::null(),
            args.as_ptr() as *const *mut c_char,
            std::ptr::null(),
        )
    };
    check(res == 0, || format!("posix_spawnp: {res}"));
    pid
}

fn test_proc(bad_pid: i32) {
    EVENT_CNT.store(0, Ordering::SeqCst);
    // Without POSIX_SPAWN_START_SUSPENDED, which Linux has not: `sleep 2`
    // outlasts registering its observers by far.
    let pid = spawn_sleep();
    let group = call!(group_create());
    let monitor_pid = if bad_pid != 0 { bad_pid } else { pid }; // rdar://problem/8090801
    let mut proc_s = Vec::new();
    for _ in 0..PID_CNT {
        call!(group_enter(group));
        let proc = call!(source_create(
            d().type_proc,
            monitor_pid as u64,
            DISPATCH_PROC_EXIT,
            global()
        ));
        test_ptr_notnull("dispatch_source_proc_create", proc);
        call!(set_event_handler(
            proc,
            block(move || {
                let flags = call!(get_data(proc));
                test_long(
                    "DISPATCH_PROC_EXIT",
                    flags as i64,
                    DISPATCH_PROC_EXIT as i64,
                );
                EVENT_CNT.fetch_add(1, Ordering::SeqCst);
                call!(cancel(proc));
            })
        ));
        call!(set_cancel_handler(
            proc,
            block(move || call!(group_leave(group)))
        ));
        call!(resume(proc));
        proc_s.push(proc);
    }
    if call!(group_wait(
        group,
        time(DISPATCH_TIME_NOW, (10 * NSEC_PER_SEC) as i64)
    )) != 0
    {
        for &proc in &proc_s {
            call!(cancel(proc));
        }
        call!(group_wait(group, DISPATCH_TIME_FOREVER));
    }
    for &proc in &proc_s {
        call!(release(proc));
    }
    call!(release(group));
    // Five seconds for any bug that makes too many events to show.
    call!(after(
        time(DISPATCH_TIME_NOW, (5 * NSEC_PER_SEC) as i64),
        d().main_q,
        block(move || {
            let mut status = 0;
            // SAFETY: a child this test spawned.
            let res2 = unsafe { libc::waitpid(pid, &mut status, 0) };
            check(res2 != -1, || "assert(res2 != -1)".into());
            test_long(
                "Sub-process exited",
                i64::from(libc::WEXITSTATUS(status) | libc::WTERMSIG(status)),
                0,
            );
            test_long(
                "Event count",
                EVENT_CNT.load(Ordering::SeqCst),
                PID_CNT as i64,
            );
            if bad_pid != 0 {
                test_stop();
            } else {
                call!(async_(d().main_q, block(move || test_proc(pid))));
            }
        })
    ));
}

fn dispatch_proc(t: &mut T) -> Result<(), Stop> {
    setup()?;
    test_proc(0);
    let ran = dispatch_main(Duration::from_secs(40));
    report(t)?;
    ran
}

// dispatch_select.c

static ACTUAL: AtomicI64 = AtomicI64::new(0);

unsafe extern "C" fn select_finish(context: *mut c_void) {
    check(!context.is_null(), || "finish: null context".into());
    test_stop();
}

fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn stage1(stage: i32) {
    let path = c"/dev/random";
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd == -1 {
        check(false, || format!("open /dev/random: {}", errno_now()));
        return test_stop();
    }
    let main_q = d().main_q;
    test_ptr_notnull("main_q", main_q);
    let source = call!(source_create(d().type_read, fd as u64, 0, main_q));
    test_ptr_notnull("select source", source);
    call!(set_event_handler(
        source,
        block(move || {
            let buffer_size = 500 * 1024;
            let mut buffer = vec![0u8; buffer_size];
            // SAFETY: a buffer of `buffer_size`.
            let sz = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer_size) };
            test_sizet_less_than_or_equal("kevent read 1", sz as u64, buffer_size as u64 + 1);
            call!(cancel(source));
        })
    ));
    call!(set_cancel_handler(
        source,
        block(move || {
            // SAFETY: the descriptor this stage opened.
            let res = unsafe { libc::close(fd) };
            test_errno("close", if res == -1 { errno_now() } else { 0 }, 0);
            call!(release(source));
            if stage == 1 {
                call!(async_(d().main_q, block(stage2)));
            }
        })
    ));
    if stage == 3 {
        call!(set_context(source, source));
        call!(set_finalizer_f(source, select_finish as *const () as u64));
    }
    call!(resume(source));
}

/// `dispatch_test_get_large_file`: 2 MiB of random bytes in a temp file.
fn large_file() -> std::path::PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("dispatch_test.{}", std::process::id()));
    let mut bytes = vec![0u8; 2 * 1024 * 1024];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i.wrapping_mul(2654435761) >> 13) as u8;
    }
    std::fs::write(&path, &bytes).expect("the large file");
    path
}

/// `dispatch_test_check_evfilt_read_for_fd`: whether a kqueue reports the
/// descriptor readable within a second.
fn check_evfilt_read_for_fd(fd: i32) -> bool {
    let kq = call!(kqueue());
    let mut ke = Kevent {
        ident: fd as usize,
        filter: -1,
        flags: 0x0001 | 0x0004,
        ..Kevent::default()
    };
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let r = call!(kevent(kq, &ke, 1, &mut ke, 1, &timeout));
    // SAFETY: the kqueue made above.
    unsafe { libc::close(kq) };
    r > 0
}

fn stage2() {
    let path = large_file();
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    let _ = std::fs::remove_file(&path);
    if fd == -1 {
        check(false, || format!("open large file: {}", errno_now()));
        return test_stop();
    }
    if !check_evfilt_read_for_fd(fd) {
        // `test_skip`: upstream moves on to stage 3.
        // SAFETY: the descriptor above.
        unsafe { libc::close(fd) };
        call!(async_(d().main_q, block(|| stage1(3))));
        return;
    }
    // SAFETY: the descriptor above.
    let expected = unsafe { libc::lseek(fd, 0, libc::SEEK_END) } as i64;
    // SAFETY: as above.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    ACTUAL.store(0, Ordering::SeqCst);
    let main_q = d().main_q;
    test_ptr_notnull("main_q", main_q);
    let source = call!(source_create(d().type_read, fd as u64, 0, main_q));
    test_ptr_notnull("kevent source", source);
    call!(set_event_handler(
        source,
        block(move || {
            let est = call!(get_data(source));
            test_sizet_less_than_or_equal(
                "estimated",
                est,
                (expected - ACTUAL.load(Ordering::SeqCst)) as u64,
            );
            let buffer_size = 500 * 1024;
            let mut buffer = vec![0u8; buffer_size];
            // SAFETY: a buffer of `buffer_size`.
            let mut sz = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer_size) };
            ACTUAL.fetch_add(sz as i64, Ordering::SeqCst);
            if sz < buffer_size as isize {
                // SAFETY: as above.
                sz = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer_size) };
                ACTUAL.fetch_add(sz as i64, Ordering::SeqCst);
                test_long("EOF", sz as i64, 0);
                call!(cancel(source));
            }
        })
    ));
    call!(set_cancel_handler(
        source,
        block(move || {
            test_long("bytes read", ACTUAL.load(Ordering::SeqCst), expected);
            // SAFETY: the descriptor this stage opened.
            let res = unsafe { libc::close(fd) };
            test_errno("close", if res == -1 { errno_now() } else { 0 }, 0);
            call!(release(source));
            call!(async_(d().main_q, block(|| stage1(3))));
        })
    ));
    call!(resume(source));
}

fn dispatch_select(t: &mut T) -> Result<(), Stop> {
    setup()?;
    call!(async_(d().main_q, block(|| stage1(1))));
    let ran = dispatch_main(Duration::from_secs(20));
    report(t)?;
    ran
}

// dispatch_vnode.c

fn dispatch_vnode(t: &mut T) -> Result<(), Stop> {
    setup()?;
    const ITERATIONS: i64 = 1000;
    let dir = std::env::temp_dir();
    let path1 = dir.join(format!("dispatchtest_vnode.{}.a", std::process::id()));
    let path2 = dir.join(format!("dispatchtest_vnode.{}.b", std::process::id()));
    std::fs::write(&path1, b"").map_err(|e| Stop::Fail(format!("mkstemp: {e}")))?;
    let _ = std::fs::remove_file(&path2);
    let (mut current, mut dest) = (path1, path2);
    let renamed = call!(semaphore_create(0));
    let g = call!(group_create());
    let mut notifications = 0;
    for iteration in 1..=ITERATIONS {
        let cpath = std::ffi::CString::new(current.as_os_str().as_encoded_bytes()).unwrap();
        // `O_EVTONLY` has no Linux equivalent; a read-only descriptor watches as well.
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
        if fd == -1 {
            test_errno("open", errno_now(), 0);
            break;
        }
        let monitor = call!(source_create(
            d().type_vnode,
            fd as u64,
            DISPATCH_VNODE_RENAME,
            global()
        ));
        call!(set_event_handler(
            monitor,
            block(move || {
                call!(semaphore_signal(renamed));
            })
        ));
        call!(set_cancel_handler(
            monitor,
            block(move || {
                // SAFETY: the descriptor this iteration opened.
                unsafe { libc::close(fd) };
            })
        ));
        call!(group_enter(g));
        call!(set_registration_handler(
            monitor,
            block(move || call!(group_leave(g)))
        ));
        call!(resume(monitor));
        call!(group_wait(g, DISPATCH_TIME_FOREVER));
        if let Err(error) = std::fs::rename(&current, &dest) {
            check(false, || format!("rename: {error}"));
            break;
        }
        std::mem::swap(&mut current, &mut dest);
        if call!(semaphore_wait(
            renamed,
            time(DISPATCH_TIME_NOW, (10 * 1000 * NSEC_PER_USEC) as i64)
        )) == 0
        {
            notifications += 1;
            call!(cancel(monitor));
        } else {
            call!(cancel(monitor));
            call!(semaphore_signal(renamed));
        }
        call!(release(monitor));
        if iteration == 20 && notifications == 0 {
            t.note("no notification in the first 20 iterations");
        }
    }
    let _ = std::fs::remove_file(&current);
    call!(release(g));
    call!(release(renamed));
    test_long("VNODE RENAME notifications", notifications, ITERATIONS);
    test_stop();
    report(t)
}

macro_rules! case {
    ($name:literal, $kind:expr, $source:literal, $timeout:literal, $run:expr) => {
        Case {
            name: $name,
            kind: $kind,
            source: $source,
            timeout_secs: $timeout,
            run: $run,
        }
    };
}

const CASES: &[Case] = &[
    case!(
        "dispatch_api",
        Kind::Upstream,
        "dispatch_api.c",
        20,
        dispatch_api
    ),
    case!(
        "dispatch_after",
        Kind::Upstream,
        "dispatch_after.c",
        30,
        dispatch_after
    ),
    case!(
        "dispatch_timer",
        Kind::Upstream,
        "dispatch_timer.c",
        30,
        dispatch_timer
    ),
    case!(
        "dispatch_timer_bit31",
        Kind::Upstream,
        "dispatch_timer_bit31.c",
        20,
        dispatch_timer_bit31
    ),
    case!(
        "dispatch_timer_bit63",
        Kind::Upstream,
        "dispatch_timer_bit63.c",
        20,
        dispatch_timer_bit63
    ),
    case!(
        "dispatch_timer_set_time",
        Kind::Upstream,
        "dispatch_timer_set_time.c",
        30,
        dispatch_timer_set_time
    ),
    case!(
        "dispatch_timer_short",
        Kind::Upstream,
        "dispatch_timer_short.c",
        150,
        dispatch_timer_short
    ),
    case!(
        "dispatch_timer_timeout",
        Kind::Upstream,
        "dispatch_timer_timeout.c",
        30,
        dispatch_timer_timeout
    ),
    case!(
        "dispatch_suspend_timer",
        Kind::Upstream,
        "dispatch_suspend_timer.c",
        30,
        dispatch_suspend_timer
    ),
    case!(
        "dispatch_drift",
        Kind::Upstream,
        "dispatch_drift.c, ACCEPTABLE_DRIFT 0.001",
        60,
        dispatch_drift
    ),
    case!(
        "dispatch_proc",
        Kind::Adapted,
        "dispatch_proc.c; /bin/sleep spawned running rather than POSIX_SPAWN_START_SUSPENDED, which Linux has not",
        60,
        dispatch_proc
    ),
    case!(
        "dispatch_select",
        Kind::Upstream,
        "dispatch_select.c, with dispatch_test.c's large file",
        30,
        dispatch_select
    ),
    case!(
        "dispatch_vnode",
        Kind::Adapted,
        "dispatch_vnode.c; O_RDONLY for O_EVTONLY, which Linux has not",
        60,
        dispatch_vnode
    ),
];

#[test]
fn libdispatch_conformance() {
    conformance::run("libdispatch_conformance", "libdispatch", UPSTREAM, CASES);
}
