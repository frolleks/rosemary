//! NSRunLoop and NSTimer conformance: `TestRunLoop.swift` and `TestTimer.swift`
//! from swift-corelibs-foundation (swiftlang/swift-corelibs-foundation,
//! `Tests/Foundation/`), Apple's open-source Foundation and the one whose tests
//! are published, ported case by case and sent the messages their Swift sends,
//! as a guest sends them.
//!
//! XCTest runs a case on the main thread, and `test_runLoopInit` and
//! `test_mainDispatchQueueCallout` depend on it: so this suite has its own
//! `main` (`harness = false`), and each case runs on its process's main thread.
//!
//! What the port supplies that Swift does: a `Timer` block or a
//! `DispatchQueue.main.async` closure is a block literal built here; `Date` is
//! an `NSDate`, and two `Date`s are equal when their intervals are; an
//! expectation is a flag, and `waitForExpectations(timeout:)` turns the
//! current run loop in the default mode until it is set or the time is up, as
//! XCTest's waiter does.
//!
//! ```text
//! cargo test -p foundation --test runloop_conformance
//! ```

#[path = "../../darwin/tests/conformance/mod.rs"]
mod conformance;

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::rc::Rc;

use conformance::{Case, Import, Kind, Stop, T, bind};
use objc::object::Id;
use objc::sel::Sel;

const UPSTREAM: &str = "swift-corelibs-foundation main Tests/Foundation/{TestRunLoop,TestTimer}.swift";

/// What a guest's import of `symbol` binds to, among Foundation's and
/// CoreFoundation's exports and then the system's.
fn address(symbol: &str) -> Option<u64> {
    let data = foundation::data_symbols()
        .into_iter()
        .chain(corefoundation::data_symbols())
        .find(|(name, _)| name == symbol)
        .map(|(_, addr)| addr);
    let bare = symbol.strip_prefix('_').unwrap_or(symbol);
    data.or_else(|| foundation::symbol(bare))
        .or_else(|| corefoundation::symbol(bare))
        .or_else(|| conformance::address(symbol))
}

fn import<F: Copy>(symbol: &'static str) -> Import<F> {
    bind(symbol, address(symbol))
}

/// The class a guest's `_OBJC_CLASS_$_<name>` import binds to.
fn class(symbol: &'static str) -> Result<Id, Stop> {
    let class: Import<Id> = import(symbol);
    class.get()
}

/// The object a guest's import of an `NSString *const` datum reads.
fn string_constant(symbol: &'static str) -> Result<Id, Stop> {
    let cell: Import<*const Id> = import(symbol);
    // SAFETY: a datum cell holding the constant's object.
    Ok(unsafe { *cell.get()? })
}

/// `objc_msgSend` as `F`, for `selector` sent to `receiver`, or the failure an
/// unrecognized selector is.
fn send<F: Copy>(receiver: Id, selector: &str) -> Result<(F, Sel), Stop> {
    assert_eq!(size_of::<F>(), size_of::<usize>());
    let sel = objc::sel::get(selector);
    if receiver.is_null() {
        return Err(Stop::Fail(format!(
            "-{selector} sent to nil, which upstream unwraps"
        )));
    }
    // SAFETY: a live object or class.
    let class = unsafe { objc::object::class_of(receiver) }.expect("a live object");
    if class.method(sel).is_none() {
        return Err(Stop::Fail(format!(
            "unrecognized selector -[{} {selector}]",
            // SAFETY: a class's name, which lives as long as it.
            unsafe { std::ffi::CStr::from_ptr(class.name()) }.to_string_lossy()
        )));
    }
    let entry = objc::msg::entry();
    // SAFETY: `objc_msgSend`, called as the method's signature, which `F` is.
    Ok((
        unsafe { std::mem::transmute_copy::<*const c_void, F>(&entry) },
        sel,
    ))
}

fn id(receiver: Id, selector: &str) -> Result<Id, Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel) -> Id>(receiver, selector)?;
    Ok(unsafe { f(receiver, sel) })
}

fn id_with(receiver: Id, selector: &str, arg: Id) -> Result<Id, Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, Id) -> Id>(receiver, selector)?;
    Ok(unsafe { f(receiver, sel, arg) })
}

fn void(receiver: Id, selector: &str) -> Result<(), Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel)>(receiver, selector)?;
    unsafe { f(receiver, sel) };
    Ok(())
}

fn void_with2(receiver: Id, selector: &str, a: Id, b: Id) -> Result<(), Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, Id, Id)>(receiver, selector)?;
    unsafe { f(receiver, sel, a, b) };
    Ok(())
}

fn void_with(receiver: Id, selector: &str, a: Id) -> Result<(), Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, Id)>(receiver, selector)?;
    unsafe { f(receiver, sel, a) };
    Ok(())
}

fn boolean(receiver: Id, selector: &str) -> Result<bool, Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel) -> u8>(receiver, selector)?;
    Ok(unsafe { f(receiver, sel) } != 0)
}

fn double(receiver: Id, selector: &str) -> Result<f64, Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel) -> f64>(receiver, selector)?;
    Ok(unsafe { f(receiver, sel) })
}

/// `==` on two Swift values bridged from objects: `isEqual:`.
fn equal(a: Id, b: Id) -> Result<bool, Stop> {
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, Id) -> u8>(a, "isEqual:")?;
    Ok(unsafe { f(a, sel, b) } != 0)
}

fn text(string: Id) -> String {
    String::from_utf8_lossy(&unsafe { foundation::string::bytes(string) }).into_owned()
}

struct Pool(*mut c_void);

impl Pool {
    fn new() -> Pool {
        foundation::bootstrap();
        Pool(objc::arc::pool_push())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        objc::arc::pool_pop(self.0);
    }
}

// Block literals: a `Timer` block is `void (^)(NSTimer *)`, a dispatch block
// `void (^)(void)`; both are global literals, which `_Block_copy` keeps as they
// are, carrying a closure of this file's.

#[repr(C)]
struct Descriptor {
    reserved: u64,
    size: u64,
}

type Body = Box<dyn Fn(Id)>;

#[repr(C)]
struct Literal {
    isa: u64,
    flags: i32,
    reserved: i32,
    invoke: *const c_void,
    descriptor: *const Descriptor,
    body: *const Body,
}

static DESCRIPTOR: Descriptor = Descriptor {
    reserved: 0,
    size: size_of::<Literal>() as u64,
};

/// `BLOCK_IS_GLOBAL`.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

unsafe extern "C" fn invoke_with(block: *const Literal, argument: Id) {
    // SAFETY: a literal this file built, whose body it leaked.
    unsafe { (*(*block).body)(argument) };
}

unsafe extern "C" fn invoke_void(block: *const Literal) {
    // SAFETY: as above.
    unsafe { (*(*block).body)(std::ptr::null_mut()) };
}

fn literal(invoke: *const c_void, body: impl Fn(Id) + 'static) -> Id {
    let body: &'static Body = Box::leak(Box::new(Box::new(body) as Body));
    let isa = objc::block::data_symbols()
        .into_iter()
        .find(|(name, _)| name == "__NSConcreteGlobalBlock")
        .map_or(0, |(_, address)| address);
    let literal = Box::leak(Box::new(Literal {
        isa,
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke,
        descriptor: &DESCRIPTOR,
        body,
    }));
    literal as *mut Literal as Id
}

/// `{ (timer: Timer) in ... }`
fn timer_block(body: impl Fn(Id) + 'static) -> Id {
    literal(invoke_with as *const c_void, body)
}

/// `{ ... }`, for `DispatchQueue.async`.
fn void_block(body: impl Fn() + 'static) -> Id {
    literal(invoke_void as *const c_void, move |_| body())
}

/// What an `XCTAssert` inside a closure records: the closure runs inside the
/// run loop, after the case has lent `T` to nobody.
#[derive(Clone, Default)]
struct Inside(Rc<RefCell<(usize, Vec<String>)>>);

impl Inside {
    fn check(&self, ok: bool, what: impl FnOnce() -> String) {
        let mut state = self.0.borrow_mut();
        match ok {
            true => state.0 += 1,
            false => state.1.push(what()),
        }
    }

    /// A message the closure sent that failed, as the exception it would be.
    fn stopped<R>(&self, result: Result<R, Stop>) -> Option<R> {
        match result {
            Ok(value) => Some(value),
            Err(Stop::Fail(what)) => {
                self.check(false, || what);
                None
            }
            Err(Stop::Unbound(symbol)) => {
                self.check(false, || format!("called unbound {symbol}"));
                None
            }
            Err(Stop::Skip(why)) => {
                self.check(false, || why);
                None
            }
        }
    }

    fn into(self, t: &mut T) {
        let (passed, failures) = std::mem::take(&mut *self.0.borrow_mut());
        for _ in 0..passed {
            t.check(true, String::new);
        }
        for failure in failures {
            t.check(false, || failure);
        }
    }
}

fn run_loop_class() -> Result<Id, Stop> {
    class("_OBJC_CLASS_$_NSRunLoop")
}

fn timer_class() -> Result<Id, Stop> {
    class("_OBJC_CLASS_$_NSTimer")
}

fn date_class() -> Result<Id, Stop> {
    class("_OBJC_CLASS_$_NSDate")
}

/// `Date()`.
fn date_now() -> Result<Id, Stop> {
    id(date_class()?, "date")
}

/// `Date(timeIntervalSinceNow:)`, and `Date(timeInterval:since: Date())`.
fn date_since_now(seconds: f64) -> Result<Id, Stop> {
    let class = date_class()?;
    let (f, sel) =
        send::<unsafe extern "C" fn(Id, Sel, f64) -> Id>(class, "dateWithTimeIntervalSinceNow:")?;
    Ok(unsafe { f(class, sel, seconds) })
}

/// `RunLoop.Mode.default`.
fn default_mode() -> Result<Id, Stop> {
    string_constant("_NSDefaultRunLoopMode")
}

/// `RunLoop.Mode.common`.
fn common_modes() -> Result<Id, Stop> {
    string_constant("_NSRunLoopCommonModes")
}

/// `Timer.scheduledTimer(withTimeInterval:repeats:block:)`.
fn scheduled_timer(interval: f64, repeats: bool, block: Id) -> Result<Id, Stop> {
    let class = timer_class()?;
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, f64, u8, Id) -> Id>(
        class,
        "scheduledTimerWithTimeInterval:repeats:block:",
    )?;
    Ok(unsafe { f(class, sel, interval, repeats as u8, block) })
}

/// `runLoop.add(timer, forMode:)`.
fn add_timer(run_loop: Id, timer: Id, mode: Id) -> Result<(), Stop> {
    void_with2(run_loop, "addTimer:forMode:", timer, mode)
}

/// `runLoop.run(mode:before:)`.
fn run_mode(run_loop: Id, mode: Id, limit: Id) -> Result<bool, Stop> {
    let (f, sel) =
        send::<unsafe extern "C" fn(Id, Sel, Id, Id) -> u8>(run_loop, "runMode:beforeDate:")?;
    Ok(unsafe { f(run_loop, sel, mode, limit) } != 0)
}

/// `runLoop.run(until:)`.
fn run_until(run_loop: Id, limit: Id) -> Result<(), Stop> {
    void_with(run_loop, "runUntilDate:", limit)
}

/// `waitForExpectations(timeout:)` for one expectation: XCTest's waiter turns
/// the current run loop in the default mode until it is fulfilled.
fn wait_for(fulfilled: &Cell<bool>, timeout: f64) -> Result<bool, Stop> {
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let start = std::time::Instant::now();
    while !fulfilled.get() && start.elapsed().as_secs_f64() < timeout {
        let _pool = Pool::new();
        run_until(run_loop, date_since_now(0.1)?)?;
        if !fulfilled.get() {
            // A loop with nothing in it returns at once; the waiter's own
            // timer is what keeps XCTest's from spinning.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    Ok(fulfilled.get())
}

// ---- TestRunLoop.swift ----

fn test_constants(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let common = text(common_modes()?);
    t.check(common == "kCFRunLoopCommonModes", || {
        format!("{common} is not equal to kCFRunLoopCommonModes")
    });
    let default = text(default_mode()?);
    t.check(default == "kCFRunLoopDefaultMode", || {
        format!("{default} is not equal to kCFRunLoopDefaultMode")
    });
    Ok(())
}

fn test_run_loop_init(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let class = run_loop_class()?;
    let main_run_loop = id(class, "mainRunLoop")?;
    let current_run_loop = id(class, "currentRunLoop")?;

    let second_access_of_main_loop = id(class, "mainRunLoop")?;
    t.check(equal(main_run_loop, second_access_of_main_loop)?, || {
        "fetching the main loop a second time should be equal".into()
    });
    t.check(main_run_loop == second_access_of_main_loop, || {
        "fetching the main loop a second time should be identical".into()
    });

    let second_access_of_current_loop = id(class, "currentRunLoop")?;
    t.check(equal(current_run_loop, second_access_of_current_loop)?, || {
        "fetching the current loop a second time should be equal".into()
    });
    t.check(current_run_loop == second_access_of_current_loop, || {
        "fetching the current loop a second time should be identical".into()
    });

    t.check(equal(main_run_loop, current_run_loop)?, || {
        "the current run loop should be the main loop".into()
    });
    Ok(())
}

fn test_run_loop_run_mode(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let time_interval = 0.05;
    let end_date = date_since_now(time_interval)?;

    let flag = Rc::new(Cell::new(false));
    let inside = Inside::default();
    let default = default_mode()?;
    let dummy_timer = scheduled_timer(0.01, false, {
        let (flag, inside) = (flag.clone(), inside.clone());
        timer_block(move |_| {
            flag.set(true);
            let Some(mode) = inside.stopped(id(run_loop, "currentMode")) else {
                return;
            };
            if mode.is_null() {
                inside.check(false, || "Run loop mode is not defined".into());
                return;
            }
            if let Some(same) = inside.stopped(equal(mode, default)) {
                inside.check(same, || format!("currentMode is {}, not .default", text(mode)));
            }
        })
    })?;
    add_timer(run_loop, dummy_timer, default)?;
    let result = run_mode(run_loop, default, end_date)?;

    inside.into(t);
    t.check(result, || "run(mode:before:) returned false".into());
    t.check(flag.get(), || "the timer did not fire".into());
    Ok(())
}

fn test_run_loop_limit_date(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let time_interval = 1.0;
    let expected_time_interval = double(date_since_now(time_interval)?, "timeIntervalSince1970")?;

    let dummy_timer = scheduled_timer(time_interval, false, timer_block(|_| {}))?;
    add_timer(run_loop, dummy_timer, default_mode()?)?;

    let limit = id_with(run_loop, "limitDateForMode:", default_mode()?)?;
    if limit.is_null() {
        t.note("limitDate(forMode:) was nil, so upstream checks nothing");
        return Ok(());
    }
    let timer_tick_interval = double(limit, "timeIntervalSince1970")?;
    let off = (timer_tick_interval - expected_time_interval).abs();
    t.check(off < 0.01, || {
        format!("limit date {off}s from the timer's fire date, not under 0.01")
    });
    Ok(())
}

fn test_run_loop_poll(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let start_date = std::time::Instant::now();
    run_until(run_loop, date_now()?)?;
    let elapsed = start_date.elapsed().as_secs_f64();
    t.check(elapsed < 0.5, || format!("run(until: Date()) took {elapsed}s"));
    Ok(())
}

fn test_common_modes(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let done = Rc::new(Cell::new(false));
    let class = timer_class()?;
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, f64, u8, Id) -> Id>(
        class,
        "timerWithTimeInterval:repeats:block:",
    )?;
    let timer = unsafe {
        f(class, sel, 1.0, 0, {
            let done = done.clone();
            timer_block(move |_| done.set(true))
        })
    };
    add_timer(run_loop, timer, common_modes()?)?;
    let fulfilled = wait_for(&done, 10.0)?;
    t.check(fulfilled, || {
        "Asynchronous wait failed: exceeded timeout of 10 seconds, with unfulfilled expectations: \"The timer has fired\"".into()
    });
    Ok(())
}

// `TestPort`: a `Port` subclass recording the modes it is scheduled in. One
// per case process, so its state is the process's.
thread_local! {
    static PORT_VALID: Cell<bool> = const { Cell::new(true) };
    static PORT_MODES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static PORT_DEALLOCATED: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" fn test_port_is_valid(_receiver: Id, _sel: Sel) -> u8 {
    PORT_VALID.get() as u8
}

/// `guard isValid else { return }; _isValid = false; post(...)`.
unsafe extern "C" fn test_port_invalidate(receiver: Id, _sel: Sel) {
    if !PORT_VALID.get() {
        return;
    }
    PORT_VALID.set(false);
    let center = id(class("_OBJC_CLASS_$_NSNotificationCenter").ok().unwrap(), "defaultCenter")
        .ok()
        .unwrap();
    let name = string_constant("_NSPortDidBecomeInvalidNotification").ok().unwrap();
    let _ = void_with2(center, "postNotificationName:object:", name, receiver);
}

unsafe extern "C" fn test_port_schedule(_receiver: Id, _sel: Sel, _run_loop: Id, mode: Id) {
    PORT_MODES.with_borrow_mut(|modes| modes.push(text(mode)));
}

unsafe extern "C" fn test_port_remove(_receiver: Id, _sel: Sel, _run_loop: Id, mode: Id) {
    let mode = text(mode);
    PORT_MODES.with_borrow_mut(|modes| modes.retain(|m| *m != mode));
}

/// `deinit { invalidate(); sentinel() }`, then `NSPort`'s own.
unsafe extern "C" fn test_port_dealloc(receiver: Id, sel: Sel) {
    unsafe { test_port_invalidate(receiver, objc::sel::get("invalidate")) };
    PORT_DEALLOCATED.set(true);
    let port = objc::class::lookup(c"NSPort").expect("bound by the case");
    let dealloc = port.method(sel).expect("NSObject's -dealloc");
    let f: unsafe extern "C" fn(Id, Sel) = unsafe { std::mem::transmute(dealloc.implementation()) };
    unsafe { f(receiver, sel) };
}

fn test_port_class() -> Result<Id, Stop> {
    let port = class("_OBJC_CLASS_$_NSPort")?;
    // SAFETY: a class this runtime registered.
    let port = unsafe { objc::class::from_ptr(port as *const objc::class::Class) }
        .expect("a class");
    let subclass = objc::class::allocate_pair(Some(port), c"TestPort", 0).expect("a new class");
    for (selector, imp, types) in [
        ("isValid", test_port_is_valid as *const c_void, c"c16@0:8"),
        ("invalidate", test_port_invalidate as *const c_void, c"v16@0:8"),
        ("scheduleInRunLoop:forMode:", test_port_schedule as *const c_void, c"v32@0:8@16@24"),
        ("removeFromRunLoop:forMode:", test_port_remove as *const c_void, c"v32@0:8@16@24"),
        ("dealloc", test_port_dealloc as *const c_void, c"v16@0:8"),
    ] {
        subclass.replace_method(objc::sel::get(selector), imp, types);
    }
    objc::class::register_pair(subclass);
    Ok(objc::class::ptr(subclass) as Id)
}

fn scheduled_modes() -> Vec<String> {
    PORT_MODES.with_borrow(|modes| modes.clone())
}

fn test_adding_removing_ports(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let default = default_mode()?;
    let default_text = text(default);
    {
        let port = id(id(test_port_class()?, "alloc")?, "init")?;
        let custom_mode = foundation::string::from_str("Custom");
        let want = |modes: &[&str]| modes.iter().map(|m| m.to_string()).collect::<Vec<_>>();

        t.check(scheduled_modes().is_empty(), || format!("{:?}, not []", scheduled_modes()));

        void_with2(run_loop, "addPort:forMode:", port, default)?;
        t.check(scheduled_modes() == want(&[&default_text]), || {
            format!("after add .default: {:?}", scheduled_modes())
        });

        void_with2(run_loop, "addPort:forMode:", port, default)?;
        t.check(scheduled_modes() == want(&[&default_text]), || {
            format!("after adding .default again: {:?}", scheduled_modes())
        });

        void_with2(run_loop, "addPort:forMode:", port, custom_mode)?;
        t.check(scheduled_modes() == want(&[&default_text, "Custom"]), || {
            format!("after add Custom: {:?}", scheduled_modes())
        });

        void_with2(run_loop, "removePort:forMode:", port, custom_mode)?;
        t.check(scheduled_modes() == want(&[&default_text]), || {
            format!("after remove Custom: {:?}", scheduled_modes())
        });

        void_with2(run_loop, "addPort:forMode:", port, custom_mode)?;
        t.check(scheduled_modes() == want(&[&default_text, "Custom"]), || {
            format!("after adding Custom again: {:?}", scheduled_modes())
        });

        void(port, "invalidate")?;
        // The end of the `do`: Swift's reference goes.
        objc::arc::release(port);
    }
    t.check(PORT_DEALLOCATED.get(), || {
        "the port outlived its invalidation and its last reference".into()
    });
    Ok(())
}

fn test_main_dispatch_queue_callout(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    let main_q: Import<*const u8> = conformance::import("__dispatch_main_q");
    let main_q = main_q.get()? as u64;
    let dispatch_async: Import<unsafe extern "C" fn(u64, Id)> = conformance::import("_dispatch_async");
    let dispatch_async = dispatch_async.get()?;
    let default = default_mode()?;
    // The block runtime libdispatch copies with, which a loaded program's
    // process has.
    let (Some(copy), Some(release)) = (
        objc::block::symbol("_Block_copy"),
        objc::block::symbol("_Block_release"),
    ) else {
        return Err(Stop::Skip("no block runtime to copy blocks with".into()));
    };
    darwin::dispatch::block::set_runtime(copy, release);

    let async_executed = Rc::new(Cell::new(false));
    let set = {
        let flag = async_executed.clone();
        move || flag.set(true)
    };
    unsafe { dispatch_async(main_q, void_block(set.clone())) };
    let _ = run_mode(run_loop, default, date_since_now(2.0)?)?;
    t.check(async_executed.get(), || "Main queue async code should be executed".into());

    async_executed.set(false);
    unsafe { dispatch_async(main_q, void_block(set)) };
    let _ = run_mode(run_loop, default, date_since_now(2.0)?)?;
    t.check(async_executed.get(), || "Main queue async code should be executed".into());

    let timer_fired = Rc::new(Cell::new(false));
    let dummy_timer = scheduled_timer(0.5, false, {
        let fired = timer_fired.clone();
        timer_block(move |_| fired.set(true))
    })?;
    add_timer(run_loop, dummy_timer, default)?;
    let _ = run_mode(run_loop, default, date_since_now(2.0)?)?;
    t.check(timer_fired.get(), || "Time should fire already".into());
    Ok(())
}

// ---- TestTimer.swift ----

/// `Timer(fire:interval:repeats:block:)`.
fn timer_with_fire_date(fire_date: Id, interval: f64, repeats: bool, block: Id) -> Result<Id, Stop> {
    let alloc = id(timer_class()?, "alloc")?;
    let (f, sel) = send::<unsafe extern "C" fn(Id, Sel, Id, f64, u8, Id) -> Id>(
        alloc,
        "initWithFireDate:interval:repeats:block:",
    )?;
    Ok(unsafe { f(alloc, sel, fire_date, interval, repeats as u8, block) })
}

fn test_timer_init(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let fire_date = date_now()?;
    let time_interval = 0.3;
    let fire = double(fire_date, "timeIntervalSinceReferenceDate")?;

    let timer = timer_with_fire_date(fire_date, time_interval, false, timer_block(|_| {}))?;
    let got = double(id(timer, "fireDate")?, "timeIntervalSinceReferenceDate")?;
    t.check(got == fire, || format!("fireDate {got}, not {fire}"));
    let interval = double(timer, "timeInterval")?;
    t.check(interval == 0.0, || {
        format!("Time interval should be 0 for a non repeating Timer, not {interval}")
    });
    t.check(boolean(timer, "isValid")?, || "the timer is not valid".into());

    let repeating_timer = timer_with_fire_date(fire_date, time_interval, true, timer_block(|_| {}))?;
    let got = double(id(repeating_timer, "fireDate")?, "timeIntervalSinceReferenceDate")?;
    t.check(got == fire, || format!("repeating fireDate {got}, not {fire}"));
    let interval = double(repeating_timer, "timeInterval")?;
    t.check(interval == time_interval, || {
        format!("repeating timeInterval {interval}, not {time_interval}")
    });
    // Upstream asserts `timer.isValid` a second time here, not the repeating
    // timer's.
    t.check(boolean(timer, "isValid")?, || "the timer is not valid".into());
    Ok(())
}

fn test_timer_tick_once(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let flag = Rc::new(Cell::new(false));
    let inside = Inside::default();
    let dummy_timer = scheduled_timer(0.01, false, {
        let (flag, inside) = (flag.clone(), inside.clone());
        timer_block(move |timer| {
            let original = flag.replace(true);
            inside.check(!original, || "the timer ticked more than once".into());
            inside.stopped(void(timer, "invalidate"));
        })
    })?;
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    add_timer(run_loop, dummy_timer, default_mode()?)?;
    run_until(run_loop, date_since_now(0.05)?)?;
    inside.into(t);
    t.check(flag.get(), || "the timer did not tick".into());
    Ok(())
}

fn now_1970() -> Result<f64, Stop> {
    double(date_now()?, "timeIntervalSince1970")
}

fn test_timer_repeats(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let flag = Rc::new(Cell::new(0usize));
    let interval = 0.1;
    let number_of_repeats = 3;
    let previous_interval = Rc::new(Cell::new(now_1970()?));
    let inside = Inside::default();

    let dummy_timer = scheduled_timer(interval, true, {
        let (flag, previous_interval, inside) = (flag.clone(), previous_interval.clone(), inside.clone());
        timer_block(move |timer| {
            if let Some(got) = inside.stopped(double(timer, "timeInterval")) {
                inside.check(got == interval, || format!("timeInterval {got}, not {interval}"));
            }
            let Some(current_interval) = inside.stopped(now_1970()) else {
                return;
            };
            let expected = previous_interval.get() + interval;
            inside.check((current_interval - expected).abs() <= 0.2, || {
                format!("ticked {:.3}s after the last, not {interval} +/- 0.2", current_interval - previous_interval.get())
            });
            previous_interval.set(current_interval);
            flag.set(flag.get() + 1);
            if flag.get() == number_of_repeats {
                inside.stopped(void(timer, "invalidate"));
            }
        })
    })?;
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    add_timer(run_loop, dummy_timer, default_mode()?)?;
    run_until(run_loop, date_since_now(interval * (number_of_repeats + 1) as f64)?)?;
    inside.into(t);
    t.check(flag.get() == number_of_repeats, || {
        format!("ticked {} times, not {number_of_repeats}", flag.get())
    });
    Ok(())
}

fn test_timer_invalidate(t: &mut T) -> Result<(), Stop> {
    let _pool = Pool::new();
    let flag = Rc::new(Cell::new(false));
    let inside = Inside::default();
    let dummy_timer = scheduled_timer(0.01, true, {
        let (flag, inside) = (flag.clone(), inside.clone());
        timer_block(move |timer| {
            if let Some(valid) = inside.stopped(boolean(timer, "isValid")) {
                inside.check(valid, || "isValid was false inside the block".into());
            }
            inside.check(!flag.get(), || "timer should tick only once".into());
            flag.set(true);
            inside.stopped(void(timer, "invalidate"));
            if let Some(valid) = inside.stopped(boolean(timer, "isValid")) {
                inside.check(!valid, || "isValid was true after invalidate".into());
            }
        })
    })?;
    let run_loop = id(run_loop_class()?, "currentRunLoop")?;
    add_timer(run_loop, dummy_timer, default_mode()?)?;
    run_until(run_loop, date_since_now(0.05)?)?;
    inside.into(t);
    t.check(flag.get(), || "the timer did not tick".into());
    Ok(())
}

const fn case(name: &'static str, source: &'static str, run: fn(&mut T) -> Result<(), Stop>) -> Case {
    Case {
        name,
        kind: Kind::Upstream,
        source,
        timeout_secs: 30,
        run,
    }
}

const CASES: &[Case] = &[
    case("test_constants", "TestRunLoop.swift", test_constants),
    case("test_runLoopInit", "TestRunLoop.swift", test_run_loop_init),
    case("test_runLoopRunMode", "TestRunLoop.swift", test_run_loop_run_mode),
    case("test_runLoopLimitDate", "TestRunLoop.swift", test_run_loop_limit_date),
    case("test_runLoopPoll", "TestRunLoop.swift", test_run_loop_poll),
    case("test_commonModes", "TestRunLoop.swift", test_common_modes),
    case("test_addingRemovingPorts", "TestRunLoop.swift", test_adding_removing_ports),
    case("test_mainDispatchQueueCallout", "TestRunLoop.swift", test_main_dispatch_queue_callout),
    case("test_timerInit", "TestTimer.swift", test_timer_init),
    case("test_timerTickOnce", "TestTimer.swift", test_timer_tick_once),
    case("test_timerRepeats", "TestTimer.swift", test_timer_repeats),
    case("test_timerInvalidate", "TestTimer.swift", test_timer_invalidate),
];

fn main() {
    #[cfg(not(target_os = "macos"))]
    conformance::run("runloop_conformance", "NSRunLoop/NSTimer", UPSTREAM, CASES);
}
