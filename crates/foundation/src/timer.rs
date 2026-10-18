use std::ffi::c_void;
use std::sync::Arc;

use corefoundation::runloop::{self, RunLoop};
use objc::object::Id;
use objc::sel::Sel;

use crate::define::{class_methods, methods};

/// Seconds between Apple's epoch, 2001-01-01, and the Unix one.
const UNIX_TO_REFERENCE: f64 = 978_307_200.0;

#[repr(C)]
pub struct Date {
    isa: *const c_void,
    /// Seconds since Apple's reference date.
    interval: f64,
}

#[repr(C)]
pub struct Timer {
    isa: *const c_void,
    /// Unretained, as Apple's is *not* - a scheduled timer retains its target.
    /// Retained here for the same reason: a target released while the timer is
    /// still scheduled would be messaged after it had gone.
    target: Id,
    user_info: Id,
    /// The run loop timer this one is, kept as a raw `Arc` so the object can own
    /// it across the C boundary. Made with the object and released with it.
    timer: *const c_void,
    selector: Sel,
    interval: f64,
    repeats: usize,
    passes_timer: usize,
    /// `-tolerance`, as the object last set it.
    tolerance: f64,
    /// The block a block-based timer runs, copied; null for one with a target.
    block: Id,
    /// Set by `-invalidate`, which is final. Apart from the run loop timer's own
    /// validity, which a one-shot loses before its action runs - `-isValid` is
    /// still YES inside the action, as Apple's is.
    invalidated: usize,
}

pub const DATE_INSTANCE_SIZE: usize = size_of::<Date>();
pub const TIMER_INSTANCE_SIZE: usize = size_of::<Timer>();

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
        - UNIX_TO_REFERENCE
}

/// A date object for `interval` seconds since the reference date, autoreleased.
pub fn date(interval: f64) -> Id {
    objc::arc::autorelease(make_date(interval))
}

/// A date object for `interval` seconds since the reference date, retained.
fn make_date(interval: f64) -> Id {
    let class = objc::class::lookup(c"NSDate").expect("registered by this module");
    // SAFETY: `Date` is the layout the class was registered with.
    let object = unsafe { corefoundation::base::allocate::<Date>(class) };
    // SAFETY: freshly allocated.
    unsafe { (*object).interval = interval };
    object as Id
}

/// A date object for a Unix timestamp, autoreleased.
pub fn date_since_1970(seconds: f64) -> Id {
    date(seconds - UNIX_TO_REFERENCE)
}

/// The Unix timestamp of an `NSDate`, or `None` for anything else.
///
/// Type-checked, because the caller is reading a value a guest put in a
/// dictionary: reading another class's second word as an interval is a date
/// with no relation to the one that was stored.
pub fn interval_since_1970(object: Id) -> Option<f64> {
    let class = objc::class::lookup(c"NSDate")?;
    // SAFETY: null or an object this runtime allocated.
    unsafe { corefoundation::base::is_kind_of(object as corefoundation::base::CFTypeRef, class) }
        .then(|| date_of(object) + UNIX_TO_REFERENCE)
}

fn date_of(receiver: Id) -> f64 {
    // SAFETY: a date of this module's.
    unsafe { (*(receiver as *const Date)).interval }
}

unsafe extern "C" fn date_now(_class: Id, _sel: Sel) -> Id {
    date(now())
}

unsafe extern "C" fn distant_future(_class: Id, _sel: Sel) -> Id {
    // Apple's is about ten thousand years out. The exact value is not the
    // interface; being past every deadline a program computes is.
    date(now() + 3600.0 * 24.0 * 365.0 * 10_000.0)
}

unsafe extern "C" fn distant_past(_class: Id, _sel: Sel) -> Id {
    date(now() - 3600.0 * 24.0 * 365.0 * 10_000.0)
}

unsafe extern "C" fn date_with_interval_since_now(_class: Id, _sel: Sel, seconds: f64) -> Id {
    date(now() + seconds)
}

/// `+dateWithTimeIntervalSince1970:`, which is the one a program building a
/// date out of a server timestamp uses.
unsafe extern "C" fn date_with_interval_since_1970(_class: Id, _sel: Sel, seconds: f64) -> Id {
    date_since_1970(seconds)
}

/// `+dateWithTimeIntervalSinceReferenceDate:`, the same constructor in Apple's
/// own epoch.
unsafe extern "C" fn date_with_interval_since_reference(_class: Id, _sel: Sel, seconds: f64) -> Id {
    date(seconds)
}

/// `-dateByAddingTimeInterval:`, the one arithmetic method on a date.
///
/// A new object rather than a mutation: `NSDate` is immutable, and a caller
/// that got its own receiver back with a moved interval would find every date
/// it had kept a reference to had moved with it.
unsafe extern "C" fn date_by_adding_interval(receiver: Id, _sel: Sel, seconds: f64) -> Id {
    date(date_of(receiver) + seconds)
}

/// `-compare:`, which answers `NSComparisonResult`: -1, 0 or 1, in that
/// numbering and no other. A caller sorts with it and branches on the sign.
///
/// Two dates that are equal to the microsecond are equal here, because a date
/// *is* its interval - there is nothing else to break a tie with.
unsafe extern "C" fn compare(receiver: Id, _sel: Sel, other: Id) -> isize {
    let (mine, theirs) = (date_of(receiver), date_of(other));
    match mine.partial_cmp(&theirs) {
        Some(std::cmp::Ordering::Less) => -1,
        Some(std::cmp::Ordering::Greater) => 1,
        // Equal, and also the answer for a NaN interval: `NSOrderedSame` is the
        // only one of the three that does not claim an order that is not there.
        _ => 0,
    }
}

unsafe extern "C" fn is_equal_to_date(receiver: Id, _sel: Sel, other: Id) -> u8 {
    u8::from(date_of(receiver) == date_of(other))
}

/// `-earlierDate:` and `-laterDate:`, which answer with *one of the two
/// receivers* rather than a new date - a caller compares the answer against its
/// own pointer.
unsafe extern "C" fn earlier_date(receiver: Id, _sel: Sel, other: Id) -> Id {
    match date_of(receiver) <= date_of(other) {
        true => receiver,
        false => other,
    }
}

unsafe extern "C" fn later_date(receiver: Id, _sel: Sel, other: Id) -> Id {
    match date_of(receiver) >= date_of(other) {
        true => receiver,
        false => other,
    }
}

unsafe extern "C" fn time_interval_since_reference(receiver: Id, _sel: Sel) -> f64 {
    date_of(receiver)
}

unsafe extern "C" fn time_interval_since_now(receiver: Id, _sel: Sel) -> f64 {
    date_of(receiver) - now()
}

unsafe extern "C" fn time_interval_since_date(receiver: Id, _sel: Sel, other: Id) -> f64 {
    date_of(receiver) - date_of(other)
}

unsafe extern "C" fn time_interval_since_1970(receiver: Id, _sel: Sel) -> f64 {
    date_of(receiver) + UNIX_TO_REFERENCE
}

fn timer_of<'a>(receiver: Id) -> &'a mut Timer {
    // SAFETY: a timer of this module's.
    unsafe { &mut *(receiver as *mut Timer) }
}

/// The run loop timer behind an `NSTimer`, as a reference of the caller's.
///
/// Every timer has one from the moment it is made, scheduled or not: Apple's
/// `NSTimer` *is* a `CFRunLoopTimer`, which is why `-fireDate` of a timer not yet
/// on any loop is already its creation time plus its interval.
fn cf_timer(object: Id) -> Arc<runloop::Timer> {
    let raw = timer_of(object).timer as *const runloop::Timer;
    // SAFETY: an `Arc` the object owns from `make` until `-dealloc`; this takes
    // a count of its own.
    unsafe {
        Arc::increment_strong_count(raw);
        Arc::from_raw(raw)
    }
}

/// One mode of one run loop a timer has been added to.
struct Schedule {
    object: usize,
    run_loop: Arc<RunLoop>,
    mode: String,
}

/// Where every scheduled timer is, so `-invalidate` can take it off them all.
///
/// Each entry holds a reference to its object, as each mode of a CF run loop
/// holds one to its timers: a program is entitled to schedule a timer and drop
/// its own reference, which is why `-invalidate` is the documented way to stop
/// one.
static SCHEDULED: std::sync::Mutex<Vec<Schedule>> = std::sync::Mutex::new(Vec::new());

fn scheduled() -> std::sync::MutexGuard<'static, Vec<Schedule>> {
    SCHEDULED.lock().unwrap_or_else(|e| e.into_inner())
}

/// `CFRunLoopAddTimer`: put the timer in `mode` of `run_loop`.
///
/// An invalidated timer is not added, and a timer is in one run loop at a time:
/// CF refuses to add one that is already in another loop rather than moving it,
/// and so does this.
fn schedule(object: Id, run_loop: &Arc<RunLoop>, mode: &str) {
    if timer_of(object).invalidated != 0 {
        return;
    }
    {
        let mut table = scheduled();
        let mut mine = table.iter().filter(|s| s.object == object as usize);
        if mine.clone().any(|s| !Arc::ptr_eq(&s.run_loop, run_loop))
            || mine.any(|s| s.mode == mode)
        {
            return;
        }
        objc::arc::retain(object);
        table.push(Schedule {
            object: object as usize,
            run_loop: Arc::clone(run_loop),
            mode: mode.to_string(),
        });
    }
    // Outside the table's lock: adding wakes the loop, and a loop woken on
    // another thread may fire a timer whose action schedules another.
    run_loop.add_timer(&cf_timer(object), mode);
}

/// One turn of a timer: send the selector to the target.
unsafe extern "C" fn fire(_timer: *const c_void, info: *mut c_void) {
    let object = info as Id;
    let (target, selector, repeats, user_info, passes_timer, block) = {
        let timer = timer_of(object);
        (
            timer.target,
            timer.selector,
            timer.repeats,
            timer.user_info,
            timer.passes_timer,
            timer.block,
        )
    };
    if timer_of(object).invalidated != 0 {
        return;
    }
    if !block.is_null() {
        objc::arc::retain(object);
        // SAFETY: a timer's block is `void (^)(NSTimer *)`, copied by `fill`;
        // held across the call as the object is.
        unsafe { crate::block::call_with(block, object) };
        if repeats == 0 {
            // SAFETY: `-invalidate` is `void (id, SEL)`.
            unsafe { invalidate(object, objc::sel::get("invalidate")) };
        }
        objc::arc::release(object);
        return;
    }
    if target.is_null() || selector.is_null() {
        return;
    }
    // SAFETY: a live object this runtime allocated.
    let method = unsafe { objc::object::class_of(target) }.and_then(|c| c.method(selector));
    let Some(method) = method else {
        // A target that does not answer is the program's error, and Apple
        // raises. Named rather than silent: a timer that fires into nothing is
        // a frame loop that does not run, which is what this whole module
        // exists to stop happening quietly.
        objc::fail!(
            "-[NSTimer fire]: the target does not respond to the selector it was scheduled with"
        );
    };
    // Held across the call, as the run loop holds a timer across its callout:
    // the action is entitled to invalidate the timer, and invalidating releases
    // the target and the user info - which may have been the last references.
    objc::arc::retain(object);
    objc::arc::retain(target);
    objc::arc::retain(user_info);
    // SAFETY: a timer action takes the timer, while delayed performing takes
    // the object supplied by its caller. Both are `void (id, SEL, id)`.
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, Id) = std::mem::transmute(method.implementation());
        f(
            target,
            selector,
            if passes_timer != 0 { object } else { user_info },
        );
    }
    if repeats == 0 {
        // "If the timer is non-repeating, it is automatically invalidated after
        // firing" - after, so that the action still sees a valid timer.
        // SAFETY: `-invalidate` is `void (id, SEL)`.
        unsafe { invalidate(object, objc::sel::get("invalidate")) };
    }
    objc::arc::release(user_info);
    objc::arc::release(target);
    objc::arc::release(object);
}

/// The monotonic instant the absolute date `date` falls on, past or future.
fn instant_of(date: f64) -> std::time::Instant {
    let (instant, ahead) = (std::time::Instant::now(), date - now());
    let span = std::time::Duration::from_secs_f64(ahead.abs().min(1e9));
    match ahead >= 0.0 {
        true => instant.checked_add(span),
        false => instant.checked_sub(span),
    }
    .unwrap_or(instant)
}

/// What a timer is made of. The target, selector and user info are a
/// selector timer's; the block a block timer's.
struct Parts {
    fire_at: f64,
    interval: f64,
    repeats: bool,
    target: Id,
    selector: Sel,
    user_info: Id,
    block: Id,
    passes_timer: bool,
}

/// Fill a timer object: `CFRunLoopTimerCreate` with `fire_at` as its first
/// fire date, and the parts the object keeps.
fn fill(object: *mut Timer, parts: Parts) {
    // "If seconds is less than or equal to 0.0, this method chooses the
    // nonnegative value of 0.1 milliseconds instead."
    let interval = match parts.interval > 0.0 {
        true => parts.interval,
        false => 0.0001,
    };
    let when = instant_of(parts.fire_at);
    let repeat = parts
        .repeats
        .then(|| std::time::Duration::from_secs_f64(interval.min(1e9)));
    let run_loop_timer = runloop::new_timer(
        when.saturating_duration_since(std::time::Instant::now()),
        repeat,
        Some(fire),
        object as usize,
    );
    run_loop_timer.set_next_date(when, parts.fire_at);
    // SAFETY: an allocated timer object; every field is written before it is
    // read.
    unsafe {
        (*object).target = objc::arc::retain(parts.target);
        (*object).user_info = objc::arc::retain(parts.user_info);
        (*object).block = match parts.block.is_null() {
            true => std::ptr::null_mut(),
            false => objc::block::copy(parts.block),
        };
        (*object).selector = parts.selector;
        (*object).interval = interval;
        (*object).repeats = parts.repeats as usize;
        (*object).passes_timer = parts.passes_timer as usize;
        (*object).tolerance = 0.0;
        (*object).invalidated = 0;
        (*object).timer = Arc::into_raw(run_loop_timer) as *const c_void;
    }
}

/// A new timer object, autoreleased, scheduled in the current thread's run
/// loop's default mode if asked - which is where `+scheduledTimer...` and
/// `-performSelector:withObject:afterDelay:` put theirs.
fn make(parts: Parts, schedule_now: bool) -> Id {
    let class = objc::class::lookup(c"NSTimer").expect("registered by this module");
    // SAFETY: `Timer` is the layout the class was registered with.
    let object = unsafe { corefoundation::base::allocate::<Timer>(class) };
    fill(object, parts);
    let object = object as Id;
    if schedule_now {
        schedule(object, &runloop::current(), runloop::DEFAULT_MODE);
    }
    objc::arc::autorelease(object)
}

/// A selector timer first due `interval` from now.
fn selector_parts(interval: f64, target: Id, selector: Sel, user_info: Id, repeats: u8) -> Parts {
    Parts {
        fire_at: now() + interval.max(0.0),
        interval,
        repeats: repeats != 0,
        target,
        selector,
        user_info,
        block: std::ptr::null_mut(),
        passes_timer: true,
    }
}

/// A block timer first due at `fire_at`.
fn block_parts(fire_at: f64, interval: f64, repeats: u8, block: Id) -> Parts {
    Parts {
        fire_at,
        interval,
        repeats: repeats != 0,
        target: std::ptr::null_mut(),
        selector: std::ptr::null(),
        user_info: std::ptr::null_mut(),
        block,
        passes_timer: true,
    }
}

unsafe extern "C" fn scheduled_timer(
    _class: Id,
    _sel: Sel,
    interval: f64,
    target: Id,
    selector: Sel,
    user_info: Id,
    repeats: u8,
) -> Id {
    make(selector_parts(interval, target, selector, user_info, repeats), true)
}

unsafe extern "C" fn unscheduled_timer(
    _class: Id,
    _sel: Sel,
    interval: f64,
    target: Id,
    selector: Sel,
    user_info: Id,
    repeats: u8,
) -> Id {
    make(selector_parts(interval, target, selector, user_info, repeats), false)
}

/// `+scheduledTimerWithTimeInterval:repeats:block:`.
unsafe extern "C" fn scheduled_block_timer(
    _class: Id,
    _sel: Sel,
    interval: f64,
    repeats: u8,
    block: Id,
) -> Id {
    make(block_parts(now() + interval.max(0.0), interval, repeats, block), true)
}

/// `+timerWithTimeInterval:repeats:block:`, first due `interval` from now.
unsafe extern "C" fn block_timer(
    _class: Id,
    _sel: Sel,
    interval: f64,
    repeats: u8,
    block: Id,
) -> Id {
    make(block_parts(now() + interval.max(0.0), interval, repeats, block), false)
}

/// The fire date a nil date argument stands for: now.
fn fire_at(date: Id) -> f64 {
    match date.is_null() {
        true => now(),
        false => date_of(date),
    }
}

/// `-initWithFireDate:interval:target:selector:userInfo:repeats:`.
unsafe extern "C" fn init_with_fire_date(
    receiver: Id,
    _sel: Sel,
    date: Id,
    interval: f64,
    target: Id,
    selector: Sel,
    user_info: Id,
    repeats: u8,
) -> Id {
    let mut parts = selector_parts(interval, target, selector, user_info, repeats);
    parts.fire_at = fire_at(date);
    fill(receiver as *mut Timer, parts);
    receiver
}

/// `-initWithFireDate:interval:repeats:block:`.
unsafe extern "C" fn init_with_fire_date_block(
    receiver: Id,
    _sel: Sel,
    date: Id,
    interval: f64,
    repeats: u8,
    block: Id,
) -> Id {
    fill(
        receiver as *mut Timer,
        block_parts(fire_at(date), interval, repeats, block),
    );
    receiver
}

/// `-performSelector:withObject:afterDelay:`: "sets up a timer to perform the
/// aSelector message on the current thread's run loop", in the default mode.
unsafe extern "C" fn perform_after_delay(
    receiver: Id,
    _sel: Sel,
    selector: Sel,
    object: Id,
    delay: f64,
) {
    let mut parts = selector_parts(delay, receiver, selector, object, 0);
    parts.passes_timer = false;
    let _ = make(parts, true);
}

/// The state owned by a `-performSelectorOnMainThread:...` queue entry.
///
/// Both objects are retained before the entry is submitted. This is necessary
/// even for the synchronous case: another thread can release either object
/// while the caller is waiting for the main thread to run it.
struct MainThreadPerform {
    receiver: Id,
    selector: Sel,
    object: Id,
}

/// Invoke one main-thread selector and release the queue entry's ownership.
///
/// # Safety
///
/// `context` must be a `Box<MainThreadPerform>` made by
/// [`perform_on_main_thread`] and consumed exactly once.
unsafe extern "C" fn run_main_thread_perform(context: *mut c_void) {
    let perform = unsafe { Box::from_raw(context.cast::<MainThreadPerform>()) };
    // Resolve here, on the main thread. Besides matching normal message
    // delivery, this lets a method installed after submission be the one run.
    let Some(method) = (unsafe { objc::object::class_of(perform.receiver) })
        .and_then(|class| class.method(perform.selector))
    else {
        objc::fail!(
            "-performSelectorOnMainThread:withObject:waitUntilDone: target does not respond to selector"
        );
    };
    // SAFETY: this API requires a selector whose method takes one object.
    let function: unsafe extern "C" fn(Id, Sel, Id) =
        unsafe { std::mem::transmute(method.implementation()) };
    // SAFETY: the retained receiver and argument are live for this call.
    unsafe { function(perform.receiver, perform.selector, perform.object) };
    objc::arc::release(perform.object);
    objc::arc::release(perform.receiver);
}

unsafe extern "C" fn perform_on_main_thread(
    receiver: Id,
    _sel: Sel,
    selector: Sel,
    object: Id,
    wait: i8,
) {
    let perform = Box::new(MainThreadPerform {
        receiver: objc::arc::retain(receiver),
        selector,
        object: objc::arc::retain(object),
    });
    let context = Box::into_raw(perform) as u64;
    let function = run_main_thread_perform as *const () as u64;
    let main = darwin::dispatch::queue::main_queue();
    // SAFETY: the boxed context is consumed exactly once by the function. A
    // synchronous submission returns only after that has happened; an
    // asynchronous one transfers ownership to the queue.
    unsafe {
        if wait != 0 {
            darwin::dispatch::queue::sync_f(main, context, function);
        } else {
            darwin::dispatch::queue::async_f(main, context, function);
        }
    }
}

/// `-invalidate`: off every mode of the loop it is in, never to fire again, and
/// the target and user info released.
unsafe extern "C" fn invalidate(receiver: Id, _sel: Sel) {
    let timer = timer_of(receiver);
    if timer.invalidated != 0 {
        return;
    }
    timer.invalidated = 1;
    let run_loop_timer = cf_timer(receiver);
    run_loop_timer.invalidate();
    let removed: Vec<Schedule> = {
        let mut table = scheduled();
        let (mine, rest) = std::mem::take(&mut *table)
            .into_iter()
            .partition(|s| s.object == receiver as usize);
        *table = rest;
        mine
    };
    for schedule in &removed {
        schedule.run_loop.remove_timer(&run_loop_timer, &schedule.mode);
    }
    let (target, user_info, block) = (timer.target, timer.user_info, timer.block);
    timer.target = std::ptr::null_mut();
    timer.user_info = std::ptr::null_mut();
    timer.block = std::ptr::null_mut();
    objc::arc::release(target);
    objc::arc::release(user_info);
    if !block.is_null() {
        objc::block::release(block);
    }
    // Last: the loops' references may be the only ones left.
    for _ in &removed {
        objc::arc::release(receiver);
    }
}

unsafe extern "C" fn timer_dealloc(receiver: Id, _sel: Sel) {
    let timer = timer_of(receiver);
    objc::arc::release(timer.target);
    objc::arc::release(timer.user_info);
    if !timer.block.is_null() {
        objc::block::release(timer.block);
    }
    if !timer.timer.is_null() {
        // SAFETY: the `Arc` `make` leaked into the object, taken back once.
        drop(unsafe { Arc::from_raw(timer.timer as *const runloop::Timer) });
        timer.timer = std::ptr::null();
    }
    objc::arc::finalize(receiver);
}

unsafe extern "C" fn is_valid(receiver: Id, _sel: Sel) -> u8 {
    (timer_of(receiver).invalidated == 0) as u8
}

unsafe extern "C" fn timer_fire(receiver: Id, _sel: Sel) {
    // SAFETY: the run loop's own callback, with this object as its `info`.
    unsafe { fire(std::ptr::null(), receiver as *mut c_void) };
}

unsafe extern "C" fn user_info(receiver: Id, _sel: Sel) -> Id {
    timer_of(receiver).user_info
}

unsafe extern "C" fn time_interval(receiver: Id, _sel: Sel) -> f64 {
    // "If the receiver is a non-repeating timer, returns 0."
    let timer = timer_of(receiver);
    match timer.repeats != 0 {
        true => timer.interval,
        false => 0.0,
    }
}

unsafe extern "C" fn tolerance(receiver: Id, _sel: Sel) -> f64 {
    timer_of(receiver).tolerance
}

/// `-setTolerance:`, by `CFRunLoopTimerSetTolerance`'s rule over the interval
/// `CFRunLoopTimerGetInterval` reports - none, for a one-shot.
unsafe extern "C" fn set_tolerance(receiver: Id, _sel: Sel, tolerance: f64) {
    let timer = timer_of(receiver);
    let interval = if timer.repeats != 0 {
        timer.interval
    } else {
        0.0
    };
    timer.tolerance = runloop::clamped_tolerance(tolerance, interval);
    cf_timer(receiver).set_tolerance(timer.tolerance);
}

/// `-fireDate`: `CFRunLoopTimerGetNextFireDate` - the date as it was given,
/// while the timer is still due then.
unsafe extern "C" fn fire_date(receiver: Id, _sel: Sel) -> Id {
    let timer = cf_timer(receiver);
    let date_value = timer.next_date().unwrap_or_else(|| {
        let (next, instant) = (timer.next_fire(), std::time::Instant::now());
        match next >= instant {
            true => now() + (next - instant).as_secs_f64(),
            false => now() - (instant - next).as_secs_f64(),
        }
    });
    date(date_value)
}

/// `-setFireDate:`, which is `CFRunLoopTimerSetNextFireDate`: a date in the past
/// fires on the loop's next turn.
unsafe extern "C" fn set_fire_date(receiver: Id, _sel: Sel, fire: Id) {
    if fire.is_null() {
        return;
    }
    let date_value = date_of(fire);
    cf_timer(receiver).set_next_date(instant_of(date_value), date_value);
    // A loop asleep until the old date has to look again.
    for schedule in scheduled().iter().filter(|s| s.object == receiver as usize) {
        schedule.run_loop.wake();
    }
}

/// An `NSRunLoop`: the Foundation face of one CF run loop.
///
/// One per CF loop, made the first time it is asked for and kept: Apple's is
/// per thread too, and `+currentRunLoop` answering the same object every time
/// on a thread is what lets a program compare it against `+mainRunLoop`.
#[repr(C)]
struct RunLoopObject {
    isa: *const c_void,
    /// The loop, as an `Arc::into_raw` reference the object owns.
    run_loop: *const RunLoop,
}

/// Every `NSRunLoop` made, by the address of its CF loop.
///
/// Each object holds its loop, so an address here never comes to name another
/// loop.
static RUN_LOOPS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

/// The `NSRunLoop` for `run_loop`.
fn run_loop_object(run_loop: Arc<RunLoop>) -> Id {
    let address = Arc::as_ptr(&run_loop) as usize;
    let mut table = RUN_LOOPS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&(_, object)) = table.iter().find(|(a, _)| *a == address) {
        return object as Id;
    }
    let class = objc::class::lookup(c"NSRunLoop").expect("registered by this module");
    // SAFETY: `RunLoopObject` is the layout the class was registered with.
    let object = unsafe { corefoundation::base::allocate::<RunLoopObject>(class) };
    // SAFETY: freshly allocated.
    unsafe { (*object).run_loop = Arc::into_raw(run_loop) };
    table.push((address, object as usize));
    object as Id
}

/// The CF loop an `NSRunLoop` stands for.
fn loop_of(receiver: Id) -> Arc<RunLoop> {
    // SAFETY: an `NSRunLoop` of this module's, whose loop it owns for good.
    unsafe {
        let raw = (*(receiver as *const RunLoopObject)).run_loop;
        Arc::increment_strong_count(raw);
        Arc::from_raw(raw)
    }
}

/// The CF loop of an `NSRunLoop` a program passed, or `None` for anything
/// else - nil included.
pub fn cf_run_loop(object: Id) -> Option<Arc<RunLoop>> {
    let class = objc::class::lookup(c"NSRunLoop")?;
    // SAFETY: null or an object this runtime allocated.
    unsafe { corefoundation::base::is_kind_of(object as corefoundation::base::CFTypeRef, class) }
        .then(|| loop_of(object))
}

/// Whether `receiver` is the calling thread's own loop.
///
/// Every running method asks first, as swift-corelibs-foundation's `RunLoop`
/// does: a run loop is only ever run by its thread. Running another thread's -
/// the main thread's, from a worker - would service that thread's sources on
/// the wrong thread, which is a crash in any program whose sources are not
/// thread-safe, and that is most of them.
fn is_current(receiver: Id) -> bool {
    Arc::ptr_eq(&loop_of(receiver), &runloop::current())
}

/// A mode a program passed, as the name the CF loop files it under. Nil is the
/// default mode, as it is in every CF call that takes one.
pub fn mode_name(mode: Id) -> String {
    // SAFETY: null or an object this runtime allocated.
    match unsafe { corefoundation::string::as_string(mode as corefoundation::base::CFTypeRef) } {
        Some(name) => String::from_utf8_lossy(&name.utf8()).into_owned(),
        None => runloop::DEFAULT_MODE.to_string(),
    }
}

/// Seconds from now until `limit`, which a nil date makes zero.
fn seconds_until(limit: Id) -> f64 {
    match limit.is_null() {
        true => 0.0,
        false => date_of(limit) - now(),
    }
}

unsafe extern "C" fn current_run_loop(_class: Id, _sel: Sel) -> Id {
    run_loop_object(runloop::current())
}

unsafe extern "C" fn main_run_loop(_class: Id, _sel: Sel) -> Id {
    run_loop_object(runloop::main())
}

/// `-getCFRunLoop`: the `CFRunLoopRef`, the one `CFRunLoopGetCurrent` answers on
/// the loop's thread.
unsafe extern "C" fn get_cf_run_loop(receiver: Id, _sel: Sel) -> *const c_void {
    // SAFETY: an `NSRunLoop` of this module's.
    unsafe { (*(receiver as *const RunLoopObject)).run_loop as *const c_void }
}

unsafe extern "C" fn add_timer_for_mode(receiver: Id, _sel: Sel, timer: Id, mode: Id) {
    if !timer.is_null() {
        schedule(timer, &loop_of(receiver), &mode_name(mode));
    }
}

/// `-runMode:beforeDate:`: one pass of the loop in `mode`, returning after the
/// first source is handled or at `limit`.
///
/// NO - without running - for another thread's loop or a mode with nothing in
/// it, which is what ends a `while ([loop runMode:... beforeDate:...])`.
unsafe extern "C" fn run_mode_before_date(receiver: Id, _sel: Sel, mode: Id, limit: Id) -> u8 {
    if !is_current(receiver) {
        return 0;
    }
    let mode = mode_name(mode);
    let run_loop = loop_of(receiver);
    if run_loop.is_empty(&mode) {
        return 0;
    }
    run_loop.run_in_mode(&mode, seconds_until(limit), true);
    1
}

/// `-runUntilDate:`: the default mode, a pass at a time, until `limit` or until
/// there is nothing left to run.
unsafe extern "C" fn run_until_date(receiver: Id, _sel: Sel, limit: Id) {
    let sel = objc::sel::get("runMode:beforeDate:");
    let default = std::ptr::null_mut();
    // SAFETY: `-runMode:beforeDate:` is `BOOL (id, SEL, id, id)`.
    while unsafe { run_mode_before_date(receiver, sel, default, limit) } != 0
        && seconds_until(limit) > 0.0
    {}
}

/// `-run`: `-runUntilDate:` the distant future.
unsafe extern "C" fn run_forever(receiver: Id, _sel: Sel) {
    let sel = objc::sel::get("runMode:beforeDate:");
    // SAFETY: `+distantFuture` is `id (Class, SEL)`.
    let limit = unsafe { distant_future(std::ptr::null_mut(), sel) };
    // SAFETY: as above.
    while unsafe { run_mode_before_date(receiver, sel, std::ptr::null_mut(), limit) } != 0 {}
}

/// `-acceptInputForMode:beforeDate:`: one pass, with no answer.
unsafe extern "C" fn accept_input(receiver: Id, _sel: Sel, mode: Id, limit: Id) {
    if is_current(receiver) {
        loop_of(receiver).run_in_mode(&mode_name(mode), seconds_until(limit), true);
    }
}

/// `-limitDateForMode:`: poll the mode once, then the date its next timer is
/// due - the distant future when it has none, and nil when there is nothing in
/// the mode or the loop is another thread's.
unsafe extern "C" fn limit_date_for_mode(receiver: Id, sel: Sel, mode: Id) -> Id {
    if !is_current(receiver) {
        return std::ptr::null_mut();
    }
    let (run_loop, mode) = (loop_of(receiver), mode_name(mode));
    run_loop.run_in_mode(&mode, 0.0, true);
    if run_loop.is_empty(&mode) {
        return std::ptr::null_mut();
    }
    match run_loop.next_timer(&mode) {
        Some(next) => {
            let instant = std::time::Instant::now();
            date(now() + next.saturating_duration_since(instant).as_secs_f64())
        }
        // SAFETY: `+distantFuture` is `id (Class, SEL)`.
        None => unsafe { distant_future(std::ptr::null_mut(), sel) },
    }
}

/// A message `-performSelector:target:argument:order:modes:` scheduled.
struct Perform {
    /// The `NSRunLoop` it was scheduled on.
    run_loop: usize,
    target: usize,
    selector: usize,
    argument: usize,
    order: usize,
    /// Scheduling order, which breaks a tie in `order`.
    sequence: u64,
    modes: Vec<String>,
    /// The zero-delay timer that has the loop come back for it, one per mode.
    timer: Arc<runloop::Timer>,
}

// SAFETY: the words are objects and a selector this runtime made, retained by
// the entry; they are only messaged on the loop's thread.
unsafe impl Send for Perform {}

static PERFORMS: std::sync::Mutex<Vec<Perform>> = std::sync::Mutex::new(Vec::new());
static PERFORM_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn performs() -> std::sync::MutexGuard<'static, Vec<Perform>> {
    PERFORMS.lock().unwrap_or_else(|e| e.into_inner())
}

/// `[array count]` and `-objectAtIndex:`, for any array a program passed.
fn objects_of(array: Id) -> Vec<Id> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: `objc_msgSend` as `NSUInteger (id, SEL)` and `id (id, SEL, NSUInteger)`.
    unsafe {
        let count: unsafe extern "C" fn(Id, Sel) -> usize = std::mem::transmute(objc::msg::entry());
        let at: unsafe extern "C" fn(Id, Sel, usize) -> Id = std::mem::transmute(objc::msg::entry());
        let n = count(array, objc::sel::get("count"));
        (0..n)
            .map(|i| at(array, objc::sel::get("objectAtIndex:"), i))
            .collect()
    }
}

/// Take a scheduled message off its loop, handing back what it held.
fn unschedule_perform(perform: &Perform) {
    let run_loop = loop_of(perform.run_loop as Id);
    for mode in &perform.modes {
        run_loop.remove_timer(&perform.timer, mode);
    }
    perform.timer.invalidate();
}

fn release_perform(perform: Perform) {
    objc::arc::release(perform.target as Id);
    objc::arc::release(perform.argument as Id);
}

/// The loop has come round for a scheduled message: send every one due on
/// this loop in the mode it is running, lowest `order` first.
unsafe extern "C" fn fire_performs(_timer: *const c_void, info: *mut c_void) {
    let receiver = info as Id;
    let Some(mode) = loop_of(receiver).current_mode() else {
        return;
    };
    let mut due: Vec<Perform> = {
        let mut table = performs();
        let (mine, rest) = std::mem::take(&mut *table)
            .into_iter()
            .partition(|p| p.run_loop == receiver as usize && p.modes.contains(&mode));
        *table = rest;
        mine
    };
    due.sort_by_key(|p| (p.order, p.sequence));
    for perform in due {
        unschedule_perform(&perform);
        let (target, selector, argument) =
            (perform.target as Id, perform.selector as Sel, perform.argument as Id);
        // SAFETY: a live target; the method takes one object, by the API's
        // contract.
        let method = unsafe { objc::object::class_of(target) }.and_then(|c| c.method(selector));
        match method {
            Some(method) => unsafe {
                let f: unsafe extern "C" fn(Id, Sel, Id) = std::mem::transmute(method.implementation());
                f(target, selector, argument);
            },
            None => objc::fail!(
                "-[NSRunLoop performSelector:target:argument:order:modes:]: the target does not \
                 respond to the selector"
            ),
        }
        release_perform(perform);
    }
}

/// `-performSelector:target:argument:order:modes:`: send `selector` to
/// `target` with `argument` "at the start of the next run loop iteration" in
/// one of `modes` - lower `order` first - retaining both until then.
unsafe extern "C" fn perform_selector(
    receiver: Id,
    _sel: Sel,
    selector: Sel,
    target: Id,
    argument: Id,
    order: usize,
    modes: Id,
) {
    let modes: Vec<String> = objects_of(modes).into_iter().map(mode_name).collect();
    if target.is_null() || selector.is_null() || modes.is_empty() {
        return;
    }
    let timer = runloop::new_timer(
        std::time::Duration::ZERO,
        None,
        Some(fire_performs),
        receiver as usize,
    );
    let run_loop = loop_of(receiver);
    performs().push(Perform {
        run_loop: receiver as usize,
        target: objc::arc::retain(target) as usize,
        selector: selector as usize,
        argument: objc::arc::retain(argument) as usize,
        order,
        sequence: PERFORM_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        modes: modes.clone(),
        timer: Arc::clone(&timer),
    });
    for mode in &modes {
        run_loop.add_timer(&timer, mode);
    }
}

/// Whether two arguments are the same one: identical, or `-isEqual:`.
fn same_argument(a: Id, b: Id) -> bool {
    if a == b {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: `-isEqual:` is `BOOL (id, SEL, id)`.
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, Id) -> u8 = std::mem::transmute(objc::msg::entry());
        f(a, objc::sel::get("isEqual:"), b) != 0
    }
}

/// Cancel the scheduled messages on `receiver` that `cancel` picks.
fn cancel_performs(receiver: Id, cancel: impl Fn(&Perform) -> bool) {
    let cancelled: Vec<Perform> = {
        let mut table = performs();
        let (gone, rest) = std::mem::take(&mut *table)
            .into_iter()
            .partition(|p| p.run_loop == receiver as usize && cancel(p));
        *table = rest;
        gone
    };
    for perform in cancelled {
        unschedule_perform(&perform);
        release_perform(perform);
    }
}

/// `-cancelPerformSelector:target:argument:`: every message this loop has
/// scheduled with that selector and target, and an argument equal to it.
unsafe extern "C" fn cancel_perform_selector(
    receiver: Id,
    _sel: Sel,
    selector: Sel,
    target: Id,
    argument: Id,
) {
    cancel_performs(receiver, |p| {
        p.target == target as usize
            && objc::sel::is_equal(p.selector as Sel, selector)
            && same_argument(p.argument as Id, argument)
    });
}

/// `-cancelPerformSelectorsWithTarget:`: every message this loop has
/// scheduled for `target`.
unsafe extern "C" fn cancel_perform_selectors_with_target(receiver: Id, _sel: Sel, target: Id) {
    cancel_performs(receiver, |p| p.target == target as usize);
}

/// `-currentMode`: the mode the loop is running, or nil when it is not.
unsafe extern "C" fn current_mode(receiver: Id, _sel: Sel) -> Id {
    match loop_of(receiver).current_mode() {
        Some(mode) => corefoundation::base::interned_name(&mode) as Id,
        None => std::ptr::null_mut(),
    }
}

/// A port a run loop has scheduled, and the modes it is in.
///
/// `RunLoop.swift`'s `monitoredPortsWithModes`: the entry holds the port, as
/// the dictionary's key does, until it is removed from its last mode or
/// announces that it has become invalid.
struct Monitored {
    run_loop: usize,
    port: usize,
    modes: Vec<String>,
}

static PORTS: std::sync::Mutex<Vec<Monitored>> = std::sync::Mutex::new(Vec::new());

fn ports() -> std::sync::MutexGuard<'static, Vec<Monitored>> {
    PORTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The selector a run loop is told a port it monitors became invalid with.
const PORT_INVALIDATED: &str = "_rosemaryPortDidBecomeInvalid:";

/// `[port scheduleInRunLoop:loop forMode:mode]` or `removeFromRunLoop:`, sent
/// so a subclass's override is the one that runs.
fn tell_port(port: Id, selector: &str, run_loop: Id, mode: Id) {
    // SAFETY: `objc_msgSend`, as `void (id, SEL, id, id)`.
    unsafe {
        let send: unsafe extern "C" fn(Id, Sel, Id, Id) = std::mem::transmute(objc::msg::entry());
        send(port, objc::sel::get(selector), run_loop, mode);
    }
}

/// `-addPort:forMode:`: schedule the port once per mode, and watch it for
/// invalidation from the first.
unsafe extern "C" fn add_port(receiver: Id, _sel: Sel, port: Id, mode: Id) {
    if port.is_null() {
        return;
    }
    let name = mode_name(mode);
    let schedule = {
        let mut table = ports();
        let entry = table
            .iter_mut()
            .find(|m| m.run_loop == receiver as usize && m.port == port as usize);
        match entry {
            Some(entry) if entry.modes.contains(&name) => false,
            Some(entry) => {
                entry.modes.push(name);
                true
            }
            None => {
                objc::arc::retain(port);
                crate::notification::observe(
                    receiver,
                    objc::sel::get(PORT_INVALIDATED),
                    crate::port::DID_BECOME_INVALID,
                    port,
                );
                table.push(Monitored {
                    run_loop: receiver as usize,
                    port: port as usize,
                    modes: vec![name],
                });
                true
            }
        }
    };
    if schedule {
        tell_port(port, "scheduleInRunLoop:forMode:", receiver, mode);
    }
}

/// Stop watching `port` and let it go: the last mode it was in is gone, or it
/// is invalid.
fn forget_port(receiver: Id, port: Id) {
    crate::notification::unobserve(receiver, crate::port::DID_BECOME_INVALID, port);
    objc::arc::release(port);
}

/// `-removePort:forMode:`.
unsafe extern "C" fn remove_port(receiver: Id, _sel: Sel, port: Id, mode: Id) {
    if port.is_null() {
        return;
    }
    let name = mode_name(mode);
    let (remove, last) = {
        let mut table = ports();
        let at = table.iter().position(|m| {
            m.run_loop == receiver as usize && m.port == port as usize && m.modes.contains(&name)
        });
        match at {
            None => (false, false),
            Some(at) if table[at].modes.len() == 1 => {
                table.remove(at);
                (true, true)
            }
            Some(at) => {
                table[at].modes.retain(|m| *m != name);
                (true, false)
            }
        }
    };
    if remove {
        // Told before it is let go: the run loop's may be the last reference.
        tell_port(port, "removeFromRunLoop:forMode:", receiver, mode);
        if last {
            forget_port(receiver, port);
        }
    }
}

/// `NSPortDidBecomeInvalidNotification` for a port this loop watches:
/// `portDidInvalidate`, which drops it from every mode without telling it.
unsafe extern "C" fn port_invalidated(receiver: Id, _sel: Sel, notification: Id) {
    // SAFETY: `-object` is `id (id, SEL)`.
    let port = unsafe {
        let send: unsafe extern "C" fn(Id, Sel) -> Id = std::mem::transmute(objc::msg::entry());
        send(notification, objc::sel::get("object"))
    };
    let found = {
        let mut table = ports();
        let before = table.len();
        table.retain(|m| m.run_loop != receiver as usize || m.port != port as usize);
        table.len() != before
    };
    if found {
        forget_port(receiver, port);
    }
}

pub(crate) fn install() {
    let nsobject = objc::class::lookup(c"NSObject").expect("the runtime's own NSObject");
    methods!(nsobject, {
        "performSelector:withObject:afterDelay:" => perform_after_delay,
            c"v40@0:8:16@24d32";
        "performSelectorOnMainThread:withObject:waitUntilDone:" => perform_on_main_thread,
            c"v40@0:8:16@24c32";
    });

    let date_class = corefoundation::base::register(c"NSDate", None, DATE_INSTANCE_SIZE, false);
    corefoundation::base::note_type_class(date_class);
    class_methods!(date_class, {
        "date" => date_now, c"@16@0:8";
        "distantFuture" => distant_future, c"@16@0:8";
        "distantPast" => distant_past, c"@16@0:8";
        "dateWithTimeIntervalSinceNow:" => date_with_interval_since_now, c"@24@0:8d16";
        "dateWithTimeIntervalSince1970:" => date_with_interval_since_1970, c"@24@0:8d16";
        "dateWithTimeIntervalSinceReferenceDate:" => date_with_interval_since_reference,
            c"@24@0:8d16";
    });
    methods!(date_class, {
        "timeIntervalSinceReferenceDate" => time_interval_since_reference, c"d16@0:8";
        "timeIntervalSinceNow" => time_interval_since_now, c"d16@0:8";
        "timeIntervalSince1970" => time_interval_since_1970, c"d16@0:8";
        "timeIntervalSinceDate:" => time_interval_since_date, c"d24@0:8@16";
        "dateByAddingTimeInterval:" => date_by_adding_interval, c"@24@0:8d16";
        "compare:" => compare, c"q24@0:8@16";
        "isEqualToDate:" => is_equal_to_date, c"c24@0:8@16";
        "earlierDate:" => earlier_date, c"@24@0:8@16";
        "laterDate:" => later_date, c"@24@0:8@16";
    });

    let timer_class = corefoundation::base::register(c"NSTimer", None, TIMER_INSTANCE_SIZE, false);
    class_methods!(timer_class, {
        "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:"
            => scheduled_timer, c"@48@0:8d16@24:32@40c48";
        "timerWithTimeInterval:target:selector:userInfo:repeats:"
            => unscheduled_timer, c"@48@0:8d16@24:32@40c48";
        "scheduledTimerWithTimeInterval:repeats:block:"
            => scheduled_block_timer, c"@36@0:8d16c24@?28";
        "timerWithTimeInterval:repeats:block:"
            => block_timer, c"@36@0:8d16c24@?28";
    });
    methods!(timer_class, {
        "dealloc" => timer_dealloc, c"v16@0:8";
        "initWithFireDate:interval:target:selector:userInfo:repeats:"
            => init_with_fire_date, c"@60@0:8@16d24@32:40@48c56";
        "initWithFireDate:interval:repeats:block:"
            => init_with_fire_date_block, c"@44@0:8@16d24c32@?36";
        "invalidate" => invalidate, c"v16@0:8";
        "isValid" => is_valid, c"B16@0:8";
        "fire" => timer_fire, c"v16@0:8";
        "userInfo" => user_info, c"@16@0:8";
        "timeInterval" => time_interval, c"d16@0:8";
        "fireDate" => fire_date, c"@16@0:8";
        "setFireDate:" => set_fire_date, c"v24@0:8@16";
        "tolerance" => tolerance, c"d16@0:8";
        "setTolerance:" => set_tolerance, c"v24@0:8d16";
    });

    let run_loop = corefoundation::base::register(
        c"NSRunLoop",
        None,
        std::mem::size_of::<RunLoopObject>(),
        false,
    );
    class_methods!(run_loop, {
        "currentRunLoop" => current_run_loop, c"@16@0:8";
        "mainRunLoop" => main_run_loop, c"@16@0:8";
    });
    methods!(run_loop, {
        "getCFRunLoop" => get_cf_run_loop, c"^{__CFRunLoop=}16@0:8";
        "addTimer:forMode:" => add_timer_for_mode, c"v32@0:8@16@24";
        "runMode:beforeDate:" => run_mode_before_date, c"B32@0:8@16@24";
        "runUntilDate:" => run_until_date, c"v24@0:8@16";
        "run" => run_forever, c"v16@0:8";
        "acceptInputForMode:beforeDate:" => accept_input, c"v32@0:8@16@24";
        "limitDateForMode:" => limit_date_for_mode, c"@24@0:8@16";
        "currentMode" => current_mode, c"@16@0:8";
        "performSelector:target:argument:order:modes:" => perform_selector,
            c"v56@0:8:16@24@32Q40@48";
        "cancelPerformSelector:target:argument:" => cancel_perform_selector,
            c"v40@0:8:16@24@32";
        "cancelPerformSelectorsWithTarget:" => cancel_perform_selectors_with_target,
            c"v24@0:8@16";
        "addPort:forMode:" => add_port, c"v32@0:8@16@24";
        "removePort:forMode:" => remove_port, c"v32@0:8@16@24";
        "_rosemaryPortDidBecomeInvalid:" => port_invalidated, c"v24@0:8@16";
    });
}

/// Core Foundation's toll-free bridge to `NSDate`.
pub mod cf {
    #![allow(non_snake_case)]

    use corefoundation::base::{CFTypeID, CFTypeRef};
    use objc::object::Id;

    unsafe extern "C" fn CFDateGetTypeID() -> CFTypeID {
        let class = objc::class::lookup(c"NSDate").expect("registered by timer::install");
        corefoundation::base::type_id(class)
    }

    unsafe extern "C" fn CFDateCreate(_allocator: CFTypeRef, interval: f64) -> Id {
        super::make_date(interval)
    }

    unsafe extern "C" fn CFDateGetAbsoluteTime(date: Id) -> f64 {
        super::date_of(date)
    }

    exports::exports! {
        functions {
            "CFDateGetTypeID" => CFDateGetTypeID,
            "CFDateCreate" => CFDateCreate,
            "CFDateGetAbsoluteTime" => CFDateGetAbsoluteTime,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REPEATED: AtomicUsize = AtomicUsize::new(0);
    static ONCE: AtomicUsize = AtomicUsize::new(0);
    static MAIN_THREAD_ARGUMENT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn repeated(_receiver: Id, _sel: Sel, _timer: Id) {
        REPEATED.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn once(_receiver: Id, _sel: Sel, _timer: Id) {
        ONCE.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn performed_on_main(_receiver: Id, _sel: Sel, object: Id) {
        MAIN_THREAD_ARGUMENT.store(object as usize, Ordering::SeqCst);
    }

    /// A target of this test's own.
    ///
    /// One per test, because the tests share a process: a counter shared
    /// between them would make each assertion depend on what else was running.
    fn target(name: &std::ffi::CStr, imp: unsafe extern "C" fn(Id, Sel, Id)) -> Id {
        crate::bootstrap();
        let class = corefoundation::base::register(name, None, std::mem::size_of::<usize>(), false);
        methods!(class, {
            "tick:" => imp, c"v24@0:8@16";
        });
        objc::object::create_instance(class, 0)
    }

    /// A deferred main-thread perform owns its target and argument until the
    /// main queue delivers the selector.
    #[test]
    fn a_selector_is_deferred_to_the_main_queue() {
        let receiver = target(c"RosemaryTestMainThreadPerformTarget", performed_on_main);
        let object = target(c"RosemaryTestMainThreadPerformObject", once);
        let expected = object as usize;
        MAIN_THREAD_ARGUMENT.store(0, Ordering::SeqCst);

        // SAFETY: both objects are live and `tick:` takes one object.
        unsafe {
            perform_on_main_thread(
                receiver,
                objc::sel::get("performSelectorOnMainThread:withObject:waitUntilDone:"),
                objc::sel::get("tick:"),
                object,
                0,
            );
        }
        assert_eq!(MAIN_THREAD_ARGUMENT.load(Ordering::SeqCst), 0);
        objc::arc::release(receiver);
        objc::arc::release(object);

        darwin::dispatch::queue::drain_main();
        assert_eq!(MAIN_THREAD_ARGUMENT.load(Ordering::SeqCst), expected);
    }

    /// A scheduled repeating timer fires from the run loop, and stops when it is
    /// invalidated.
    #[test]
    fn a_scheduled_timer_fires_until_it_is_invalidated() {
        let target = target(c"RosemaryTestRepeatingTarget", repeated);
        REPEATED.store(0, Ordering::SeqCst);
        // SAFETY: the prototype is the class method's.
        let timer = unsafe {
            scheduled_timer(
                std::ptr::null_mut(),
                objc::sel::get("scheduledTimerWithTimeInterval:"),
                0.005,
                target,
                objc::sel::get("tick:"),
                std::ptr::null_mut(),
                1,
            )
        };
        // SAFETY: `-isValid` is `BOOL (id, SEL)`.
        assert_eq!(unsafe { is_valid(timer, objc::sel::get("isValid")) }, 1);

        for _ in 0..100 {
            if REPEATED.load(Ordering::SeqCst) >= 2 {
                break;
            }
            corefoundation::runloop::current().run_in_mode(
                corefoundation::runloop::DEFAULT_MODE,
                0.01,
                false,
            );
        }
        assert!(
            REPEATED.load(Ordering::SeqCst) >= 2,
            "the timer did not repeat"
        );

        // SAFETY: `-invalidate` is `void (id, SEL)`.
        unsafe { invalidate(timer, objc::sel::get("invalidate")) };
        assert_eq!(unsafe { is_valid(timer, objc::sel::get("isValid")) }, 0);
        let after = REPEATED.load(Ordering::SeqCst);
        for _ in 0..5 {
            corefoundation::runloop::current().run_in_mode(
                corefoundation::runloop::DEFAULT_MODE,
                0.01,
                false,
            );
        }
        assert_eq!(
            REPEATED.load(Ordering::SeqCst),
            after,
            "it fired after invalidation"
        );
    }

    /// A non-repeating timer invalidates itself, which is what stops a
    /// one-shot from becoming a frame loop.
    #[test]
    fn a_one_shot_timer_stops_itself() {
        let target = target(c"RosemaryTestOneShotTarget", once);
        ONCE.store(0, Ordering::SeqCst);
        // SAFETY: the prototype is the class method's.
        let timer = unsafe {
            scheduled_timer(
                std::ptr::null_mut(),
                objc::sel::get("scheduledTimerWithTimeInterval:"),
                0.005,
                target,
                objc::sel::get("tick:"),
                std::ptr::null_mut(),
                0,
            )
        };
        for _ in 0..100 {
            if ONCE.load(Ordering::SeqCst) >= 1 {
                break;
            }
            corefoundation::runloop::current().run_in_mode(
                corefoundation::runloop::DEFAULT_MODE,
                0.01,
                false,
            );
        }
        assert_eq!(
            ONCE.load(Ordering::SeqCst),
            1,
            "a one-shot fired more than once"
        );
        // SAFETY: `-isValid` is `BOOL (id, SEL)`.
        assert_eq!(unsafe { is_valid(timer, objc::sel::get("isValid")) }, 0);
    }

    static WORKER_SOURCE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn count_worker_source(_info: *mut c_void) {
        WORKER_SOURCE.fetch_add(1, Ordering::SeqCst);
    }

    fn send_id(receiver: Id, selector: &str) -> Id {
        // SAFETY: `objc_msgSend`, as `id (id, SEL)`.
        unsafe {
            let f: unsafe extern "C" fn(Id, Sel) -> Id = std::mem::transmute(objc::msg::entry());
            f(receiver, objc::sel::get(selector))
        }
    }

    fn run_loop_class() -> Id {
        crate::bootstrap();
        objc::class::ptr(objc::class::lookup(c"NSRunLoop").unwrap()) as Id
    }

    /// `+currentRunLoop` is the calling thread's, the same object each time it
    /// is asked there, and another thread's is another; `+mainRunLoop` is one
    /// object from everywhere; `-getCFRunLoop` is `CFRunLoopGetCurrent`.
    #[test]
    fn each_thread_has_its_own_run_loop() {
        let class = run_loop_class();
        let here = send_id(class, "currentRunLoop");
        assert_eq!(here, send_id(class, "currentRunLoop"));
        let class_word = class as usize;
        let main = send_id(class, "mainRunLoop");
        // SAFETY: no arguments.
        let cf = unsafe { corefoundation::api::CFRunLoopGetCurrent() };
        assert_eq!(send_id(here, "getCFRunLoop") as usize, cf as usize);
        let (there, main_there) = std::thread::spawn(move || {
            let class = class_word as Id;
            (
                send_id(class, "currentRunLoop") as usize,
                send_id(class, "mainRunLoop") as usize,
            )
        })
        .join()
        .unwrap();
        assert_ne!(here as usize, there);
        assert_eq!(main as usize, main_there);
        assert_ne!(here, main, "a test thread is not the main thread");
    }

    /// Running another thread's loop does nothing: NO, and none of that
    /// loop's sources serviced on the wrong thread.
    #[test]
    fn a_run_loop_runs_only_on_its_own_thread() {
        let class_word = run_loop_class() as usize;
        let (tx, rx) = std::sync::mpsc::channel::<usize>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let mine = send_id(class_word as Id, "currentRunLoop");
            let source = corefoundation::runloop::new_source(Some(count_worker_source), 0);
            corefoundation::runloop::current().add_source(&source, corefoundation::runloop::DEFAULT_MODE);
            source.signal();
            tx.send(mine as usize).unwrap();
            done_rx.recv().unwrap();
            source
        });
        let theirs = rx.recv().unwrap() as Id;
        let before = WORKER_SOURCE.load(Ordering::SeqCst);
        // SAFETY: `-runMode:beforeDate:` is `BOOL (id, SEL, id, id)`.
        let ran = unsafe {
            run_mode_before_date(theirs, objc::sel::get("runMode:beforeDate:"), std::ptr::null_mut(), date(now() + 0.05))
        };
        assert_eq!(ran, 0, "ran another thread's loop");
        assert_eq!(WORKER_SOURCE.load(Ordering::SeqCst), before, "serviced another thread's source");
        done_tx.send(()).unwrap();
        let _source = worker.join().unwrap();
    }

    /// A mode with nothing in it is not run: `-runMode:beforeDate:` answers NO
    /// at once rather than waiting out its date.
    #[test]
    fn an_empty_mode_is_not_run() {
        let here = send_id(run_loop_class(), "currentRunLoop");
        let start = std::time::Instant::now();
        let mode = foundation_string("RosemaryTestEmptyMode");
        // SAFETY: as above.
        let ran = unsafe {
            run_mode_before_date(here, objc::sel::get("runMode:beforeDate:"), mode, date(now() + 2.0))
        };
        assert_eq!(ran, 0);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    fn foundation_string(text: &str) -> Id {
        crate::string::from_str(text)
    }

    static CUSTOM: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn custom(_receiver: Id, _sel: Sel, _timer: Id) {
        CUSTOM.fetch_add(1, Ordering::SeqCst);
    }

    /// A timer added for one mode fires in that mode only, and adding it for a
    /// second mode afterwards puts it there too.
    #[test]
    fn a_timer_fires_in_the_modes_it_was_added_for() {
        let target = target(c"RosemaryTestCustomModeTarget", custom);
        CUSTOM.store(0, Ordering::SeqCst);
        let here = send_id(run_loop_class(), "currentRunLoop");
        // SAFETY: the prototype is the class method's.
        let timer = unsafe {
            unscheduled_timer(std::ptr::null_mut(), objc::sel::get("timerWithTimeInterval:"), 0.005, target, objc::sel::get("tick:"), std::ptr::null_mut(), 1)
        };
        let custom_mode = foundation_string("RosemaryTestCustomMode");
        // SAFETY: `-addTimer:forMode:` is `void (id, SEL, id, id)`.
        unsafe { add_timer_for_mode(here, objc::sel::get("addTimer:forMode:"), timer, custom_mode) };
        let current = corefoundation::runloop::current();
        current.run_in_mode(corefoundation::runloop::DEFAULT_MODE, 0.03, false);
        assert_eq!(CUSTOM.load(Ordering::SeqCst), 0, "fired in a mode it was not added for");
        current.run_in_mode("RosemaryTestCustomMode", 0.03, false);
        assert!(CUSTOM.load(Ordering::SeqCst) >= 1, "did not fire in its mode");
        // SAFETY: as above, with nil for the default mode.
        unsafe { add_timer_for_mode(here, objc::sel::get("addTimer:forMode:"), timer, std::ptr::null_mut()) };
        let before = CUSTOM.load(Ordering::SeqCst);
        current.run_in_mode(corefoundation::runloop::DEFAULT_MODE, 0.03, false);
        assert!(CUSTOM.load(Ordering::SeqCst) > before, "adding a second mode was ignored");
        // SAFETY: `-invalidate` is `void (id, SEL)`.
        unsafe { invalidate(timer, objc::sel::get("invalidate")) };
    }

    static PERFORMED: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    unsafe extern "C" fn record_performed(_receiver: Id, _sel: Sel, argument: Id) {
        PERFORMED.lock().unwrap().push(argument as usize);
    }

    fn array_of(objects: &[Id]) -> Id {
        let class = objc::class::ptr(objc::class::lookup(c"NSArray").unwrap()) as Id;
        // SAFETY: `+arrayWithObjects:count:` is `id (Class, SEL, const id *, NSUInteger)`.
        unsafe {
            let f: unsafe extern "C" fn(Id, Sel, *const Id, usize) -> Id =
                std::mem::transmute(objc::msg::entry());
            f(class, objc::sel::get("arrayWithObjects:count:"), objects.as_ptr(), objects.len())
        }
    }

    /// Scheduled messages are sent on the loop's next pass in one of their
    /// modes, lowest order first; a cancelled one is not sent at all.
    #[test]
    fn scheduled_messages_are_sent_in_order_unless_cancelled() {
        let target = target(c"RosemaryTestPerformTarget", record_performed);
        let here = send_id(run_loop_class(), "currentRunLoop");
        let default = array_of(&[foundation_string("kCFRunLoopDefaultMode")]);
        let other = array_of(&[foundation_string("RosemaryTestPerformMode")]);
        let (first, second, third, cancelled) = (
            foundation_string("first"),
            foundation_string("second"),
            foundation_string("third"),
            foundation_string("cancelled"),
        );
        let tick = objc::sel::get("tick:");
        let sel = objc::sel::get("performSelector:target:argument:order:modes:");
        // SAFETY: the methods' own prototypes.
        unsafe {
            perform_selector(here, sel, tick, target, second, 20, default);
            perform_selector(here, sel, tick, target, first, 10, default);
            perform_selector(here, sel, tick, target, third, 0, other);
            perform_selector(here, sel, tick, target, cancelled, 0, default);
            cancel_perform_selector(
                here,
                objc::sel::get("cancelPerformSelector:target:argument:"),
                tick,
                target,
                foundation_string("cancelled"),
            );
        }
        PERFORMED.lock().unwrap().clear();
        let current = corefoundation::runloop::current();
        current.run_in_mode(corefoundation::runloop::DEFAULT_MODE, 0.0, false);
        assert_eq!(*PERFORMED.lock().unwrap(), vec![first as usize, second as usize]);
        current.run_in_mode("RosemaryTestPerformMode", 0.0, false);
        assert_eq!(
            *PERFORMED.lock().unwrap(),
            vec![first as usize, second as usize, third as usize]
        );
    }

    /// An unscheduled timer is valid until it is invalidated, as Apple's is.
    #[test]
    fn an_unscheduled_timer_is_valid() {
        let target = target(c"RosemaryTestUnscheduledTarget", once);
        // SAFETY: the prototype is the class method's.
        let timer = unsafe {
            unscheduled_timer(std::ptr::null_mut(), objc::sel::get("timerWithTimeInterval:"), 1.0, target, objc::sel::get("tick:"), std::ptr::null_mut(), 0)
        };
        // SAFETY: `BOOL (id, SEL)` and `void (id, SEL)`.
        unsafe {
            assert_eq!(is_valid(timer, objc::sel::get("isValid")), 1);
            invalidate(timer, objc::sel::get("invalidate"));
            assert_eq!(is_valid(timer, objc::sel::get("isValid")), 0);
        }
    }

    /// A date is seconds since Apple's epoch, and the Unix conversion is the
    /// difference between the two - which is the one number here that can be
    /// wrong by thirty years without looking wrong.
    #[test]
    fn a_date_agrees_with_the_unix_epoch() {
        crate::bootstrap();
        let d = date(0.0);
        // SAFETY: both are `double (id, SEL)`.
        unsafe {
            assert_eq!(
                time_interval_since_1970(d, objc::sel::get("timeIntervalSince1970")),
                UNIX_TO_REFERENCE
            );
            assert_eq!(
                time_interval_since_reference(d, objc::sel::get("timeIntervalSinceReferenceDate")),
                0.0
            );
        }
    }
}
