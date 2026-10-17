#![allow(clippy::manual_dangling_ptr, clippy::missing_safety_doc)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `CVReturn`. Zero is success, and the one failure this reports is
/// `kCVReturnInvalidArgument`.
const SUCCESS: i32 = 0;
const INVALID_ARGUMENT: i32 = -6661;

/// `CVTimeStamp`, which the callback receives twice - "now" and "when this frame
/// will be shown".
///
/// Eighty bytes, and the layout is ABI: a guest reads `videoTime` and
/// `videoTimeScale` out of it to work out how much time has passed. Checked
/// against the header rather than counted.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimeStamp {
    pub version: u32,
    pub video_time_scale: i32,
    pub video_time: i64,
    pub host_time: u64,
    pub rate_scalar: f64,
    pub video_refresh_period: i64,
    /// `CVSMPTETime`, which nothing here fills in.
    smpte_time: [u8; 24],
    pub flags: u64,
    pub reserved: u64,
}

/// `CVTimeStampFlags`: which of a timestamp's fields mean something.
mod stamp {
    pub const VIDEO_TIME_VALID: u64 = 1 << 0;
    pub const HOST_TIME_VALID: u64 = 1 << 1;
    pub const VIDEO_REFRESH_PERIOD_VALID: u64 = 1 << 3;
    pub const RATE_SCALAR_VALID: u64 = 1 << 4;
    /// What every stamp a link makes carries.
    pub const LINK: u64 =
        VIDEO_TIME_VALID | HOST_TIME_VALID | VIDEO_REFRESH_PERIOD_VALID | RATE_SCALAR_VALID;
}

/// The scale a link's video times are counted in, nanoseconds.
const VIDEO_SCALE: i32 = 1_000_000_000;

const _: () = {
    assert!(size_of::<TimeStamp>() == 80);
    assert!(std::mem::offset_of!(TimeStamp, video_time) == 8);
    assert!(std::mem::offset_of!(TimeStamp, host_time) == 16);
    assert!(std::mem::offset_of!(TimeStamp, rate_scalar) == 24);
    assert!(std::mem::offset_of!(TimeStamp, video_refresh_period) == 32);
    assert!(std::mem::offset_of!(TimeStamp, flags) == 64);
};

/// `CVDisplayLinkOutputCallback`.
type OutputCallback = unsafe extern "C" fn(
    *mut c_void,
    *const TimeStamp,
    *const TimeStamp,
    u64,
    *mut u64,
    *mut c_void,
) -> i32;

/// One display link.
struct Link {
    /// References the guest holds. `CVDisplayLinkRef` is a CF type: the create
    /// returns one, and the last release stops and frees the link.
    refs: usize,
    /// The display the link follows, `CVDisplayLinkGetCurrentCGDisplay`.
    display: u32,
    callback: Option<OutputCallback>,
    context: *mut c_void,
    /// Set while the link's thread should keep calling back. Cleared by
    /// [`CVDisplayLinkStop`], which is the thread's only stop signal.
    running: Option<Arc<AtomicBool>>,
    /// Seconds between frames, from the display SDL reports.
    period: f64,
    /// How many times the callback has run, which is the `videoTime` a guest
    /// integrates to get elapsed time.
    frame: i64,
    started: std::time::Instant,
}

// SAFETY: the context is the guest's own pointer and is only ever handed back to
// the guest's callback; the callback is a thunk this runtime made.
unsafe impl Send for Link {}

/// Every link this process has made, by the handle the guest holds.
///
/// The handle is the address of the `Arc`'s contents, which is stable and unique
/// for as long as the link is alive - so it is the `CVDisplayLinkRef` itself
/// rather than an index a guest could fabricate.
static LINKS: Mutex<Vec<(usize, Arc<Mutex<Link>>)>> = Mutex::new(Vec::new());

fn link_for(handle: *mut c_void) -> Option<Arc<Mutex<Link>>> {
    LINKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(h, _)| *h == handle as usize)
        .map(|(_, link)| Arc::clone(link))
}

/// The refresh period of a display, in seconds.
///
/// A zero display names the primary display for the active-displays spelling.
/// Sixty hertz is only a fallback for a host with no SDL video subsystem or no
/// desktop mode; a real display link follows the mode SDL reports.
fn display_period(display: u32) -> f64 {
    let display = resolve(display);
    let refresh_rate = sdl3::video::display_refresh_rate(display).unwrap_or(60.0);
    1.0 / f64::from(refresh_rate)
}

/// A zero display, which the active-displays spelling passes, as the main one.
fn resolve(display: u32) -> u32 {
    match display {
        0 => sdl3::video::primary_display(),
        display => display,
    }
}

/// `CVReturn CVDisplayLinkCreateWithCGDisplay(CGDirectDisplayID, CVDisplayLinkRef *)`.
///
/// # Safety
///
/// `out` must be null or a writable pointer-sized slot.
pub unsafe extern "C" fn CVDisplayLinkCreateWithCGDisplay(
    display: u32,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() {
        return INVALID_ARGUMENT;
    }
    let link = Arc::new(Mutex::new(Link {
        refs: 1,
        display: resolve(display),
        callback: None,
        context: std::ptr::null_mut(),
        running: None,
        period: display_period(display),
        frame: 0,
        started: std::time::Instant::now(),
    }));
    // The handle is the `Mutex`'s address, which the `Arc` in the table keeps
    // alive for as long as the link exists.
    let handle = Arc::as_ptr(&link) as *mut c_void;
    LINKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((handle as usize, link));
    unsafe { *out = handle };
    SUCCESS
}

/// As above, for the "all active displays" spelling. One display link either
/// way: this runtime draws into one window.
///
/// # Safety
///
/// As [`CVDisplayLinkCreateWithCGDisplay`].
pub unsafe extern "C" fn CVDisplayLinkCreateWithActiveCGDisplays(out: *mut *mut c_void) -> i32 {
    unsafe { CVDisplayLinkCreateWithCGDisplay(0, out) }
}

/// `CVReturn CVDisplayLinkCreateWithCGDisplays(CGDirectDisplayID *, CFIndex,
/// CVDisplayLinkRef *)`: a link that can follow any of the displays, and
/// starts on the first.
///
/// # Safety
///
/// `displays` must hold `count` display IDs; `out` as above.
pub unsafe extern "C" fn CVDisplayLinkCreateWithCGDisplays(
    displays: *const u32,
    count: isize,
    out: *mut *mut c_void,
) -> i32 {
    if displays.is_null() || count < 1 {
        return INVALID_ARGUMENT;
    }
    // SAFETY: at least one display, by the check above.
    unsafe { CVDisplayLinkCreateWithCGDisplay(*displays, out) }
}

/// `CGDirectDisplayID CVDisplayLinkGetCurrentCGDisplay(CVDisplayLinkRef)`, or
/// `kCGNullDirectDisplay` for a handle that names no link.
pub unsafe extern "C" fn CVDisplayLinkGetCurrentCGDisplay(handle: *mut c_void) -> u32 {
    link_for(handle).map_or(0, |link| {
        link.lock().unwrap_or_else(|e| e.into_inner()).display
    })
}

/// # Safety
///
/// `callback` must be a host-callable function of the display link's prototype -
/// which for a guest's own function is the thunk `rosemary`'s ABI layer made,
/// because the table entry names the parameter a callback.
pub unsafe extern "C" fn CVDisplayLinkSetOutputCallback(
    handle: *mut c_void,
    callback: *mut c_void,
    context: *mut c_void,
) -> i32 {
    let Some(link) = link_for(handle) else {
        return INVALID_ARGUMENT;
    };
    let mut link = link.lock().unwrap_or_else(|e| e.into_inner());
    link.callback = (!callback.is_null())
        .then(|| unsafe { std::mem::transmute::<*mut c_void, OutputCallback>(callback) });
    link.context = context;
    SUCCESS
}

pub unsafe extern "C" fn CVDisplayLinkSetCurrentCGDisplay(
    handle: *mut c_void,
    display: u32,
) -> i32 {
    let Some(link) = link_for(handle) else {
        return INVALID_ARGUMENT;
    };
    let mut link = link.lock().unwrap_or_else(|e| e.into_inner());
    link.display = resolve(display);
    link.period = display_period(display);
    SUCCESS
}

pub unsafe extern "C" fn CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext(
    handle: *mut c_void,
    _context: *mut c_void,
    _format: *mut c_void,
) -> i32 {
    match link_for(handle).is_some() {
        true => SUCCESS,
        false => INVALID_ARGUMENT,
    }
}

pub unsafe extern "C" fn CVDisplayLinkGetActualOutputVideoRefreshPeriod(
    handle: *mut c_void,
) -> f64 {
    link_for(handle).map_or(0.0, |link| {
        link.lock().unwrap_or_else(|e| e.into_inner()).period
    })
}

/// `CVTime`: sixteen bytes, so both ABIs return it in two integer registers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Time {
    pub time_value: i64,
    pub time_scale: i32,
    pub flags: i32,
}

/// `kCVTimeIsIndefinite`, for a handle that names no link.
const TIME_IS_INDEFINITE: i32 = 1;

/// The scale the nominal period is reported in, nanoseconds.
const NOMINAL_SCALE: i32 = 1_000_000_000;

/// `CVTime CVDisplayLinkGetNominalOutputVideoRefreshPeriod(CVDisplayLinkRef)`
///
/// Unity 5 derives its frame rate cap from this; zero reads as "invalid".
pub unsafe extern "C" fn CVDisplayLinkGetNominalOutputVideoRefreshPeriod(
    handle: *mut c_void,
) -> Time {
    match link_for(handle) {
        Some(link) => {
            let period = link.lock().unwrap_or_else(|e| e.into_inner()).period;
            Time {
                time_value: (period * f64::from(NOMINAL_SCALE)).round() as i64,
                time_scale: NOMINAL_SCALE,
                flags: 0,
            }
        }
        None => Time {
            time_value: 0,
            time_scale: 0,
            flags: TIME_IS_INDEFINITE,
        },
    }
}

/// `CVTime CVDisplayLinkGetOutputVideoLatency(CVDisplayLinkRef)`: zero, in
/// the nominal period's scale - a frame drawn is a frame shown, as far as
/// anything here can tell - or indefinite for a handle that names no link.
pub unsafe extern "C" fn CVDisplayLinkGetOutputVideoLatency(handle: *mut c_void) -> Time {
    match link_for(handle) {
        Some(_) => Time {
            time_value: 0,
            time_scale: NOMINAL_SCALE,
            flags: 0,
        },
        None => Time {
            time_value: 0,
            time_scale: 0,
            flags: TIME_IS_INDEFINITE,
        },
    }
}

/// `CVReturn CVDisplayLinkGetCurrentTime(CVDisplayLinkRef, CVTimeStamp *)`:
/// the link's "now". The caller sets `version` to zero, as for every
/// `CVTimeStamp` it hands CoreVideo.
///
/// # Safety
///
/// `out` must be null or a writable `CVTimeStamp`.
pub unsafe extern "C" fn CVDisplayLinkGetCurrentTime(
    handle: *mut c_void,
    out: *mut TimeStamp,
) -> i32 {
    let Some(link) = link_for(handle) else {
        return INVALID_ARGUMENT;
    };
    if out.is_null() {
        return INVALID_ARGUMENT;
    }
    let now = stamp_now(&link.lock().unwrap_or_else(|e| e.into_inner()));
    // SAFETY: the caller's stamp.
    unsafe { *out = now };
    SUCCESS
}

/// `uint64_t CVGetCurrentHostTime(void)`: `mach_absolute_time`.
pub unsafe extern "C" fn CVGetCurrentHostTime() -> u64 {
    darwin::mach::absolute()
}

/// `double CVGetHostClockFrequency(void)`: host ticks per second, which with a
/// one-to-one timebase are nanoseconds.
pub unsafe extern "C" fn CVGetHostClockFrequency() -> f64 {
    1e9
}

/// `uint32_t CVGetHostClockMinimumTimeDelta(void)`: the smallest step the host
/// clock takes, one tick.
pub unsafe extern "C" fn CVGetHostClockMinimumTimeDelta() -> u32 {
    1
}

/// A link's "now": video time counted from its start, host time on the
/// guest's `mach_absolute_time` line.
fn stamp_now(link: &Link) -> TimeStamp {
    let elapsed = link.started.elapsed().as_secs_f64();
    TimeStamp {
        version: 0,
        video_time_scale: VIDEO_SCALE,
        video_time: (elapsed * f64::from(VIDEO_SCALE)) as i64,
        host_time: darwin::mach::absolute(),
        rate_scalar: 1.0,
        video_refresh_period: (link.period * f64::from(VIDEO_SCALE)) as i64,
        smpte_time: [0; 24],
        flags: stamp::LINK,
        reserved: 0,
    }
}

/// `CVDisplayLinkStart`: start the thread that calls the guest back.
pub unsafe extern "C" fn CVDisplayLinkStart(handle: *mut c_void) -> i32 {
    let Some(link) = link_for(handle) else {
        return INVALID_ARGUMENT;
    };
    let (period, running) = {
        let mut guard = link.lock().unwrap_or_else(|e| e.into_inner());
        if guard.running.is_some() {
            return SUCCESS;
        }
        guard.started = std::time::Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        guard.running = Some(Arc::clone(&running));
        (guard.period, running)
    };

    let period = std::time::Duration::from_secs_f64(period);
    let at = handle as usize;
    // Detached. A guest may stop its link from inside the callback, and a
    // `Stop` that joined would then be the thread waiting for itself.
    std::thread::Builder::new()
        .name("CVDisplayLink".to_string())
        .spawn(move || {
            // The callback is guest code, which reads its thread identity off the
            // thread pointer - its parent's on a new thread until it enters.
            let _darwin = darwin::tls::DarwinThread::enter();
            let mut next = std::time::Instant::now() + period;
            while running.load(Ordering::Acquire) {
                let now = std::time::Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                } else {
                    // Behind: give up the frames that were missed rather than
                    // calling back in a burst to catch up.
                    next = now;
                }
                next += period;
                if !running.load(Ordering::Acquire) {
                    break;
                }
                // SAFETY: `at` is a handle this module made, and the table keeps
                // it alive.
                unsafe { fire(std::ptr::null(), at as *mut c_void) };
            }
        })
        .map_or(INVALID_ARGUMENT, |_| SUCCESS)
}

pub unsafe extern "C" fn CVDisplayLinkStop(handle: *mut c_void) -> i32 {
    let Some(link) = link_for(handle) else {
        return INVALID_ARGUMENT;
    };
    let running = link
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .running
        .take();
    if let Some(running) = running {
        running.store(false, Ordering::Release);
    }
    SUCCESS
}

/// `CVDisplayLinkRef CVDisplayLinkRetain(CVDisplayLinkRef)`: the link, with
/// one more reference. NULL in, NULL out.
pub unsafe extern "C" fn CVDisplayLinkRetain(handle: *mut c_void) -> *mut c_void {
    if let Some(link) = link_for(handle) {
        link.lock().unwrap_or_else(|e| e.into_inner()).refs += 1;
    }
    handle
}

/// `void CVDisplayLinkRelease(CVDisplayLinkRef)`. The last reference stops the
/// link, so its thread calls back no more, and forgets it. NULL is ignored.
pub unsafe extern "C" fn CVDisplayLinkRelease(handle: *mut c_void) {
    let Some(link) = link_for(handle) else {
        return;
    };
    let last = {
        let mut link = link.lock().unwrap_or_else(|e| e.into_inner());
        link.refs = link.refs.saturating_sub(1);
        if link.refs > 0 {
            return;
        }
        link.running.take()
    };
    if let Some(running) = last {
        running.store(false, Ordering::Release);
    }
    LINKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(h, _)| *h != handle as usize);
}

pub unsafe extern "C" fn CVDisplayLinkIsRunning(handle: *mut c_void) -> u8 {
    link_for(handle).is_some_and(|link| {
        link.lock()
            .unwrap_or_else(|e| e.into_inner())
            .running
            .is_some()
    }) as u8
}

/// One turn of the link: build the two timestamps and call the guest.
///
/// `info` is the link's handle, which is how one function serves them all.
unsafe extern "C" fn fire(_timer: *const c_void, info: *mut c_void) {
    let Some(link) = link_for(info) else {
        return;
    };
    let (callback, context, now, output) = {
        let mut guard = link.lock().unwrap_or_else(|e| e.into_inner());
        let Some(callback) = guard.callback else {
            return;
        };
        guard.frame += 1;
        let now = stamp_now(&guard);
        // The frame after this one, which is what "output time" means: one
        // period later on both clocks.
        let output = TimeStamp {
            video_time: now.video_time + now.video_refresh_period,
            host_time: now.host_time + now.video_refresh_period as u64,
            ..now
        };
        (callback, guard.context, now, output)
    };
    // Called with the lock released: the guest's callback may stop the link, and
    // `CVDisplayLinkStop` takes the same lock.
    let mut flags_out = 0u64;
    // SAFETY: `callback` is the thunk the guest's function was registered
    // through, and the two timestamps outlive the call.
    unsafe { callback(info, &now, &output, 0, &mut flags_out, context) };
}

exports::exports! {
    functions {
        "CVDisplayLinkCreateWithCGDisplay" => CVDisplayLinkCreateWithCGDisplay,
        "CVDisplayLinkCreateWithActiveCGDisplays" => CVDisplayLinkCreateWithActiveCGDisplays,
        "CVDisplayLinkSetOutputCallback" => CVDisplayLinkSetOutputCallback,
        "CVDisplayLinkSetCurrentCGDisplay" => CVDisplayLinkSetCurrentCGDisplay,
        "CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext" => CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext,
        "CVDisplayLinkGetActualOutputVideoRefreshPeriod" => CVDisplayLinkGetActualOutputVideoRefreshPeriod,
        "CVDisplayLinkGetNominalOutputVideoRefreshPeriod" => CVDisplayLinkGetNominalOutputVideoRefreshPeriod,
        "CVDisplayLinkStart" => CVDisplayLinkStart,
        "CVDisplayLinkStop" => CVDisplayLinkStop,
        "CVDisplayLinkRetain" => CVDisplayLinkRetain,
        "CVDisplayLinkRelease" => CVDisplayLinkRelease,
        "CVDisplayLinkIsRunning" => CVDisplayLinkIsRunning,
        "CVDisplayLinkCreateWithCGDisplays" => CVDisplayLinkCreateWithCGDisplays,
        "CVDisplayLinkGetCurrentCGDisplay" => CVDisplayLinkGetCurrentCGDisplay,
        "CVDisplayLinkGetOutputVideoLatency" => CVDisplayLinkGetOutputVideoLatency,
        "CVDisplayLinkGetCurrentTime" => CVDisplayLinkGetCurrentTime,
        "CVGetCurrentHostTime" => CVGetCurrentHostTime,
        "CVGetHostClockFrequency" => CVGetHostClockFrequency,
        "CVGetHostClockMinimumTimeDelta" => CVGetHostClockMinimumTimeDelta,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static SEEN_CONTEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record(
        _link: *mut c_void,
        now: *const TimeStamp,
        output: *const TimeStamp,
        _flags: u64,
        _flags_out: *mut u64,
        context: *mut c_void,
    ) -> i32 {
        FIRED.fetch_add(1, Ordering::SeqCst);
        SEEN_CONTEXT.store(context as usize, Ordering::SeqCst);
        // SAFETY: two timestamps the caller built on its own frame.
        unsafe {
            assert!((*output).video_time > (*now).video_time, "output is later");
        }
        SUCCESS
    }

    #[test]
    fn a_started_link_calls_back_on_its_own_thread() {
        FIRED.store(0, Ordering::SeqCst);
        let mut handle = std::ptr::null_mut();
        // SAFETY: a writable slot.
        assert_eq!(
            unsafe { CVDisplayLinkCreateWithCGDisplay(0, &mut handle) },
            SUCCESS
        );
        assert!(!handle.is_null());

        // SAFETY: `record` has the callback's prototype.
        assert_eq!(
            unsafe {
                CVDisplayLinkSetOutputCallback(handle, record as *mut c_void, 0x1234 as *mut c_void)
            },
            SUCCESS
        );
        // SAFETY: a link this test made.
        assert_eq!(unsafe { CVDisplayLinkStart(handle) }, SUCCESS);
        assert_eq!(unsafe { CVDisplayLinkIsRunning(handle) }, 1);

        // Nothing is turned here, which is the whole point: this thread does
        // not serve the link, so a guest may block on it.
        for _ in 0..100 {
            if FIRED.load(Ordering::SeqCst) >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            FIRED.load(Ordering::SeqCst) >= 2,
            "the link did not call back twice"
        );
        assert_eq!(
            SEEN_CONTEXT.load(Ordering::SeqCst),
            0x1234,
            "the context arrives"
        );

        // SAFETY: a link this test made.
        assert_eq!(unsafe { CVDisplayLinkStop(handle) }, SUCCESS);
        assert_eq!(unsafe { CVDisplayLinkIsRunning(handle) }, 0);

        // And a stopped link stops: the thread notices the flag within a frame.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let settled = FIRED.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            FIRED.load(Ordering::SeqCst),
            settled,
            "the thread kept firing"
        );
    }

    /// Unity 5 caps its frame rate from the nominal period, and reads zero as
    /// an invalid rate.
    #[test]
    fn the_nominal_period_is_the_actual_one_as_a_time() {
        let mut handle = std::ptr::null_mut();
        // SAFETY: a writable slot, then the handle it was given.
        unsafe {
            assert_eq!(CVDisplayLinkCreateWithCGDisplay(0, &mut handle), SUCCESS);
            let actual = CVDisplayLinkGetActualOutputVideoRefreshPeriod(handle);
            let nominal = CVDisplayLinkGetNominalOutputVideoRefreshPeriod(handle);
            assert!(nominal.time_value > 0 && nominal.time_scale > 0);
            let seconds = nominal.time_value as f64 / f64::from(nominal.time_scale);
            assert!((seconds - actual).abs() < 1e-6);
            CVDisplayLinkRelease(handle);
            assert_eq!(
                CVDisplayLinkGetNominalOutputVideoRefreshPeriod(0x1 as *mut c_void).flags,
                TIME_IS_INDEFINITE
            );
        }
    }

    /// A link stamps its times on the guest's `mach_absolute_time` line, says
    /// which fields are valid, and follows the display it was made for.
    #[test]
    fn a_link_reports_its_display_and_host_times() {
        let mut handle = std::ptr::null_mut();
        // SAFETY: a writable slot, then the handle it was given.
        unsafe {
            assert_eq!(CVDisplayLinkCreateWithCGDisplay(7, &mut handle), SUCCESS);
            assert_eq!(CVDisplayLinkGetCurrentCGDisplay(handle), 7);
            assert_eq!(CVDisplayLinkSetCurrentCGDisplay(handle, 9), SUCCESS);
            assert_eq!(CVDisplayLinkGetCurrentCGDisplay(handle), 9);

            let before = CVGetCurrentHostTime();
            let mut now = TimeStamp::default();
            assert_eq!(CVDisplayLinkGetCurrentTime(handle, &mut now), SUCCESS);
            let after = CVGetCurrentHostTime();
            assert!(before <= now.host_time && now.host_time <= after);
            assert_eq!(now.flags & stamp::LINK, stamp::LINK);
            assert!(now.video_refresh_period > 0 && now.video_time_scale > 0);

            // A retain is a second reference: one release leaves the link.
            assert_eq!(CVDisplayLinkRetain(handle), handle);
            CVDisplayLinkRelease(handle);
            assert_eq!(CVDisplayLinkGetCurrentCGDisplay(handle), 9);
            CVDisplayLinkRelease(handle);
            assert_eq!(CVDisplayLinkGetCurrentCGDisplay(handle), 0);
            assert_eq!(
                CVDisplayLinkGetCurrentTime(handle, &mut now),
                INVALID_ARGUMENT
            );
        }
    }

    /// A handle nothing made is refused rather than dereferenced.
    #[test]
    fn an_unknown_handle_is_an_invalid_argument() {
        // SAFETY: a pointer this module never handed out.
        unsafe {
            assert_eq!(CVDisplayLinkStart(0x1 as *mut c_void), INVALID_ARGUMENT);
            assert_eq!(
                CVDisplayLinkSetOutputCallback(
                    0x1 as *mut c_void,
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                INVALID_ARGUMENT
            );
        }
    }
}
