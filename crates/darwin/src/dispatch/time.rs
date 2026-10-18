//! `dispatch_time_t`, encoded as Apple's libdispatch encodes it (`src/time.c`
//! and `src/shims/time.h`): an uptime value is a `mach_absolute_time`, one
//! with bit 63 set is a `mach_continuous_time`, and one with bits 63 and 62
//! set is the negated wall-clock nanoseconds. `mach_absolute_time` counts
//! nanoseconds here, so no conversion is needed between the two.

/// `DISPATCH_TIME_NOW`: read the clock rather than using the base given.
pub const NOW: u64 = 0;
/// `DISPATCH_TIME_FOREVER`: a deadline that never arrives.
pub const FOREVER: u64 = u64::MAX;
/// `DISPATCH_WALLTIME_NOW`.
pub const WALLTIME_NOW: u64 = !1;
/// `DISPATCH_MONOTONICTIME_NOW`.
pub const MONOTONICTIME_NOW: u64 = 1 << 63;

const UP_OR_MONOTONIC_TIME_MASK: u64 = 1 << 63;
const WALLTIME_MASK: u64 = 1 << 62;
/// `DISPATCH_TIME_MAX_VALUE`
const MAX_VALUE: u64 = WALLTIME_MASK - 1;

/// `dispatch_clock_t`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clock {
    /// `mach_absolute_time`, which stops while the machine sleeps.
    Uptime,
    /// `mach_continuous_time`, which does not.
    Monotonic,
    /// Nanoseconds since the epoch.
    Wall,
}

impl Clock {
    /// What the clock reads now.
    pub fn now(self) -> u64 {
        match self {
            Clock::Uptime => crate::mach::absolute(),
            Clock::Monotonic => crate::mach::continuous(),
            Clock::Wall => wall_now(),
        }
    }
}

/// `_dispatch_get_nanoseconds`: the wall clock.
fn wall_now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes the `timespec` it is given and nothing else.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

/// The uptime clock `dispatch_time_t` counts on by default, in nanoseconds.
pub fn now() -> u64 {
    Clock::Uptime.now()
}

/// `_dispatch_time_to_clock_and_value`: which clock `time` is on, and its
/// value there - `FOREVER` for one out of that clock's range.
pub fn to_clock_and_value(time: u64, allow_now: bool) -> (Clock, u64) {
    if allow_now {
        match time {
            NOW => return (Clock::Uptime, Clock::Uptime.now()),
            MONOTONICTIME_NOW => return (Clock::Monotonic, Clock::Monotonic.now()),
            WALLTIME_NOW => return (Clock::Wall, Clock::Wall.now()),
            _ => {}
        }
    }
    let (clock, value) = match (time as i64) < 0 {
        true if time & WALLTIME_MASK != 0 => (Clock::Wall, time.wrapping_neg()),
        true => (Clock::Monotonic, time & !UP_OR_MONOTONIC_TIME_MASK),
        false => (Clock::Uptime, time),
    };
    (clock, if value > MAX_VALUE { FOREVER } else { value })
}

/// `_dispatch_clock_and_value_to_time`.
pub fn from_clock_and_value(clock: Clock, value: u64) -> u64 {
    if value >= MAX_VALUE {
        return FOREVER;
    }
    match clock {
        Clock::Wall => value.wrapping_neg(),
        Clock::Uptime => value,
        Clock::Monotonic => value | UP_OR_MONOTONIC_TIME_MASK,
    }
}

/// `dispatch_time_t dispatch_time(dispatch_time_t when, int64_t delta)`.
///
/// `delta` is signed nanoseconds. Overflow is `FOREVER`; underflow stops at
/// the clock's first value rather than wrapping, since a deadline that
/// wrapped would read as far in the future, or as `FOREVER` itself.
pub unsafe extern "C" fn time(when: u64, delta: i64) -> u64 {
    if when == FOREVER {
        return FOREVER;
    }
    let (clock, value) = to_clock_and_value(when, true);
    if value == FOREVER {
        return FOREVER;
    }
    if clock == Clock::Wall {
        let value = (value as i64).wrapping_add(delta);
        return match delta >= 0 {
            true if value <= 0 => FOREVER,
            // -1 is `FOREVER` once negated, so the floor is 2.
            false if value < 1 => from_clock_and_value(Clock::Wall, 2),
            _ => from_clock_and_value(Clock::Wall, value as u64),
        };
    }
    match delta >= 0 {
        true => {
            let value = value.wrapping_add(delta as u64);
            match (value as i64) <= 0 {
                true => FOREVER,
                false => from_clock_and_value(clock, value),
            }
        }
        false => {
            let value = value.wrapping_sub(delta.unsigned_abs());
            match (value as i64) < 1 {
                true => from_clock_and_value(clock, 1),
                false => from_clock_and_value(clock, value),
            }
        }
    }
}

/// `dispatch_time_t dispatch_walltime(const struct timespec *when, int64_t
/// delta)`: a wall-clock deadline, from `when` or from now.
///
/// # Safety
///
/// `when` is null or a readable `timespec`.
pub unsafe extern "C" fn walltime(when: *const libc::timespec, delta: i64) -> u64 {
    // SAFETY: the caller's null or `timespec`.
    let nsec = match unsafe { when.as_ref() } {
        Some(ts) => (ts.tv_sec as i64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as i64),
        None => wall_now() as i64,
    }
    .wrapping_add(delta);
    if nsec <= 1 {
        return match delta >= 0 {
            true => FOREVER,
            false => (-2i64) as u64,
        };
    }
    nsec.wrapping_neg() as u64
}

/// `_dispatch_timeout`: nanoseconds from now until `when`, on whichever clock
/// it is on - zero for one already past, `FOREVER` for one that never comes.
pub fn timeout(when: u64) -> u64 {
    match when {
        FOREVER => return FOREVER,
        NOW | MONOTONICTIME_NOW | WALLTIME_NOW => return 0,
        _ => {}
    }
    let (clock, value) = to_clock_and_value(when, false);
    value.saturating_sub(clock.now())
}

/// Nanoseconds from now until `deadline`, or `None` for a deadline that never
/// arrives. Zero for one already past.
pub fn remaining(deadline: u64) -> Option<u64> {
    match timeout(deadline) {
        FOREVER => None,
        left => Some(left),
    }
}

/// `deadline` as an uptime value, for a wait that only counts on uptime.
pub fn uptime_deadline(deadline: u64) -> u64 {
    match remaining(deadline) {
        None => FOREVER,
        Some(left) => now().saturating_add(left).min(MAX_VALUE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_is_absolute_and_forever_is_infectious() {
        let soon = unsafe { time(NOW, 50_000_000) };
        assert!(soon > now(), "a future deadline is ahead of the clock");
        assert_eq!(unsafe { time(FOREVER, 5) }, FOREVER);
        assert_eq!(remaining(FOREVER), None);
    }

    /// A negative delta larger than the base must not wrap into the distant future.
    #[test]
    fn a_deadline_saturates_rather_than_wrapping() {
        assert_eq!(unsafe { time(10, -100) }, 1);
        assert_eq!(unsafe { time(u64::MAX - 1, i64::MAX) }, u64::MAX);
    }

    #[test]
    fn a_past_deadline_has_no_time_left() {
        assert_eq!(remaining(1), Some(0));
    }

    /// Apple's three clocks: uptime as itself, continuous time with bit 63,
    /// and wall time negated, each with its own floor and ceiling.
    #[test]
    fn each_clock_keeps_its_own_encoding() {
        let wall = unsafe { time(WALLTIME_NOW, 0) };
        assert_eq!(to_clock_and_value(wall, false).0, Clock::Wall);
        assert!(wall & (3 << 62) == 3 << 62, "bits 63 and 62: {wall:#x}");
        let soon = unsafe { time(MONOTONICTIME_NOW, 1_000) };
        assert_eq!(soon & (3 << 62), 1 << 63);
        assert_eq!(to_clock_and_value(soon, false).0, Clock::Monotonic);
        assert_eq!(unsafe { time(MONOTONICTIME_NOW | 10, -100) }, (1 << 63) | 1);
        assert_eq!(unsafe { time(wall, i64::MAX) }, FOREVER);
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(unsafe { walltime(&ts, -5) }, (-2i64) as u64);
        assert_eq!(unsafe { walltime(&ts, 0) }, FOREVER);
        let later = unsafe { walltime(std::ptr::null(), 2_000_000_000) };
        let left = timeout(later);
        assert!(left > 1_000_000_000 && left <= 2_000_000_000, "{left}");
    }
}
