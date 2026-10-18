use core::ffi::{c_int, c_void};

use crate::signal::{Code, Context};

pub const SIGEMT: Option<c_int> = None;
pub const SIGINFO: Option<c_int> = None;

pub fn code(_signo: c_int, _code: c_int) -> Code {
    Code::Unknown
}

pub unsafe fn context(_: *const c_void) -> Option<Context> {
    None
}

pub unsafe fn set_context(_: *mut c_void, _: &Context) {}

/// Only the program counter. A whole context is cheap enough here.
///
/// # Safety
///
/// As [`context`].
pub unsafe fn pc(raw: *const c_void) -> Option<u64> {
    // SAFETY: the caller's guarantee.
    unsafe { context(raw) }.map(|c| c.machine.pc())
}

pub fn private_signal(_index: u8) -> Option<c_int> {
    None
}

pub fn send_to_thread(_tid: i32, _signo: c_int) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
