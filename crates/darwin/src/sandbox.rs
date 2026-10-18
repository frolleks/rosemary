//! libsandbox: `sandbox_init` and the calls around it - `<sandbox.h>`, and the
//! private ones a sandboxed program's own process uses (Chromium's
//! `sandbox/mac/seatbelt.cc` declares them, WebKit's `SandboxSPI.h` too).
//!
//! A Seatbelt profile is a policy the kernel's Sandbox MAC module enforces.
//! There is no such module here, so a profile is accepted and not enforced:
//! the process goes on with the access it had, and is told once. What a
//! process may ask about its own sandbox is answered as on a Mac after the
//! profile was applied: `sandbox_check(getpid(), NULL, SANDBOX_FILTER_NONE)`
//! - "am I sandboxed?" - is 1 from then on, and an operation check is 0,
//! "allowed", which is what this host will do with it.
//!
//! Extensions are the tokens a sandboxed process is given to reach a path its
//! profile does not cover. With no profile in force there is nothing for one
//! to widen, so a token is issued for any path that exists and consuming one
//! hands back a handle, as on a Mac for a process the token is valid in.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Whether this process has applied a profile.
static SANDBOXED: AtomicBool = AtomicBool::new(false);

/// `SANDBOX_NAMED`: `profile` is the name of a built-in profile.
const SANDBOX_NAMED: u64 = 0x0001;

/// The built-in profiles `<sandbox.h>` names: `kSBXProfileNoInternet` and
/// the rest.
const NAMED_PROFILES: &[&CStr] = &[
    c"no-internet",
    c"no-network",
    c"no-write",
    c"no-write-except-temporary",
    c"pure-computation",
];

/// `kSBXProfileNoInternet` and its siblings, which `<sandbox.h>` declares as
/// `extern const char[]`.
#[repr(transparent)]
pub struct Name([c_char; 32]);

const fn name(text: &CStr) -> Name {
    let bytes = text.to_bytes_with_nul();
    let mut out = [0 as c_char; 32];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i] as c_char;
        i += 1;
    }
    Name(out)
}

static K_SBX_PROFILE_NO_INTERNET: Name = name(c"no-internet");
static K_SBX_PROFILE_NO_NETWORK: Name = name(c"no-network");
static K_SBX_PROFILE_NO_WRITE: Name = name(c"no-write");
static K_SBX_PROFILE_NO_WRITE_EXCEPT_TEMPORARY: Name = name(c"no-write-except-temporary");
static K_SBX_PROFILE_PURE_COMPUTATION: Name = name(c"pure-computation");

/// A `const char *const`, the type of `APP_SANDBOX_READ`.
#[repr(transparent)]
pub struct Text(*const c_char);

// SAFETY: a pointer to a string literal, never written.
unsafe impl Sync for Text {}

/// The extension classes a token is issued under.
static APP_SANDBOX_READ: Text = Text(c"com.apple.app-sandbox.read".as_ptr());
static APP_SANDBOX_READ_WRITE: Text = Text(c"com.apple.app-sandbox.read-write".as_ptr());

/// What the guest's `free` takes back.
fn guest_alloc(size: usize) -> *mut c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: plain allocation; a guest's `free` is the host's here.
    return unsafe { libc::malloc(size) };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: plain allocation from the guest's own heap.
    return unsafe { crate::malloc::malloc(size) };
}

fn guest_free(ptr: *mut c_void) {
    #[cfg(target_os = "macos")]
    // SAFETY: memory `guest_alloc` gave, or null.
    unsafe {
        libc::free(ptr)
    };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: memory `guest_alloc` gave, or null.
    unsafe {
        crate::malloc::free(ptr)
    };
}

/// `text` as a NUL-terminated string the guest frees.
fn guest_string(text: &str) -> *mut c_char {
    let out = guest_alloc(text.len() + 1).cast::<u8>();
    if !out.is_null() {
        // SAFETY: `text.len() + 1` bytes just allocated.
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), out, text.len());
            *out.add(text.len()) = 0;
        }
    }
    out.cast()
}

/// Write `message` to `*errorbuf`, if the caller asked for one.
///
/// # Safety
///
/// `errorbuf` is null or writable.
unsafe fn fail(errorbuf: *mut *mut c_char, message: &str) -> c_int {
    if !errorbuf.is_null() {
        // SAFETY: the caller's obligation.
        unsafe { *errorbuf = guest_string(message) };
    }
    -1
}

/// Apply a profile: record it, and say once what that means here.
fn apply() {
    if !SANDBOXED.swap(true, Ordering::SeqCst) {
        eprintln!(
            "rosemary: sandbox profile accepted but not enforced - there is no Sandbox policy \
             module here, so this process keeps the access it had"
        );
    }
}

/// `int sandbox_init(const char *profile, uint64_t flags, char **errorbuf)`
///
/// A named profile must be one of the five `<sandbox.h>` names; any other
/// profile is Scheme source, accepted as written.
///
/// # Safety
///
/// `profile` is a string, and `errorbuf` is null or writable.
unsafe extern "C" fn sandbox_init(
    profile: *const c_char,
    flags: u64,
    errorbuf: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller's obligation.
    unsafe { init(profile, flags, errorbuf) }
}

/// [`sandbox_init`] and [`sandbox_init_with_parameters`].
///
/// # Safety
///
/// As [`sandbox_init`].
unsafe fn init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int {
    if profile.is_null() {
        crate::errno::set(libc::EINVAL);
        // SAFETY: the caller's obligation.
        return unsafe { fail(errorbuf, "no profile") };
    }
    // SAFETY: the caller's obligation.
    let profile = unsafe { CStr::from_ptr(profile) };
    if flags & SANDBOX_NAMED != 0 && !NAMED_PROFILES.contains(&profile) {
        crate::errno::set(libc::EINVAL);
        let message = format!("unknown profile: {}", profile.to_string_lossy());
        // SAFETY: the caller's obligation.
        return unsafe { fail(errorbuf, &message) };
    }
    apply();
    0
}

/// `int sandbox_init_with_parameters(const char *profile, uint64_t flags,
/// const char *const parameters[], char **errorbuf)`: [`sandbox_init`] with
/// the profile's `(param "KEY")` values, a NULL-terminated list of keys and
/// values.
///
/// # Safety
///
/// As [`sandbox_init`]; `parameters` is null or NULL-terminated.
unsafe extern "C" fn sandbox_init_with_parameters(
    profile: *const c_char,
    flags: u64,
    _parameters: *const *const c_char,
    errorbuf: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller's obligation.
    unsafe { init(profile, flags, errorbuf) }
}

/// `void sandbox_free_error(char *errorbuf)`
///
/// # Safety
///
/// `errorbuf` is null or one this module wrote.
unsafe extern "C" fn sandbox_free_error(errorbuf: *mut c_char) {
    guest_free(errorbuf.cast());
}

/// `int sandbox_check(pid_t pid, const char *operation, enum
/// sandbox_filter_type type, ...)`: 0 when allowed, 1 when denied.
///
/// With no operation it asks whether `pid` is sandboxed: this process is
/// once it has applied a profile, and another process is not known to be.
/// An operation is allowed, as nothing denies one here.
///
/// # Safety
///
/// `operation` is null or a string.
unsafe extern "C" fn sandbox_check(pid: c_int, operation: *const c_char, _type: c_int) -> c_int {
    if operation.is_null() {
        // SAFETY: `getpid` cannot fail.
        let me = unsafe { libc::getpid() };
        return c_int::from(pid == me && SANDBOXED.load(Ordering::SeqCst));
    }
    0
}

/// `struct sandbox_params_t`, as Chromium declares it: a growable array of
/// alternating keys and values.
#[repr(C)]
pub struct Params {
    params: *mut *const c_char,
    size: usize,
    available: usize,
}

/// `sandbox_params_t *sandbox_create_params(void)`
extern "C" fn sandbox_create_params() -> *mut Params {
    Box::into_raw(Box::new(Params {
        params: std::ptr::null_mut(),
        size: 0,
        available: 0,
    }))
}

/// `int sandbox_set_param(sandbox_params_t *, const char *key, const char
/// *value)`: append a copy of the pair.
///
/// # Safety
///
/// `params` is one [`sandbox_create_params`] made, and `key` and `value` are
/// strings.
unsafe extern "C" fn sandbox_set_param(
    params: *mut Params,
    key: *const c_char,
    value: *const c_char,
) -> c_int {
    if params.is_null() || key.is_null() || value.is_null() {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    // SAFETY: the caller's obligations.
    let (params, key, value) =
        unsafe { (&mut *params, CStr::from_ptr(key), CStr::from_ptr(value)) };
    let mut list: Vec<*const c_char> = match params.params.is_null() {
        true => Vec::new(),
        // SAFETY: a list this module built, `size` long and `available` wide.
        false => unsafe { Vec::from_raw_parts(params.params, params.size, params.available) },
    };
    list.push(key.to_owned().into_raw());
    list.push(value.to_owned().into_raw());
    let mut list = std::mem::ManuallyDrop::new(list);
    params.params = list.as_mut_ptr();
    params.size = list.len();
    params.available = list.capacity();
    0
}

/// `void sandbox_free_params(sandbox_params_t *)`
///
/// # Safety
///
/// `params` is null or one [`sandbox_create_params`] made.
unsafe extern "C" fn sandbox_free_params(params: *mut Params) {
    if params.is_null() {
        return;
    }
    // SAFETY: the caller's obligation.
    let params = unsafe { Box::from_raw(params) };
    if !params.params.is_null() {
        // SAFETY: as in `sandbox_set_param`.
        let list = unsafe { Vec::from_raw_parts(params.params, params.size, params.available) };
        for entry in list {
            // SAFETY: each made by `CString::into_raw`.
            drop(unsafe { std::ffi::CString::from_raw(entry.cast_mut()) });
        }
    }
}

/// `struct sandbox_profile_t`: a compiled profile.
#[repr(C)]
pub struct Profile {
    builtin: *mut c_char,
    data: *const u8,
    size: usize,
}

/// `sandbox_profile_t *sandbox_compile_string(const char *data,
/// sandbox_params_t *, char **error)`
///
/// The compiled form is opaque to its caller, which hands it to
/// [`sandbox_apply`], perhaps in another process. Nothing here evaluates it,
/// so it is the source itself.
///
/// # Safety
///
/// `data` is a string, and `error` is null or writable.
unsafe extern "C" fn sandbox_compile_string(
    data: *const c_char,
    _params: *mut Params,
    error: *mut *mut c_char,
) -> *mut Profile {
    if data.is_null() {
        // SAFETY: the caller's obligation.
        unsafe { fail(error, "no profile") };
        return std::ptr::null_mut();
    }
    // SAFETY: the caller's obligation.
    let source = unsafe { CStr::from_ptr(data) }
        .to_bytes()
        .to_vec()
        .into_boxed_slice();
    let size = source.len();
    Box::into_raw(Box::new(Profile {
        builtin: std::ptr::null_mut(),
        data: Box::into_raw(source).cast::<u8>(),
        size,
    }))
}

/// `int sandbox_apply(sandbox_profile_t *)`
///
/// # Safety
///
/// `profile` is null or a profile.
unsafe extern "C" fn sandbox_apply(profile: *mut Profile) -> c_int {
    if profile.is_null() {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    apply();
    0
}

/// `void sandbox_free_profile(sandbox_profile_t *)`
///
/// # Safety
///
/// `profile` is null or one [`sandbox_compile_string`] made.
unsafe extern "C" fn sandbox_free_profile(profile: *mut Profile) {
    if profile.is_null() {
        return;
    }
    // SAFETY: the caller's obligation.
    let profile = unsafe { Box::from_raw(profile) };
    if !profile.data.is_null() {
        // SAFETY: the slice `sandbox_compile_string` leaked.
        drop(unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                profile.data.cast_mut(),
                profile.size,
            ))
        });
    }
}

/// The last handle [`sandbox_extension_consume`] gave out.
static HANDLES: AtomicI64 = AtomicI64::new(0);

/// The prefix of a token this module issued.
const TOKEN: &str = "rosemary-sandbox-extension";

/// `char *sandbox_extension_issue_file(const char *extension_class, const
/// char *path, uint32_t flags)`: a token another process consumes to reach
/// `path`, or NULL with `errno`.
///
/// The token is opaque to everything but [`sandbox_extension_consume`]: the
/// class, then the path in hex, so that no byte of it can end the token.
///
/// # Safety
///
/// `extension_class` and `path` are strings.
unsafe extern "C" fn sandbox_extension_issue_file(
    extension_class: *const c_char,
    path: *const c_char,
    _flags: u32,
) -> *mut c_char {
    if extension_class.is_null() || path.is_null() {
        crate::errno::set(libc::EINVAL);
        return std::ptr::null_mut();
    }
    // SAFETY: the caller's obligation.
    let (class, path) = unsafe { (CStr::from_ptr(extension_class), CStr::from_ptr(path)) };
    let host = prefix::ns::to_host(path);
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::access(host.as_ptr(), libc::F_OK) } != 0 {
        return std::ptr::null_mut();
    }
    let hex: String = path.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    guest_string(&format!("{TOKEN};{};{hex}", class.to_string_lossy()))
}

/// `int64_t sandbox_extension_consume(const char *extension_token)`: a handle
/// for [`sandbox_extension_release`], or -1 with `errno` for a token that is
/// not one.
///
/// # Safety
///
/// `extension_token` is a string.
unsafe extern "C" fn sandbox_extension_consume(extension_token: *const c_char) -> i64 {
    if extension_token.is_null() {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    // SAFETY: the caller's obligation.
    let token = unsafe { CStr::from_ptr(extension_token) }.to_string_lossy();
    if !token.starts_with(TOKEN) || token.split(';').count() != 3 {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    HANDLES.fetch_add(1, Ordering::Relaxed) + 1
}

/// `int sandbox_extension_release(int64_t extension_handle)`
extern "C" fn sandbox_extension_release(extension_handle: i64) -> c_int {
    if extension_handle <= 0 {
        crate::errno::set(libc::EINVAL);
        return -1;
    }
    0
}

/// Darwin's `ENOPOLICY`, "No such policy registered", which this host has no
/// number for.
const ENOPOLICY: i32 = 103;

/// Darwin's `EFAULT`.
const EFAULT: i32 = 14;

/// AMFI's status query: the flags its boot arguments set
/// (`amfi_unrestrict_task_for_pid`, `amfi_allow_any_signature`,
/// `amfi_get_out_of_my_way`), as a `uint64_t` - Chromium's
/// `content/common/mac/task_port_policy.cc` reads it.
const AMFI_STATUS: c_int = 0x60;

/// `int __mac_syscall(const char *policy, int call, void *arg)` - and
/// `__sandbox_ms`, libsystem_kernel's other name for the same trap: a call
/// into the MAC policy module named `policy`.
///
/// XNU's `__mac_syscall` (`security/mac_base.c`) hands the call to the
/// registered policy of that name and answers `ENOPOLICY` when there is none.
/// No policy module runs here, so that is the answer - but for AMFI's status
/// query, whose answer is known: none of its boot arguments is set, as on any
/// Mac booted normally. AMFI's other calls are refused as ones it does not
/// take, rather than claimed.
extern "C" fn mac_syscall(policy: *const c_char, call: c_int, arg: *mut c_void) -> c_int {
    if policy.is_null() {
        crate::errno::set_guest(EFAULT);
        return -1;
    }
    // SAFETY: a NUL-terminated policy name, by the call's contract.
    let name = unsafe { CStr::from_ptr(policy) };
    match (name.to_bytes(), call) {
        (b"AMFI", AMFI_STATUS) => {
            if arg.is_null() {
                crate::errno::set_guest(EFAULT);
                return -1;
            }
            // SAFETY: the caller's `uint64_t`.
            unsafe { arg.cast::<u64>().write_unaligned(0) };
            0
        }
        (b"AMFI", _) => {
            crate::errno::set(libc::EINVAL);
            -1
        }
        _ => {
            crate::errno::set_guest(ENOPOLICY);
            -1
        }
    }
}

exports::exports! {
    functions {
        "__mac_syscall" | "__sandbox_ms" => mac_syscall,
        "sandbox_init" => sandbox_init,
        "sandbox_init_with_parameters" => sandbox_init_with_parameters,
        "sandbox_free_error" => sandbox_free_error,
        "sandbox_check" => sandbox_check,
        "sandbox_create_params" => sandbox_create_params,
        "sandbox_set_param" => sandbox_set_param,
        "sandbox_free_params" => sandbox_free_params,
        "sandbox_compile_string" => sandbox_compile_string,
        "sandbox_apply" => sandbox_apply,
        "sandbox_free_profile" => sandbox_free_profile,
        "sandbox_extension_issue_file" => sandbox_extension_issue_file,
        "sandbox_extension_consume" => sandbox_extension_consume,
        "sandbox_extension_release" => sandbox_extension_release,
    }
    constants {
        "APP_SANDBOX_READ" => &raw const APP_SANDBOX_READ as u64,
        "APP_SANDBOX_READ_WRITE" => &raw const APP_SANDBOX_READ_WRITE as u64,
        "kSBXProfileNoInternet" => &raw const K_SBX_PROFILE_NO_INTERNET as u64,
        "kSBXProfileNoNetwork" => &raw const K_SBX_PROFILE_NO_NETWORK as u64,
        "kSBXProfileNoWrite" => &raw const K_SBX_PROFILE_NO_WRITE as u64,
        "kSBXProfileNoWriteExceptTemporary" => &raw const K_SBX_PROFILE_NO_WRITE_EXCEPT_TEMPORARY as u64,
        "kSBXProfilePureComputation" => &raw const K_SBX_PROFILE_PURE_COMPUTATION as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AMFI's status is "no boot argument set"; any other policy is not
    /// registered.
    #[test]
    fn a_policy_syscall_reaches_only_what_is_here() {
        let mut status = u64::MAX;
        assert_eq!(
            mac_syscall(c"AMFI".as_ptr(), AMFI_STATUS, (&raw mut status).cast()),
            0
        );
        assert_eq!(status, 0);
        assert_eq!(
            mac_syscall(c"AMFI".as_ptr(), 0x5a, std::ptr::null_mut()),
            -1
        );
        assert_eq!(
            mac_syscall(c"Quarantine".as_ptr(), 0, std::ptr::null_mut()),
            -1
        );
        assert_eq!(crate::errno::guest_errno(), ENOPOLICY);
    }

    /// Before a profile, the process is not sandboxed; after one it is, and an
    /// operation is still allowed. A named profile has to be a real name.
    #[test]
    fn a_profile_once_applied_is_what_sandbox_check_reports() {
        // SAFETY: `getpid` cannot fail.
        let me = unsafe { libc::getpid() };
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: a string, and a writable error.
        assert_eq!(
            unsafe { sandbox_init(c"no-such-profile".as_ptr(), SANDBOX_NAMED, &mut error) },
            -1
        );
        assert!(!error.is_null());
        // SAFETY: the error just written.
        assert!(
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .contains("no-such-profile")
        );
        // SAFETY: as above.
        unsafe { sandbox_free_error(error) };
        // SAFETY: no operation.
        assert_eq!(
            unsafe { sandbox_check(me, std::ptr::null(), 0) },
            0,
            "nothing applied yet"
        );

        let params = [
            c"USER_HOMEDIR_AS_LITERAL".as_ptr(),
            c"/Users/x".as_ptr(),
            std::ptr::null(),
        ];
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: a string, a terminated list, and a writable error.
        let rv = unsafe {
            sandbox_init_with_parameters(
                c"(version 1)(deny default)".as_ptr(),
                0,
                params.as_ptr(),
                &mut error,
            )
        };
        assert_eq!((rv, error.is_null()), (0, true));
        // SAFETY: no operation, and then a string.
        unsafe {
            assert_eq!(sandbox_check(me, std::ptr::null(), 0), 1);
            assert_eq!(sandbox_check(me, c"file-read-data".as_ptr(), 1), 0);
            assert_eq!(sandbox_check(me + 1, std::ptr::null(), 0), 0);
        }
    }

    /// A compiled profile carries its source, and parameters accumulate.
    #[test]
    fn profiles_compile_and_parameters_accumulate() {
        let params = sandbox_create_params();
        // SAFETY: the params just made, and strings.
        unsafe {
            assert_eq!(sandbox_set_param(params, c"A".as_ptr(), c"1".as_ptr()), 0);
            assert_eq!(sandbox_set_param(params, c"B".as_ptr(), c"2".as_ptr()), 0);
            assert_eq!((*params).size, 4);
            assert_eq!(CStr::from_ptr(*(*params).params.add(3)), c"2");
        }
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: a string, the params, a writable error.
        let profile =
            unsafe { sandbox_compile_string(c"(version 1)".as_ptr(), params, &mut error) };
        assert!(!profile.is_null() && error.is_null());
        // SAFETY: the profile just made.
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts((*profile).data, (*profile).size),
                b"(version 1)"
            );
            // Not applied: the other test asks what this process is before
            // it applies one, and they share the process.
            assert_eq!(sandbox_apply(std::ptr::null_mut()), -1);
            sandbox_free_profile(profile);
            sandbox_free_params(params);
        }
    }

    /// A token for a path that exists is consumed into a handle; anything else
    /// is refused.
    #[test]
    fn an_extension_for_a_path_can_be_consumed_and_released() {
        // SAFETY: two strings.
        let token = unsafe { sandbox_extension_issue_file(APP_SANDBOX_READ.0, c"/".as_ptr(), 0) };
        assert!(!token.is_null());
        // SAFETY: the token just issued.
        let handle = unsafe { sandbox_extension_consume(token) };
        assert!(handle > 0);
        assert_eq!(sandbox_extension_release(handle), 0);
        guest_free(token.cast());
        // SAFETY: a string.
        assert_eq!(
            unsafe { sandbox_extension_consume(c"garbage".as_ptr()) },
            -1
        );
        // SAFETY: two strings.
        let none = unsafe {
            sandbox_extension_issue_file(APP_SANDBOX_READ.0, c"/no/such/path/at/all".as_ptr(), 0)
        };
        assert!(none.is_null());
    }
}
