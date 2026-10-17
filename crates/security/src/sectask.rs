//! `SecTask`: a process, asked about its code signature.
//!
//! After Apple's `sectask/SecTask.c` (apple-oss-distributions/Security). A
//! task is an audit token, and every question about it goes to the kernel
//! through `csops_audittoken`, which here is `darwin::bsd`'s. What that answers
//! for an unsigned process - no flags, and `EINVAL` for its entitlements and
//! identity - is what this module turns into Apple's answers: no entitlements,
//! no identifier, a code-signing status of zero.

#![allow(non_snake_case)]

use std::ffi::c_void;

use corefoundation::base::{CFTypeID, CFTypeRef};
use darwin::bsd::cs_ops;
use darwin::mach::info::AuditToken;
use objc::class::Class;
use objc::object::Id;

/// `struct __SecTask`, past its CF header.
#[repr(C)]
struct Body {
    isa: *const Class,
    token: AuditToken,
    /// Whether [`load_entitlements`] has run, successfully.
    loaded: bool,
    /// The entitlements dictionary, retained, or null for none.
    entitlements: CFTypeRef,
}

fn class() -> &'static Class {
    static CLASS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let pointer = *CLASS.get_or_init(|| {
        let class = corefoundation::base::register(c"SecTask", None, size_of::<Body>(), true);
        class.replace_method(
            objc::sel::get("dealloc"),
            dealloc as *const c_void,
            c"v16@0:8",
        );
        objc::class::ptr(class) as usize
    });
    // SAFETY: a class registered above and kept for the process.
    unsafe { objc::class::from_ptr(pointer as *const Class).expect("a task class") }
}

unsafe extern "C" fn dealloc(receiver: Id, _sel: objc::sel::Sel) {
    // SAFETY: this class's layout, and the dictionary it owns.
    unsafe {
        let body = receiver as *mut Body;
        if !(*body).entitlements.is_null() {
            objc::arc::release((*body).entitlements as Id);
        }
        objc::arc::finalize(receiver);
    }
}

/// `check_task`: the task, if `task` is one.
///
/// # Safety
///
/// `task` is null or an object this runtime allocated.
unsafe fn body<'a>(task: CFTypeRef) -> Option<&'a mut Body> {
    // SAFETY: the caller's obligation.
    match unsafe { corefoundation::base::is_kind_of(task, class()) } {
        true => Some(unsafe { &mut *(task as *mut Body) }),
        false => None,
    }
}

fn create(token: AuditToken) -> CFTypeRef {
    // SAFETY: `Body` is the registered layout.
    let body = unsafe { corefoundation::base::allocate::<Body>(class()) };
    if body.is_null() {
        return std::ptr::null();
    }
    // SAFETY: a freshly allocated body.
    unsafe {
        (*body).token = token;
        (*body).loaded = false;
        (*body).entitlements = std::ptr::null();
    }
    body as CFTypeRef
}

/// `csops_task`: `csops_audittoken` for the task's process, as the errno it
/// fails with, or zero.
fn csops(task: &Body, ops: u32, buffer: *mut c_void, size: usize) -> i32 {
    let pid = task.token.val[5] as i32;
    // SAFETY: the caller's buffer of `size` bytes, and a token on our body.
    match unsafe { darwin::bsd::csops_audittoken(pid, ops, buffer, size, &task.token) } {
        0 => 0,
        _ => darwin::errno::get(),
    }
}

/// `*error = CFErrorCreate(NULL, kCFErrorDomainPOSIX, errno, NULL)`, if the
/// caller asked for one and none is there yet.
///
/// # Safety
///
/// `error` is null or a writable `CFErrorRef`.
unsafe fn fail(error: *mut CFTypeRef, errno: i32) {
    // SAFETY: the caller's obligation.
    if error.is_null() || !unsafe { *error }.is_null() {
        return;
    }
    let reason = std::io::Error::from_raw_os_error(errno).to_string();
    let darwin = darwin::errno::from_host(errno);
    let description = format!("The operation couldn\u{2019}t be completed. {reason}");
    let made = foundation::error::create("NSPOSIXErrorDomain", i64::from(darwin), &description, &[]);
    // SAFETY: the caller's obligation.
    unsafe { *error = made as CFTypeRef };
}

/// `SecTaskLoadEntitlements`.
///
/// Apple asks for the DER entitlements' header first, and reads the blob only
/// when the kernel says, with `ERANGE`, how long it is. `EINVAL` is the
/// kernel's answer for unsigned code, which has none, and that is a success.
///
/// # Safety
///
/// `error` as [`fail`].
unsafe fn load_entitlements(task: &mut Body, error: *mut CFTypeRef) -> bool {
    let mut header = [0u8; 8];
    let errno = csops(task, cs_ops::DER_ENTITLEMENTS_BLOB, header.as_mut_ptr().cast(), 8);
    let failure = match errno {
        libc::EINVAL => {
            task.loaded = true;
            return true;
        }
        // A blob of entitlements: this `csops` never hands one out, since
        // nothing here is signed, and decoding CoreEntitlements' DER is the
        // part of Apple's path with nothing to run on. `EDOM` is what Apple
        // reports for entitlements it could not decode.
        0 | libc::ERANGE => libc::EDOM,
        errno => errno,
    };
    // SAFETY: the caller's obligation.
    unsafe { fail(error, failure) };
    false
}

/// `CFTypeID SecTaskGetTypeID(void)`.
pub extern "C" fn SecTaskGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(class())
}

/// `SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef)`: this process, by the
/// audit token `task_info(TASK_AUDIT_TOKEN)` gives it.
pub extern "C" fn SecTaskCreateFromSelf(_allocator: CFTypeRef) -> CFTypeRef {
    create(darwin::mach::info::audit_token(starnix::process::me()))
}

/// `SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef, audit_token_t)`.
/// The token is not checked here; `csops_audittoken` checks it on each
/// question, as the kernel does.
pub extern "C" fn SecTaskCreateWithAuditToken(
    _allocator: CFTypeRef,
    token: AuditToken,
) -> CFTypeRef {
    create(token)
}

/// `CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef, CFStringRef,
/// CFErrorRef *)`: the entitlement's value, retained, or NULL.
///
/// # Safety
///
/// `task` is null or an object; `error` is null or writable.
pub unsafe extern "C" fn SecTaskCopyValueForEntitlement(
    task: CFTypeRef,
    entitlement: CFTypeRef,
    error: *mut CFTypeRef,
) -> CFTypeRef {
    // SAFETY: the caller's obligation.
    let Some(task) = (unsafe { body(task) }) else {
        return std::ptr::null();
    };
    // SAFETY: the caller's obligation.
    if !task.loaded && !unsafe { load_entitlements(task, error) } {
        return std::ptr::null();
    }
    if task.entitlements.is_null() {
        return std::ptr::null();
    }
    // SAFETY: a dictionary the task holds.
    let value =
        unsafe { corefoundation::api::CFDictionaryGetValue(task.entitlements, entitlement) };
    match value.is_null() {
        true => value,
        // Something the caller must release.
        false => unsafe { corefoundation::api::CFRetain(value) },
    }
}

/// `CFDictionaryRef SecTaskCopyValuesForEntitlements(SecTaskRef, CFArrayRef,
/// CFErrorRef *)`: those of the named entitlements the task has, which is an
/// empty dictionary when it has none; NULL if they could not be loaded.
///
/// # Safety
///
/// As [`SecTaskCopyValueForEntitlement`]; `entitlements` is an array.
pub unsafe extern "C" fn SecTaskCopyValuesForEntitlements(
    task: CFTypeRef,
    entitlements: CFTypeRef,
    error: *mut CFTypeRef,
) -> CFTypeRef {
    // SAFETY: the caller's obligation.
    let Some(task) = (unsafe { body(task) }) else {
        return std::ptr::null();
    };
    if !task.loaded {
        // SAFETY: the caller's obligation. Apple goes on either way, and
        // answers from whether the load took.
        unsafe { load_entitlements(task, error) };
    }
    if !task.loaded {
        return std::ptr::null();
    }
    let values = corefoundation::collections::new_dictionary(
        &[],
        corefoundation::callbacks::Policy::from_key_callbacks(),
        corefoundation::callbacks::Policy::from_type_callbacks(),
        true,
    );
    if task.entitlements.is_null() {
        return values;
    }
    // SAFETY: the caller's array, and the task's dictionary.
    unsafe {
        for i in 0..corefoundation::api::CFArrayGetCount(entitlements) {
            let name = corefoundation::api::CFArrayGetValueAtIndex(entitlements, i);
            let value = corefoundation::api::CFDictionaryGetValue(task.entitlements, name);
            if !value.is_null() {
                corefoundation::api::CFDictionarySetValue(values, name, value);
            }
        }
    }
    values
}

/// `SecTaskCopyIdentifier`: the signing identity or team ID out of the
/// blob `csops` hands back. Apple answers NULL - and leaves `error` alone -
/// whenever the header question fails any way but `ERANGE`, which is how an
/// unsigned process's `EINVAL` arrives here.
///
/// # Safety
///
/// `error` as [`fail`].
unsafe fn copy_identifier(task: &Body, op: u32, error: *mut CFTypeRef) -> CFTypeRef {
    let mut header = [0u8; 8];
    if csops(task, op, header.as_mut_ptr().cast(), header.len()) != libc::ERANGE {
        return std::ptr::null();
    }
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(8..=1024 * 1024).contains(&length) {
        // SAFETY: the caller's obligation.
        unsafe { fail(error, libc::EINVAL) };
        return std::ptr::null();
    }
    let mut data = vec![0u8; length];
    let errno = csops(task, op, data.as_mut_ptr().cast(), length);
    if errno != 0 {
        // SAFETY: the caller's obligation.
        unsafe { fail(error, errno) };
        return std::ptr::null();
    }
    let text = &data[8..];
    let text = &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())];
    corefoundation::string::from_bytes(text, false)
}

/// `CFStringRef SecTaskCopySigningIdentifier(SecTaskRef, CFErrorRef *)`.
///
/// # Safety
///
/// As [`SecTaskCopyValueForEntitlement`].
pub unsafe extern "C" fn SecTaskCopySigningIdentifier(
    task: CFTypeRef,
    error: *mut CFTypeRef,
) -> CFTypeRef {
    // SAFETY: the caller's obligation.
    match unsafe { body(task) } {
        Some(task) => unsafe { copy_identifier(task, cs_ops::IDENTITY, error) },
        None => std::ptr::null(),
    }
}

/// `CFStringRef SecTaskCopyTeamIdentifier(SecTaskRef, CFErrorRef *)`.
///
/// # Safety
///
/// As [`SecTaskCopyValueForEntitlement`].
pub unsafe extern "C" fn SecTaskCopyTeamIdentifier(
    task: CFTypeRef,
    error: *mut CFTypeRef,
) -> CFTypeRef {
    // SAFETY: the caller's obligation.
    match unsafe { body(task) } {
        Some(task) => unsafe { copy_identifier(task, cs_ops::TEAMID, error) },
        None => std::ptr::null(),
    }
}

/// `uint32_t SecTaskGetCodeSignStatus(SecTaskRef)`: the `CS_*` flags, or
/// zero if `csops` will not say.
///
/// # Safety
///
/// `task` is null or an object.
pub unsafe extern "C" fn SecTaskGetCodeSignStatus(task: CFTypeRef) -> u32 {
    // SAFETY: the caller's obligation.
    let Some(task) = (unsafe { body(task) }) else {
        return 0;
    };
    let mut flags = 0u32;
    match csops(task, cs_ops::STATUS, (&raw mut flags).cast(), size_of::<u32>()) {
        0 => flags,
        _ => 0,
    }
}

/// `Boolean SecTaskEntitlementsValidated(SecTaskRef)`: whether the kernel
/// validated the signature the entitlements came in - `CS_VALID`, `CS_KILL`
/// and `CS_ENTITLEMENTS_VALIDATED`, or a debugged process that was valid.
///
/// # Safety
///
/// `task` is null or an object.
pub unsafe extern "C" fn SecTaskEntitlementsValidated(task: CFTypeRef) -> u8 {
    const CS_VALID: u32 = 0x1;
    const CS_KILL: u32 = 0x200;
    const CS_ENTITLEMENTS_VALIDATED: u32 = 0x4000;
    const CS_DEBUGGED: u32 = 0x1000_0000;
    // SAFETY: the caller's obligation.
    let Some(task) = (unsafe { body(task) }) else {
        return 0;
    };
    let mut flags = 0u32;
    if csops(task, cs_ops::STATUS, (&raw mut flags).cast(), size_of::<u32>()) != 0 {
        return 0;
    }
    let mask = CS_VALID | CS_KILL | CS_ENTITLEMENTS_VALIDATED;
    let debug_mask = CS_DEBUGGED | CS_ENTITLEMENTS_VALIDATED;
    u8::from(flags & mask == mask || flags & debug_mask == debug_mask)
}

exports::exports! {
    functions {
        "SecTaskGetTypeID" => SecTaskGetTypeID,
        "SecTaskCreateFromSelf" => SecTaskCreateFromSelf,
        "SecTaskCreateWithAuditToken" => SecTaskCreateWithAuditToken,
        "SecTaskCopyValueForEntitlement" => SecTaskCopyValueForEntitlement,
        "SecTaskCopyValuesForEntitlements" => SecTaskCopyValuesForEntitlements,
        "SecTaskCopySigningIdentifier" => SecTaskCopySigningIdentifier,
        "SecTaskCopyTeamIdentifier" => SecTaskCopyTeamIdentifier,
        "SecTaskGetCodeSignStatus" => SecTaskGetCodeSignStatus,
        "SecTaskEntitlementsValidated" => SecTaskEntitlementsValidated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This process, which is unsigned: no entitlements and no error, an empty
    /// dictionary for a list of them, no identifier, and a status of zero.
    #[test]
    fn an_unsigned_process_has_no_entitlements_and_no_error() {
        foundation::bootstrap();
        let task = SecTaskCreateFromSelf(std::ptr::null());
        assert!(!task.is_null());
        // SAFETY: a task this test made, a string, and writable error slots.
        unsafe {
            assert_eq!(corefoundation::api::CFGetTypeID(task), SecTaskGetTypeID());
            let name = corefoundation::string::from_bytes(b"com.apple.security.app-sandbox", false);
            let mut error = std::ptr::null();
            let value = SecTaskCopyValueForEntitlement(task, name, &mut error);
            assert!(value.is_null() && error.is_null());

            let names = corefoundation::collections::new_array(
                &[name],
                corefoundation::callbacks::Policy::from_type_callbacks(),
                false,
            );
            let values = SecTaskCopyValuesForEntitlements(task, names, &mut error);
            assert!(!values.is_null() && error.is_null());
            assert_eq!(corefoundation::api::CFDictionaryGetCount(values), 0);

            assert!(SecTaskCopySigningIdentifier(task, &mut error).is_null());
            assert!(SecTaskCopyTeamIdentifier(task, &mut error).is_null());
            assert!(error.is_null());
            assert_eq!(SecTaskGetCodeSignStatus(task), 0);
            assert_eq!(SecTaskEntitlementsValidated(task), 0);

            for object in [values, names, name, task] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// A token that names another process is refused by `csops_audittoken`,
    /// and the refusal comes back as a POSIX error.
    #[test]
    fn a_token_for_another_process_fails_with_an_error() {
        foundation::bootstrap();
        let mut token = darwin::mach::info::audit_token(starnix::process::me());
        token.val[7] = 1;
        let task = SecTaskCreateWithAuditToken(std::ptr::null(), token);
        // SAFETY: a task this test made, a string, and a writable error slot.
        unsafe {
            let name = corefoundation::string::from_bytes(b"com.apple.security.cs.allow-jit", false);
            let mut error = std::ptr::null();
            assert!(SecTaskCopyValueForEntitlement(task, name, &mut error).is_null());
            assert!(!error.is_null(), "ESRCH comes back as an error");
            for object in [error, name, task] {
                corefoundation::api::CFRelease(object);
            }
        }
    }
}
