#![allow(non_snake_case)]

use corefoundation::base::CFTypeRef;
use corefoundation::callbacks::Policy;
use corefoundation::collections;

/// `CFTypeRef IOPSCopyPowerSourcesInfo(void)` - a `Copy`, so the caller
/// releases it.
pub unsafe extern "C" fn IOPSCopyPowerSourcesInfo() -> CFTypeRef {
    collections::new_dictionary(
        &[],
        Policy::from_key_callbacks(),
        Policy::from_type_callbacks(),
        false,
    )
}

/// `CFArrayRef IOPSCopyPowerSourcesList(CFTypeRef blob)`.
///
/// Empty, and owned by the caller. The blob is not consulted: this
/// implementation puts nothing in it.
pub unsafe extern "C" fn IOPSCopyPowerSourcesList(_blob: CFTypeRef) -> CFTypeRef {
    collections::new_array(&[], Policy::from_type_callbacks(), false)
}

/// `CFDictionaryRef IOPSGetPowerSourceDescription(CFTypeRef blob, CFTypeRef ps)`.
///
/// Null, which is the answer for a source that is not in the list - and the
/// list is empty, so no caller can hold one that is. A `Get`, so nothing is
/// owned either way.
pub unsafe extern "C" fn IOPSGetPowerSourceDescription(
    _blob: CFTypeRef,
    _source: CFTypeRef,
) -> CFTypeRef {
    std::ptr::null_mut()
}

/// `CFDictionaryRef IOPSCopyExternalPowerAdapterDetails(void)`.
///
/// Null, which is what a Mac with no adapter attached answers: wattage and
/// identity are an SMC's to report, and the host exposes none, so naming an
/// adapter would be inventing one. A `Copy`, so nothing is owned either way.
pub unsafe extern "C" fn IOPSCopyExternalPowerAdapterDetails() -> CFTypeRef {
    std::ptr::null_mut()
}

/// `CFRunLoopSourceRef IOPSNotificationCreateRunLoopSource(callback, context)`.
///
/// Null: nothing here changes power state, so a source would be one that never
/// fires. The callback is deliberately not retained - a program that gets null
/// knows it is not registered, where one holding a source that never fires
/// waits for a notification that cannot arrive.
pub unsafe extern "C" fn IOPSNotificationCreateRunLoopSource(
    _callback: *const std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> CFTypeRef {
    std::ptr::null_mut()
}

/// Where the assertion ids come from. Zero is `kIOPMNullAssertionID`.
static NEXT_ASSERTION: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// `IOReturn IOPMAssertionCreateWithDescription(type, name, details, reason,
/// bundle, timeout, timeoutAction, IOPMAssertionID *)`.
///
/// Granted and not enforced: a guest asks to keep the display awake while it runs,
/// and a refusal would only make it report an error for something this host's
/// idle policy does not let it do anything about. Each id is distinct, so a
/// release names what it created.
pub unsafe extern "C" fn IOPMAssertionCreateWithDescription(
    _kind: CFTypeRef,
    _name: CFTypeRef,
    _details: CFTypeRef,
    _reason: CFTypeRef,
    _bundle: CFTypeRef,
    _timeout: f64,
    _timeout_action: CFTypeRef,
    assertion: *mut u32,
) -> i32 {
    if !assertion.is_null() {
        let id = NEXT_ASSERTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: an out parameter the caller sized.
        unsafe { assertion.write(id) };
    }
    0
}

/// `IOReturn IOPMAssertionRelease(IOPMAssertionID)`.
pub unsafe extern "C" fn IOPMAssertionRelease(_assertion: u32) -> i32 {
    0
}

/// `IOReturn IOPMAssertionCreateWithName(CFStringRef type, IOPMAssertionLevel,
/// CFStringRef name, IOPMAssertionID *)`: the older spelling of the call
/// above, granted the same way.
pub unsafe extern "C" fn IOPMAssertionCreateWithName(
    _kind: CFTypeRef,
    _level: u32,
    _name: CFTypeRef,
    assertion: *mut u32,
) -> i32 {
    if assertion.is_null() {
        return BAD_ARGUMENT;
    }
    let id = NEXT_ASSERTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: an out parameter the caller sized.
    unsafe { assertion.write(id) };
    0
}

/// `kIOReturnBadArgument` and `kIOReturnNotFound`.
const BAD_ARGUMENT: i32 = 0xe000_02c2u32 as i32;
const NOT_FOUND: i32 = 0xe000_02f0u32 as i32;

/// `IOReturn IOPMCopyCPUPowerStatus(CFDictionaryRef *cpuPowerStatus)`.
///
/// `IOPMPowerNotifications.c` reads `State:/IOKit/Power/CPUPower` from the
/// SCDynamicStore, where `powerd` publishes the processor speed and count
/// limits a thermal event imposes, and answers `kIOReturnNotFound` when nothing
/// has been published - which, with no `powerd` here, is always.
pub unsafe extern "C" fn IOPMCopyCPUPowerStatus(status: *mut CFTypeRef) -> i32 {
    if status.is_null() {
        return BAD_ARGUMENT;
    }
    // SAFETY: the caller's out-parameter.
    unsafe { status.write(std::ptr::null()) };
    NOT_FOUND
}

/// `IOReturn IOPMGetThermalWarningLevel(uint32_t *thermalLevel)`.
///
/// The same store, the `ThermalWarning` key, and the same answer.
pub unsafe extern "C" fn IOPMGetThermalWarningLevel(level: *mut u32) -> i32 {
    if level.is_null() {
        return BAD_ARGUMENT;
    }
    NOT_FOUND
}

exports::exports! {
    functions {
        "IOPMAssertionCreateWithName" => IOPMAssertionCreateWithName,
        "IOPMCopyCPUPowerStatus" => IOPMCopyCPUPowerStatus,
        "IOPMGetThermalWarningLevel" => IOPMGetThermalWarningLevel,
        "IOPMAssertionCreateWithDescription" => IOPMAssertionCreateWithDescription,
        "IOPMAssertionRelease" => IOPMAssertionRelease,
        "IOPSCopyPowerSourcesInfo" => IOPSCopyPowerSourcesInfo,
        "IOPSCopyPowerSourcesList" => IOPSCopyPowerSourcesList,
        "IOPSGetPowerSourceDescription" => IOPSGetPowerSourceDescription,
        "IOPSCopyExternalPowerAdapterDetails" => IOPSCopyExternalPowerAdapterDetails,
        "IOPSNotificationCreateRunLoopSource" => IOPSNotificationCreateRunLoopSource,
    }
}
