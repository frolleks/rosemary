#[repr(i32)]
enum CGWindowLevelKey {
    _BaseWindow = 0,
}

type CGWindowLevel = i32;

// FIXME: Window levels are not implemented; every key returns zero.
#[allow(non_snake_case)]
extern "C" fn CGWindowLevelForKey(_key: CGWindowLevelKey) -> CGWindowLevel {
    0
}

/// `Boolean AXIsProcessTrusted(void)`: whether the user has let this process
/// control the computer through accessibility. Nothing here grants that.
#[allow(non_snake_case)]
extern "C" fn AXIsProcessTrusted() -> u8 {
    0
}

/// `Boolean AXIsProcessTrustedWithOptions(CFDictionaryRef)`: the same answer.
/// `kAXTrustedCheckOptionPrompt` asks for the dialog that sends the user to
/// System Settings, and there is no such pane here to send them to.
#[allow(non_snake_case)]
extern "C" fn AXIsProcessTrustedWithOptions(_options: *const std::ffi::c_void) -> u8 {
    0
}

/// The `CFStringRef` globals this framework defines.
const STRING_GLOBALS: &[(&str, &str)] = &[(
    "_kAXTrustedCheckOptionPrompt",
    "AXTrustedCheckOptionPrompt",
)];

pub fn data_symbols() -> Vec<(String, u64)> {
    corefoundation::base::string_globals(STRING_GLOBALS)
}

exports::exports! {
    functions {
        "CGWindowLevelForKey" => CGWindowLevelForKey,
        "AXIsProcessTrusted" => AXIsProcessTrusted,
        "AXIsProcessTrustedWithOptions" => AXIsProcessTrustedWithOptions,
    }
}
