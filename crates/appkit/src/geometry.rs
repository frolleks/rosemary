#![allow(non_snake_case)]

/// `void NSDisableScreenUpdates(void)` and `NSEnableScreenUpdates`: they hold
/// back the window server's flushes so several windows change at once. Each
/// window here presents on its own, so there is nothing to hold back.
pub extern "C" fn NSDisableScreenUpdates() {}

pub extern "C" fn NSEnableScreenUpdates() {}
