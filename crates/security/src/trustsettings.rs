//! `SecTrustSettings`: which certificates each trust domain has settings for.
//!
//! Apple keeps three domains (Security, `SecTrustSettings.cpp`): the user's and
//! the administrator's, which hold whatever a user or an administrator chose to
//! trust or distrust, and the system's, which lists the system roots. A fresh
//! Mac has nothing in the first two - "a fairly common case", as Apple's own
//! comment calls it - and that is the state here: no user or administrator has
//! ever changed a setting in this prefix. The system domain is the anchors the
//! rest of this crate trusts.

#![allow(non_snake_case)]

use corefoundation::base::CFTypeRef;

type OSStatus = i32;
const SUCCESS: OSStatus = 0;
/// `errSecParam`.
const PARAM: OSStatus = -50;
/// `errSecItemNotFound`: "documented result if no trust settings exist".
const ITEM_NOT_FOUND: OSStatus = -25300;
/// `errSecNoTrustSettings`.
const NO_TRUST_SETTINGS: OSStatus = -25263;

/// `SecTrustSettingsDomain`.
mod domain {
    pub const USER: u32 = 0;
    pub const ADMIN: u32 = 1;
    pub const SYSTEM: u32 = 2;
}

/// `OSStatus SecTrustSettingsCopyCertificates(SecTrustSettingsDomain,
/// CFArrayRef *)`: every certificate with settings in the domain.
///
/// `errSecNoTrustSettings` for a domain with none - the user's and the
/// administrator's - which callers treat as the empty list it is. The system
/// domain answers its roots, as Apple's does after dropping any that fail a
/// basic evaluation outright; a null out-parameter asks only for the status.
///
/// # Safety
///
/// `certificates` is null or writable.
pub unsafe extern "C" fn SecTrustSettingsCopyCertificates(
    domain: u32,
    certificates: *mut CFTypeRef,
) -> OSStatus {
    let roots: &[Vec<u8>] = match domain {
        domain::USER | domain::ADMIN => &[],
        domain::SYSTEM => crate::trust::system_anchors(),
        _ => return PARAM,
    };
    if roots.is_empty() {
        return NO_TRUST_SETTINGS;
    }
    if certificates.is_null() {
        return SUCCESS;
    }
    let objects: Vec<CFTypeRef> = roots
        .iter()
        .map(|der| crate::trust::certificate_object(der))
        .filter(|object| !object.is_null())
        .collect();
    let array = corefoundation::collections::new_array(
        &objects,
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    for object in objects {
        // SAFETY: the array took its own reference.
        unsafe { corefoundation::api::CFRelease(object) };
    }
    // SAFETY: writable, per the caller.
    unsafe { certificates.write(array) };
    SUCCESS
}

/// `OSStatus SecTrustSettingsCopyTrustSettings(SecCertificateRef,
/// SecTrustSettingsDomain, CFArrayRef *)`: the certificate's settings in the
/// domain.
///
/// `errSecItemNotFound` when it has none, which is every certificate in the
/// user's and the administrator's domains. A system root's are the empty
/// array: "trusted as a root for every policy", which is how the system domain
/// records its roots.
///
/// # Safety
///
/// `certificate` is null or a live object, and `settings` is null or writable.
pub unsafe extern "C" fn SecTrustSettingsCopyTrustSettings(
    certificate: CFTypeRef,
    domain: u32,
    settings: *mut CFTypeRef,
) -> OSStatus {
    if settings.is_null() {
        return PARAM;
    }
    // SAFETY: the caller's guarantee.
    let Some(der) = (unsafe { crate::trust::certificate_der(certificate) }) else {
        return PARAM;
    };
    // SAFETY: writable, checked above.
    unsafe { settings.write(std::ptr::null()) };
    let listed = match domain {
        domain::USER | domain::ADMIN => false,
        domain::SYSTEM => crate::trust::system_anchors().iter().any(|root| root == der),
        _ => return PARAM,
    };
    if !listed {
        return ITEM_NOT_FOUND;
    }
    let empty = corefoundation::collections::new_array(
        &[],
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    // SAFETY: writable, checked above.
    unsafe { settings.write(empty) };
    SUCCESS
}

exports::exports! {
    functions {
        "SecTrustSettingsCopyCertificates" => SecTrustSettingsCopyCertificates,
        "SecTrustSettingsCopyTrustSettings" => SecTrustSettingsCopyTrustSettings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user's and the administrator's domains have no settings at all,
    /// and say so the way Chromium's trust store expects to hear it.
    #[test]
    fn the_user_and_admin_domains_have_no_settings() {
        foundation::bootstrap();
        for domain in [domain::USER, domain::ADMIN] {
            let mut certificates: CFTypeRef = std::ptr::null();
            // SAFETY: a writable out-parameter.
            let status = unsafe { SecTrustSettingsCopyCertificates(domain, &mut certificates) };
            assert_eq!(status, NO_TRUST_SETTINGS);
            assert!(certificates.is_null());
        }
        // SAFETY: as above.
        assert_eq!(unsafe { SecTrustSettingsCopyCertificates(7, std::ptr::null_mut()) }, PARAM);
    }

    /// A system root has the system domain's settings - none, which is "trust
    /// it as a root" - and nothing in the others.
    #[test]
    fn a_system_root_is_listed_in_the_system_domain_only() {
        foundation::bootstrap();
        let mut certificates: CFTypeRef = std::ptr::null();
        // SAFETY: a writable out-parameter.
        let status = unsafe { SecTrustSettingsCopyCertificates(domain::SYSTEM, &mut certificates) };
        if status == NO_TRUST_SETTINGS {
            // A host with no CA bundle has no system roots to list.
            return;
        }
        assert_eq!(status, SUCCESS);
        // SAFETY: the array this call made, and its elements.
        unsafe {
            assert!(corefoundation::api::CFArrayGetCount(certificates) > 0);
            let root = corefoundation::api::CFArrayGetValueAtIndex(certificates, 0);
            let mut settings: CFTypeRef = std::ptr::null();
            assert_eq!(SecTrustSettingsCopyTrustSettings(root, domain::SYSTEM, &mut settings), SUCCESS);
            assert_eq!(corefoundation::api::CFArrayGetCount(settings), 0);
            corefoundation::api::CFRelease(settings);
            for domain in [domain::USER, domain::ADMIN] {
                let mut settings: CFTypeRef = std::ptr::null();
                assert_eq!(
                    SecTrustSettingsCopyTrustSettings(root, domain, &mut settings),
                    ITEM_NOT_FOUND
                );
                assert!(settings.is_null());
            }
            corefoundation::api::CFRelease(certificates);
        }
    }
}
