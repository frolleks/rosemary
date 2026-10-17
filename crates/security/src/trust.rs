//! Certificates, the basic X.509 and SSL policies, and trust evaluation.
//!
//! A program that runs its own TLS stack hands the server's chain to
//! `SecTrustEvaluate` and connects only if it is trusted. The chain is checked
//! for real - signatures, validity dates, and a path to a root - because an
//! answer of "trusted" for anything would turn every such program into one that
//! accepts any server.
//!
//! The SSL policy is Apple's `SecPolicyCreateSSL` (Security, `SecPolicy.c`)
//! with the checks trustd runs for it (`SecPolicyServer.c`,
//! `SecPolicyLeafCallbacks.c`), and a failed evaluation is described the way
//! `SecTrustCopyError` (`SecTrust.c`) describes one.

#![allow(non_snake_case)]

use std::ffi::c_void;

use corefoundation::base::CFTypeRef;
use objc::class::Class;
use objc::object::Id;
use rustls_pki_types::TrustAnchor;
use rustls_pki_types::{CertificateDer, UnixTime};

use crate::der;

type OSStatus = i32;
const SUCCESS: OSStatus = 0;
/// `errSecParam`.
const PARAM: OSStatus = -50;

/// `SecTrustResultType`.
mod result {
    /// `kSecTrustResultProceed`: trusted, by an explicit user setting.
    pub const PROCEED: u32 = 1;
    /// `kSecTrustResultUnspecified`: trusted, with no explicit user setting.
    pub const UNSPECIFIED: u32 = 4;
    /// `kSecTrustResultRecoverableTrustFailure`: untrusted, but well formed.
    pub const RECOVERABLE: u32 = 5;
    /// `kSecTrustResultFatalTrustFailure`: a certificate could not be used at all.
    pub const FATAL: u32 = 6;
}

/// `kSecTrustOptionAllowExpired`.
const ALLOW_EXPIRED: u32 = 0x1;
/// `kSecTrustOptionAllowExpiredRoot`.
const ALLOW_EXPIRED_ROOT: u32 = 0x8;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Policy {
    /// `SecPolicyCreateBasicX509`: a chain to a trusted root, no name and no
    /// extended key usage required.
    BasicX509,
    /// `SecPolicyCreateSSL`: the basic policy, plus the host name and the
    /// usages a TLS server or client certificate must have.
    Ssl {
        server: bool,
        hostname: Option<String>,
    },
}

enum Payload {
    Certificate(Vec<u8>),
    Policy(Policy),
    Trust {
        chain: Vec<Vec<u8>>,
        options: u32,
        policies: Vec<Policy>,
        /// The last evaluation, until something that changes it is set.
        evaluation: Option<Evaluation>,
    },
}

#[repr(C)]
struct Body {
    isa: *const Class,
    payload: *mut Payload,
}

fn class() -> &'static Class {
    static CLASS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let pointer = *CLASS.get_or_init(|| {
        let class =
            corefoundation::base::register(c"__R3SecTrustObject", None, size_of::<Body>(), true);
        class.replace_method(
            objc::sel::get("dealloc"),
            dealloc as *const c_void,
            c"v16@0:8",
        );
        objc::class::ptr(class) as usize
    });
    // SAFETY: a class registered above and kept for the process.
    unsafe { objc::class::from_ptr(pointer as *const Class).expect("a trust object class") }
}

unsafe extern "C" fn dealloc(receiver: Id, _sel: objc::sel::Sel) {
    // SAFETY: this class's layout, and the payload `new` boxed.
    unsafe {
        let body = receiver as *mut Body;
        drop(Box::from_raw((*body).payload));
        objc::arc::finalize(receiver);
    }
}

/// A handle holding `payload`, owned by the caller.
fn new(payload: Payload) -> CFTypeRef {
    // SAFETY: `Body` is the registered layout.
    let body = unsafe { corefoundation::base::allocate::<Body>(class()) };
    if body.is_null() {
        return std::ptr::null();
    }
    // SAFETY: a freshly allocated body.
    unsafe { (*body).payload = Box::into_raw(Box::new(payload)) };
    body as CFTypeRef
}

/// The payload of one of these handles, or `None` for anything else.
///
/// # Safety
///
/// `object` is null or an object this runtime allocated, live for `'a`.
unsafe fn payload<'a>(object: CFTypeRef) -> Option<&'a mut Payload> {
    // SAFETY: the caller's guarantee.
    if object.is_null() || !unsafe { corefoundation::base::is_kind_of(object, class()) } {
        return None;
    }
    // SAFETY: a body of this class, whose payload lives as long as it does.
    Some(unsafe { &mut *(*(object as *const Body)).payload })
}

/// `object` itself, or each element if it is a `CFArray`.
///
/// # Safety
///
/// `object` is null or a live CoreFoundation object.
unsafe fn one_or_many(object: CFTypeRef) -> Vec<CFTypeRef> {
    use corefoundation::api::{
        CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFGetTypeID,
    };
    if object.is_null() {
        return Vec::new();
    }
    // SAFETY: a live object, and an array when its type says so.
    unsafe {
        if CFGetTypeID(object) != CFArrayGetTypeID() {
            return vec![object];
        }
        (0..CFArrayGetCount(object))
            .map(|i| CFArrayGetValueAtIndex(object, i))
            .collect()
    }
}

/// `SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef, CFDataRef)`.
///
/// Null unless the bytes are one DER-encoded X.509 certificate, as Apple's.
///
/// # Safety
///
/// `data` is null or a live `CFData`.
pub unsafe extern "C" fn SecCertificateCreateWithData(
    _allocator: CFTypeRef,
    data: CFTypeRef,
) -> CFTypeRef {
    if data.is_null() {
        return std::ptr::null();
    }
    // SAFETY: a live `CFData`, whose bytes stay put while it does.
    let bytes = unsafe {
        let length = corefoundation::api::CFDataGetLength(data);
        let base = corefoundation::api::CFDataGetBytePtr(data);
        if base.is_null() || length <= 0 {
            return std::ptr::null();
        }
        std::slice::from_raw_parts(base, length as usize).to_vec()
    };
    let der = CertificateDer::from(bytes.as_slice());
    if webpki::EndEntityCert::try_from(&der).is_err() {
        return std::ptr::null();
    }
    new(Payload::Certificate(bytes))
}

/// The host's root certificates, DER-encoded, read once.
///
/// From the bundle the host's own TLS libraries trust, so a program running
/// its own stack trusts the same servers the rest of the machine does.
/// `SSL_CERT_FILE` first, as OpenSSL reads it, then where Debian, Fedora,
/// NixOS and the BSDs keep theirs.
fn host_anchors() -> &'static [Vec<u8>] {
    static ANCHORS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    ANCHORS.get_or_init(|| {
        use rustls_pki_types::pem::PemObject;
        const BUNDLES: &[&str] = &[
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/usr/local/share/certs/ca-root-nss.crt",
        ];
        let named = std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from);
        let pem = named
            .into_iter()
            .chain(BUNDLES.iter().map(std::path::PathBuf::from))
            .find_map(|path| std::fs::read(path).ok())
            .unwrap_or_default();
        CertificateDer::pem_slice_iter(&pem)
            .filter_map(Result::ok)
            .map(|der| der.to_vec())
            .collect()
    })
}

/// `OSStatus SecTrustCopyAnchorCertificates(CFArrayRef *anchors)`.
///
/// # Safety
///
/// `anchors` is null or writable.
pub unsafe extern "C" fn SecTrustCopyAnchorCertificates(anchors: *mut CFTypeRef) -> OSStatus {
    if anchors.is_null() {
        return PARAM;
    }
    let certificates: Vec<CFTypeRef> = host_anchors()
        .iter()
        .map(|der| new(Payload::Certificate(der.clone())))
        .filter(|certificate| !certificate.is_null())
        .collect();
    let array = corefoundation::collections::new_array(
        &certificates,
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    for certificate in certificates {
        // SAFETY: the array took its own reference.
        unsafe { corefoundation::api::CFRelease(certificate) };
    }
    // SAFETY: writable, per the caller.
    unsafe { anchors.write(array) };
    SUCCESS
}

/// The DER bytes of a certificate handle.
///
/// # Safety
///
/// As [`payload`].
unsafe fn der_of<'a>(certificate: CFTypeRef) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    match unsafe { payload(certificate) } {
        Some(Payload::Certificate(der)) => Some(der),
        _ => None,
    }
}

/// `CFDataRef SecCertificateCopyData(SecCertificateRef)`.
///
/// # Safety
///
/// `certificate` is null or a live object.
pub unsafe extern "C" fn SecCertificateCopyData(certificate: CFTypeRef) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    match unsafe { der_of(certificate) } {
        Some(der) => corefoundation::collections::new_data(der.to_vec()),
        None => std::ptr::null(),
    }
}

/// `OSStatus SecCertificateGetData(SecCertificateRef, CSSM_DATA *)`.
///
/// `CSSM_DATA` is a length and a pointer, `size_t` wide on LP64. The pointer is
/// into the certificate, which is what Apple hands back too: valid for as long
/// as the caller holds the certificate.
///
/// # Safety
///
/// `certificate` is null or a live object, and `data` is null or writable.
pub unsafe extern "C" fn SecCertificateGetData(
    certificate: CFTypeRef,
    data: *mut (usize, *const u8),
) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some(der) = (unsafe { der_of(certificate) }) else {
        return PARAM;
    };
    if data.is_null() {
        return PARAM;
    }
    // SAFETY: writable, per the caller.
    unsafe { data.write((der.len(), der.as_ptr())) };
    SUCCESS
}

/// `SecPolicyRef SecPolicyCreateBasicX509(void)`.
///
/// # Safety
///
/// None beyond being called as the C function it is.
pub unsafe extern "C" fn SecPolicyCreateBasicX509() -> CFTypeRef {
    new(Payload::Policy(Policy::BasicX509))
}

/// `SecPolicyRef SecPolicyCreateSSL(Boolean server, CFStringRef hostname)`.
///
/// `server` is whether the certificates being evaluated are a server's, which
/// is what a TLS client asks; `hostname` is the name the leaf must carry, or
/// null for no name check at all.
///
/// # Safety
///
/// `hostname` is null or a live `CFString`.
pub unsafe extern "C" fn SecPolicyCreateSSL(server: u8, hostname: CFTypeRef) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    let hostname = unsafe { corefoundation::string::as_string(hostname) }
        .map(|text| String::from_utf16_lossy(&text.utf16()));
    new(Payload::Policy(Policy::Ssl {
        server: server != 0,
        hostname,
    }))
}

/// `OSStatus SecTrustCreateWithCertificates(CFTypeRef certificates, CFTypeRef
/// policies, SecTrustRef *trust)`.
///
/// `certificates` is one certificate or an array, the leaf first, and
/// `policies` one policy or an array of them. A policy this runtime does not
/// know is refused rather than evaluated as if it were another.
///
/// # Safety
///
/// Both are null or live objects, and `trust` is null or writable.
pub unsafe extern "C" fn SecTrustCreateWithCertificates(
    certificates: CFTypeRef,
    policies: CFTypeRef,
    trust: *mut CFTypeRef,
) -> OSStatus {
    if trust.is_null() {
        return PARAM;
    }
    let mut chain = Vec::new();
    // SAFETY: the caller's guarantee.
    for certificate in unsafe { one_or_many(certificates) } {
        // SAFETY: an element of a live array, or the object itself.
        match unsafe { payload(certificate) } {
            Some(Payload::Certificate(der)) => chain.push(der.clone()),
            _ => return PARAM,
        }
    }
    let mut known = Vec::new();
    // SAFETY: the caller's guarantee.
    for policy in unsafe { one_or_many(policies) } {
        // SAFETY: as above.
        match unsafe { payload(policy) } {
            Some(Payload::Policy(policy)) => known.push(policy.clone()),
            _ => {
                eprintln!(
                    "rosemary: security: SecTrustCreateWithCertificates: a policy this runtime does not know"
                );
                return PARAM;
            }
        }
    }
    if chain.is_empty() {
        return PARAM;
    }
    // Apple's default when none is given is the basic X.509 policy.
    if known.is_empty() {
        known.push(Policy::BasicX509);
    }
    // SAFETY: writable, checked above.
    unsafe {
        trust.write(new(Payload::Trust {
            chain,
            options: 0,
            policies: known,
            evaluation: None,
        }))
    };
    SUCCESS
}

/// `OSStatus SecTrustSetOptions(SecTrustRef, SecTrustOptionFlags)`.
///
/// # Safety
///
/// `trust` is null or a live object.
pub unsafe extern "C" fn SecTrustSetOptions(trust: CFTypeRef, flags: u32) -> OSStatus {
    // SAFETY: the caller's guarantee.
    match unsafe { payload(trust) } {
        Some(Payload::Trust {
            options,
            evaluation,
            ..
        }) => {
            *options = flags;
            // Evaluated again next time, under the new options.
            *evaluation = None;
            SUCCESS
        }
        _ => PARAM,
    }
}

/// The extended key usage each certificate in the path must allow.
///
/// For the basic policy, nothing: a certificate restricted to some purpose is
/// still a valid X.509 certificate. For an SSL policy, Apple's `set_ssl_ekus`,
/// run on every certificate in the path: the extension is optional, and when
/// present it must name one of the purposes listed.
struct Usage {
    allowed: Option<&'static [&'static [u8]]>,
    /// The purpose to name in the error, which is the one the role needs.
    required: fn() -> webpki::KeyUsage,
}

/// A server's: any usage, server authentication, or either Server Gated
/// Crypto purpose.
const SERVER_PURPOSES: &[&[u8]] = &[
    der::oid::ANY_EKU,
    der::oid::SERVER_AUTH,
    der::oid::MICROSOFT_SGC,
    der::oid::NETSCAPE_SGC,
];
/// A client's: any usage, or client authentication.
const CLIENT_PURPOSES: &[&[u8]] = &[der::oid::ANY_EKU, der::oid::CLIENT_AUTH];

impl webpki::ExtendedKeyUsageValidator for Usage {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        let Some(allowed) = self.allowed else {
            return Ok(());
        };
        let mut present = Vec::new();
        for id in iter {
            let id = id?;
            if allowed
                .iter()
                .any(|oid| webpki::KeyPurposeId::new(oid) == id)
            {
                return Ok(());
            }
            present.push(id.to_decoded_oid());
        }
        match present.is_empty() {
            true => Ok(()),
            false => Err(webpki::Error::RequiredEkuNotFoundContext(
                webpki::RequiredEkuNotFoundContext {
                    required: (self.required)(),
                    present,
                },
            )),
        }
    }
}

/// `SecTrustErrorSubType` (`SecTrustInternal.h`), in its order, which is the
/// order of precedence when a failed evaluation is put in one sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SubType {
    KeySize,
    WeakHash,
    Compliance,
    Trust,
    Usage,
    Name,
    Expired,
    Invalid,
}

impl SubType {
    /// The `SEC_TRUST_ERROR_SUBTYPE_*` sentence, around a certificate summary.
    fn sentence(self, summary: &str) -> String {
        match self {
            SubType::KeySize => {
                format!("\u{201c}{summary}\u{201d} certificate is using a broken key size")
            }
            SubType::WeakHash => {
                format!(
                    "\u{201c}{summary}\u{201d} certificate is using a broken signature algorithm"
                )
            }
            SubType::Compliance => {
                format!("\u{201c}{summary}\u{201d} certificate is not standards compliant")
            }
            SubType::Trust => format!("\u{201c}{summary}\u{201d} certificate is not trusted"),
            SubType::Usage => {
                format!("\u{201c}{summary}\u{201d} certificate is not permitted for this usage")
            }
            SubType::Name => {
                format!("\u{201c}{summary}\u{201d} certificate name does not match input")
            }
            SubType::Expired => format!("\u{201c}{summary}\u{201d} certificate is expired"),
            SubType::Invalid => {
                format!("Unknown trust error for \u{201c}{summary}\u{201d} certificate")
            }
        }
    }
}

/// One of `SecPolicyChecks.list`'s checks: what it says when it fails
/// (`SEC_TRUST_ERROR_<name>`), its subtype, its `OSStatus`, and whether its
/// failure is fatal rather than recoverable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Check {
    description: &'static str,
    subtype: SubType,
    status: OSStatus,
    fatal: bool,
}

mod check {
    use super::{Check, SubType};

    pub const SSL_HOSTNAME: Check = Check {
        description: "SSL hostname does not match name(s) in certificate",
        subtype: SubType::Name,
        status: -67602, // errSecHostNameMismatch
        fatal: false,
    };
    pub const TEMPORAL_VALIDITY: Check = Check {
        description: "Certificate is not temporally valid",
        subtype: SubType::Expired,
        status: -67818, // errSecCertificateExpired
        fatal: false,
    };
    pub const EXTENDED_KEY_USAGE: Check = Check {
        description: "Extended key usage does not match certificate usage",
        subtype: SubType::Usage,
        status: -67609, // errSecInvalidExtendedKeyUsage
        fatal: false,
    };
    pub const SERVER_AUTH_EKU: Check = Check {
        description: "Extended key usage does not match certificate usage",
        subtype: SubType::Usage,
        status: -67609, // errSecInvalidExtendedKeyUsage
        fatal: false,
    };
    pub const ANCHOR_TRUSTED: Check = Check {
        description: "Root is not trusted",
        subtype: SubType::Trust,
        status: -67843, // errSecNotTrusted
        fatal: false,
    };
    pub const SYSTEM_TRUST_VALIDITY_PERIOD: Check = Check {
        description: "Certificate exceeds maximum temporal validity period",
        subtype: SubType::Compliance,
        status: -67901, // errSecCertificateValidityPeriodTooLong
        fatal: false,
    };
    pub const BASIC_CONSTRAINTS: Check = Check {
        description: "Basic constraints are required but missing",
        subtype: SubType::Compliance,
        status: -67604, // errSecNoBasicConstraints
        fatal: false,
    };
    pub const WEAK_SIGNATURE: Check = Check {
        description: "Certificate is using a broken signature algorithm",
        subtype: SubType::WeakHash,
        status: -67815, // errSecInvalidDigestAlgorithm
        fatal: true,
    };
    pub const WEAK_KEY_SIZE: Check = Check {
        description: "Key size is not permitted for this use",
        subtype: SubType::KeySize,
        status: -67735, // errSecUnsupportedKeySize
        fatal: true,
    };
    /// A certificate `webpki` accepted and this crate's reader could not
    /// read, which leaves its names and usages unknown: never trusted.
    pub const UNREADABLE: Check = Check {
        description: "Certificate could not be read",
        subtype: SubType::Invalid,
        status: -67690, // errSecInvalidCertificateRef
        fatal: true,
    };
}

/// What an evaluation found: the `SecTrustResultType`, and each failed check
/// with the index of the certificate it failed on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Evaluation {
    result: u32,
    failures: Vec<(usize, Check)>,
}

/// `set_ssl_validity_periods`, for a leaf anchored by the system: from each
/// date a certificate is issued on, the longest it may be valid for, in
/// seconds since the Unix epoch.
const SYSTEM_TRUST_VALIDITY_PERIODS: &[(i64, i64)] = &[
    // 1 March 2018: 825 days, and an hour's slip.
    (1_519_862_400, 825 * 86_400 + 3600),
    // 1 September 2020: 398 days.
    (1_598_918_400, 398 * 86_400),
];

/// `check_validity_period_maximums`.
fn within_validity_maximums(leaf: &der::Certificate<'_>) -> bool {
    let period = leaf.not_after - leaf.not_before;
    SYSTEM_TRUST_VALIDITY_PERIODS
        .iter()
        .all(|&(effective, maximum)| leaf.not_before < effective || period <= maximum)
}

/// `SecDNSMatch`: a reference identifier - the name asked for - against one
/// a certificate presents, under RFC 6125's rules as Apple applies them.
///
/// A wildcard is a whole left-most label, matching one label, with at least
/// two labels after it. Apple also refuses one in front of a multi-label
/// public suffix, through CFNetwork's `_CFHostIsDomainTopLevelForCertificatePolicy`;
/// with no such list here the check passes, which is what Apple's code does
/// when it cannot find that function.
fn dns_match(reference: &str, presented: &str) -> bool {
    if reference.is_empty() {
        return false;
    }
    // A trailing dot on the reference is allowed, and stripped.
    let reference = reference.strip_suffix('.').unwrap_or(reference);
    let reference: Vec<&str> = reference.split('.').collect();
    let presented: Vec<&str> = presented.split('.').collect();
    if reference.len() != presented.len() {
        return false;
    }
    let count = presented.len();
    (0..count).rev().all(|ix| match presented[ix] {
        "*" => ix == 0 && count > 2 && ix != count - 2,
        label => !label.contains('*') && label.eq_ignore_ascii_case(reference[ix]),
    })
}

/// `SecPolicyCheckCertSSLHostname`: a DNS name of the subject alternative
/// name extension that matches, or for an address, an equal `iPAddress`
/// entry. The subject's common name is not consulted.
fn hostname_matches(leaf: &der::Certificate<'_>, hostname: &str) -> bool {
    if leaf.dns_names.iter().any(|name| dns_match(hostname, name)) {
        return true;
    }
    let address: Vec<u8> = match hostname.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.octets().to_vec(),
        Ok(std::net::IpAddr::V6(v6)) => v6.octets().to_vec(),
        Err(_) => return false,
    };
    leaf.ip_addresses
        .iter()
        .any(|entry| *entry == address.as_slice())
}

/// The check a chain `webpki` refused failed, and which certificate it is
/// reported against.
///
/// FIXME (ACCURACY): `webpki` names the error and not the certificate, so
/// everything but an untrusted root is reported against the leaf.
fn chain_failure(error: &webpki::Error, chain_length: usize) -> (usize, Check) {
    use webpki::Error as E;
    // The unit variants are deprecated, and still what an older path returns.
    #[allow(deprecated)]
    match error {
        E::CertExpired { .. } | E::CertNotValidYet { .. } | E::InvalidCertValidity => {
            (0, check::TEMPORAL_VALIDITY)
        }
        E::RequiredEkuNotFound | E::RequiredEkuNotFoundContext(_) | E::EmptyEkuExtension => {
            (0, check::EXTENDED_KEY_USAGE)
        }
        E::UnsupportedSignatureAlgorithm
        | E::UnsupportedSignatureAlgorithmContext(_)
        | E::SignatureAlgorithmMismatch => (0, check::WEAK_SIGNATURE),
        E::UnsupportedSignatureAlgorithmForPublicKey
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => (0, check::WEAK_KEY_SIZE),
        E::CaUsedAsEndEntity | E::EndEntityUsedAsCa | E::PathLenConstraintViolated => {
            (0, check::BASIC_CONSTRAINTS)
        }
        _ => (chain_length - 1, check::ANCHOR_TRUSTED),
    }
}

/// Evaluate `chain` (leaf first) under `policies` and `options`, against the
/// built-in roots, now.
///
/// FIXME (ACCURACY): the anchors are Mozilla's root program (`webpki-roots`),
/// not the keychain's. The two sets largely agree for public servers; a root
/// only Apple ships is untrusted here.
fn evaluate(chain: &[Vec<u8>], options: u32, policies: &[Policy]) -> Evaluation {
    evaluate_against(
        chain,
        options,
        policies,
        webpki_roots::TLS_SERVER_ROOTS,
        UnixTime::now(),
    )
}

/// [`evaluate`], against `anchors` - every one of which is treated as a
/// system anchor, as the built-in roots stand in for Apple's - at `now`.
///
/// FIXME (ACCURACY): Apple's SSL server policy also requires Certificate
/// Transparency for a system-trusted leaf (`SystemTrustedCTRequired`), checks
/// revocation where a certificate asks for it, and refuses leaves on its
/// block lists. None of those are checked here.
fn evaluate_against(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    anchors: &[TrustAnchor<'_>],
    now: UnixTime,
) -> Evaluation {
    let Some((leaf_der, rest)) = chain.split_first() else {
        return Evaluation {
            result: result::FATAL,
            failures: vec![(0, check::UNREADABLE)],
        };
    };
    let leaf_certificate = CertificateDer::from(leaf_der.as_slice());
    let Ok(end_entity) = webpki::EndEntityCert::try_from(&leaf_certificate) else {
        return Evaluation {
            result: result::FATAL,
            failures: vec![(0, check::UNREADABLE)],
        };
    };
    let Some(leaf) = der::certificate(leaf_der) else {
        return Evaluation {
            result: result::FATAL,
            failures: vec![(0, check::UNREADABLE)],
        };
    };
    let intermediates: Vec<_> = rest
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    // Of several SSL policies the first decides; the basic policy asks
    // nothing more of a chain than any of them does.
    let ssl = policies.iter().find_map(|policy| match policy {
        Policy::Ssl { server, hostname } => Some((*server, hostname.as_deref())),
        Policy::BasicX509 => None,
    });
    let usage = match ssl {
        Some((true, _)) => Usage {
            allowed: Some(SERVER_PURPOSES),
            required: webpki::KeyUsage::server_auth,
        },
        Some((false, _)) => Usage {
            allowed: Some(CLIENT_PURPOSES),
            required: webpki::KeyUsage::client_auth,
        },
        None => Usage {
            allowed: None,
            required: webpki::KeyUsage::server_auth,
        },
    };

    let mut failures = Vec::new();
    let mut time = now;
    // A date failure does not end the evaluation: Apple runs every check and
    // reports the one that matters most, so the chain is asked again at a
    // moment the failing certificate was valid - a few times, since each step
    // can land outside another certificate's dates. An allowed expiry is the
    // same step without the failure.
    for _ in 0..4 {
        let verified = end_entity.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            anchors,
            &intermediates,
            time,
            &usage,
            None,
            None,
        );
        match verified {
            Ok(path) => {
                // `SecPolicyCheckServerAuthEKU`, for a system-anchored server:
                // the leaf must name server authentication outright, and a
                // sub-CA that restricts its usages must allow it.
                if let Some((true, _)) = ssl {
                    let named = leaf
                        .extended_key_usage
                        .as_ref()
                        .is_some_and(|purposes| purposes.contains(&der::oid::SERVER_AUTH));
                    if !named {
                        failures.push((0, check::SERVER_AUTH_EKU));
                    }
                    for intermediate in path.intermediate_certificates() {
                        let bytes = intermediate.der();
                        let restricted = der::certificate(&bytes)
                            .and_then(|ca| ca.extended_key_usage)
                            .is_some_and(|purposes| {
                                !purposes.is_empty()
                                    && !purposes.contains(&der::oid::SERVER_AUTH)
                                    && !purposes.contains(&der::oid::ANY_EKU)
                            });
                        if restricted {
                            let index = chain
                                .iter()
                                .position(|der| der.as_slice() == bytes.as_ref())
                                .unwrap_or(1);
                            failures.push((index, check::SERVER_AUTH_EKU));
                        }
                    }
                    // `SecPolicyCheckSystemTrustValidityPeriod`.
                    if !within_validity_maximums(&leaf) {
                        failures.push((0, check::SYSTEM_TRUST_VALIDITY_PERIOD));
                    }
                }
                break;
            }
            Err(webpki::Error::CertExpired { not_after, .. }) => {
                if options & (ALLOW_EXPIRED | ALLOW_EXPIRED_ROOT) == 0
                    && !failures.contains(&(0, check::TEMPORAL_VALIDITY))
                {
                    failures.push((0, check::TEMPORAL_VALIDITY));
                }
                time = not_after;
            }
            Err(webpki::Error::CertNotValidYet { not_before, .. }) => {
                if !failures.contains(&(0, check::TEMPORAL_VALIDITY)) {
                    failures.push((0, check::TEMPORAL_VALIDITY));
                }
                time = not_before;
            }
            Err(error) => {
                failures.push(chain_failure(&error, chain.len()));
                break;
            }
        }
    }
    // `SecPolicyCheckSSLHostname`, which is the leaf's alone and so runs
    // whether or not the chain did.
    if let Some((_, Some(hostname))) = ssl
        && !hostname_matches(&leaf, hostname)
    {
        failures.push((0, check::SSL_HOSTNAME));
    }
    let result = match () {
        _ if failures.is_empty() => result::UNSPECIFIED,
        _ if failures.iter().any(|(_, check)| check.fatal) => result::FATAL,
        _ => result::RECOVERABLE,
    };
    Evaluation { result, failures }
}

/// The trust's evaluation, made now if it has not been since it last changed:
/// `SecTrustEvaluateIfNecessary`.
fn evaluated(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    cached: &mut Option<Evaluation>,
) -> Evaluation {
    cached
        .get_or_insert_with(|| evaluate(chain, options, policies))
        .clone()
}

/// `OSStatus SecTrustEvaluate(SecTrustRef, SecTrustResultType *)`.
///
/// # Safety
///
/// `trust` is null or a live object, and `out` is null or writable.
pub unsafe extern "C" fn SecTrustEvaluate(trust: CFTypeRef, out: *mut u32) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some(Payload::Trust {
        chain,
        options,
        policies,
        evaluation,
    }) = (unsafe { payload(trust) })
    else {
        return PARAM;
    };
    // An explicit evaluation is a fresh one, as Apple's is.
    *evaluation = None;
    let verdict = evaluated(chain, *options, policies, evaluation).result;
    if !out.is_null() {
        // SAFETY: writable, per the caller.
        unsafe { out.write(verdict) };
    }
    SUCCESS
}

/// `bool SecTrustEvaluateWithError(SecTrustRef, CFErrorRef *error)`.
///
/// True for a trusted chain, with `*error` set to null; false otherwise,
/// with `*error` - which the caller releases - saying why, as Apple's
/// `SecTrustCopyError` does.
///
/// # Safety
///
/// `trust` is null or a live object, and `error` is null or writable.
pub unsafe extern "C" fn SecTrustEvaluateWithError(trust: CFTypeRef, error: *mut CFTypeRef) -> u8 {
    // SAFETY: the caller's guarantee.
    let Some(Payload::Trust {
        chain,
        options,
        policies,
        evaluation,
    }) = (unsafe { payload(trust) })
    else {
        if !error.is_null() {
            // SAFETY: writable, per the caller.
            unsafe { error.write(status_error(PARAM)) };
        }
        return 0;
    };
    *evaluation = None;
    let evaluated = evaluated(chain, *options, policies, evaluation);
    let trusted = matches!(evaluated.result, result::PROCEED | result::UNSPECIFIED);
    if !error.is_null() {
        let made = match trusted {
            true => std::ptr::null(),
            false => copy_error(chain, &evaluated),
        };
        // SAFETY: writable, per the caller.
        unsafe { error.write(made) };
    }
    trusted as u8
}

/// `OSStatus SecTrustGetTrustResult(SecTrustRef, SecTrustResultType *)`: the
/// result of the last evaluation, evaluating first if there has been none.
///
/// # Safety
///
/// `trust` is null or a live object, and `out` is null or writable.
pub unsafe extern "C" fn SecTrustGetTrustResult(trust: CFTypeRef, out: *mut u32) -> OSStatus {
    if out.is_null() {
        return PARAM;
    }
    // SAFETY: the caller's guarantee.
    let Some(Payload::Trust {
        chain,
        options,
        policies,
        evaluation,
    }) = (unsafe { payload(trust) })
    else {
        return PARAM;
    };
    let verdict = evaluated(chain, *options, policies, evaluation).result;
    // SAFETY: writable, checked above.
    unsafe { out.write(verdict) };
    SUCCESS
}

/// `kCFErrorDomainOSStatus`.
const OSSTATUS_DOMAIN: &str = "NSOSStatusErrorDomain";

/// `SecCopyErrorMessageString` for the statuses this module reports: the
/// sentences `SecBase.h` gives them.
fn status_message(status: OSStatus) -> &'static str {
    match status {
        PARAM => "One or more parameters passed to a function were not valid.",
        -67602 => "A host name mismatch has occurred.",
        -67604 => "No basic constraints were found.",
        -67609 => "The extended key usage is not valid.",
        -67690 => "An invalid certificate reference was encountered.",
        -67735 => "The key size is not supported.",
        -67815 => "An invalid digest algorithm was detected.",
        -67818 => "An expired certificate was detected.",
        -67843 => "The certificate was not trusted.",
        -67901 => "The validity period in the certificate exceeds the maximum allowed.",
        _ => "An internal error has occurred.",
    }
}

/// `SecCopyLastError`: an `OSStatus` as a `CFError`, at +1.
fn status_error(status: OSStatus) -> CFTypeRef {
    foundation::error::create(
        OSSTATUS_DOMAIN,
        i64::from(status),
        status_message(status),
        &[],
    ) as CFTypeRef
}

/// `SecTrustCopyError`, for an evaluation that failed: an error whose
/// description is the one sentence `SecTrustCopyErrorStrings` picks - the
/// failure of the highest-precedence subtype, on the lowest-indexed
/// certificate that has it - over an underlying error listing every failure
/// of every certificate. Both carry that failure's `OSStatus`.
fn copy_error(chain: &[Vec<u8>], evaluation: &Evaluation) -> CFTypeRef {
    let summary = |index: usize| {
        chain
            .get(index)
            .and_then(|der| der::certificate(der))
            .and_then(|certificate| der::subject_summary(&certificate))
    };
    let chosen = evaluation
        .failures
        .iter()
        .min_by_key(|(index, check)| (check.subtype, *index))
        .copied();
    let (status, simple) = match chosen {
        Some((index, check)) => (
            check.status,
            match summary(index) {
                Some(name) => check.subtype.sentence(&name),
                None => status_message(check.status).to_string(),
            },
        ),
        None => (-26276, status_message(-26276).to_string()), // errSecInternalError
    };
    let mut detailed = String::new();
    let mut indices: Vec<usize> = evaluation
        .failures
        .iter()
        .map(|(index, _)| *index)
        .collect();
    indices.sort_unstable();
    indices.dedup();
    for index in indices {
        let mut descriptions: Vec<&str> = Vec::new();
        for (_, check) in evaluation.failures.iter().filter(|(at, _)| *at == index) {
            if !descriptions.contains(&check.description) {
                descriptions.push(check.description);
            }
        }
        detailed.push_str(&format!(
            "Certificate {index} \u{201c}{}\u{201d} has errors: {};",
            summary(index).unwrap_or_default(),
            descriptions.join(", "),
        ));
    }
    let underlying = foundation::error::create(OSSTATUS_DOMAIN, i64::from(status), &detailed, &[]);
    let error = foundation::error::create(
        OSSTATUS_DOMAIN,
        i64::from(status),
        &simple,
        &[("NSUnderlyingError", underlying)],
    );
    objc::arc::release(underlying);
    error as CFTypeRef
}

/// `int SecRandomCopyBytes(SecRandomRef, size_t, void *)`. The generator
/// argument is `kSecRandomDefault` - null - in every caller.
///
/// # Safety
///
/// `bytes` is writable for `count` bytes.
pub unsafe extern "C" fn SecRandomCopyBytes(_rnd: CFTypeRef, count: usize, bytes: *mut u8) -> i32 {
    if count == 0 {
        return 0;
    }
    if bytes.is_null() {
        return -1;
    }
    // SAFETY: the caller's guarantee.
    let buffer = unsafe { std::slice::from_raw_parts_mut(bytes, count) };
    match getrandom::fill(buffer) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

exports::exports! {
    functions {
        "SecCertificateCreateWithData" => SecCertificateCreateWithData,
        "SecPolicyCreateBasicX509" => SecPolicyCreateBasicX509,
        "SecTrustCreateWithCertificates" => SecTrustCreateWithCertificates,
        "SecTrustSetOptions" => SecTrustSetOptions,
        "SecTrustEvaluate" => SecTrustEvaluate,
        "SecTrustEvaluateWithError" => SecTrustEvaluateWithError,
        "SecTrustGetTrustResult" => SecTrustGetTrustResult,
        "SecPolicyCreateSSL" => SecPolicyCreateSSL,
        "SecRandomCopyBytes" => SecRandomCopyBytes,
        "SecTrustCopyAnchorCertificates" => SecTrustCopyAnchorCertificates,
        "SecCertificateCopyData" => SecCertificateCopyData,
        "SecCertificateGetData" => SecCertificateGetData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every anchor reads back as the bytes it was made from, through both
    /// spellings of the question.
    #[test]
    fn anchors_read_back_as_their_der() {
        let mut array: CFTypeRef = std::ptr::null();
        assert_eq!(
            unsafe { SecTrustCopyAnchorCertificates(&mut array) },
            SUCCESS
        );
        let count = unsafe { corefoundation::api::CFArrayGetCount(array) };
        if count == 0 {
            // A host with no CA bundle, which is a host and not a failure.
            return;
        }
        let first = unsafe { corefoundation::api::CFArrayGetValueAtIndex(array, 0) };
        let data = unsafe { SecCertificateCopyData(first) };
        let length = unsafe { corefoundation::api::CFDataGetLength(data) } as usize;
        let mut cssm = (0usize, std::ptr::null::<u8>());
        assert_eq!(unsafe { SecCertificateGetData(first, &mut cssm) }, SUCCESS);
        assert_eq!(cssm.0, length);
        assert_eq!(host_anchors()[0].len(), length);
    }

    /// A certificate that chains to nothing: well formed, so it is accepted as a
    /// certificate, but evaluation must not call it trusted.
    #[test]
    fn a_self_signed_certificate_is_not_trusted() {
        objc::bootstrap();
        let der = self_signed();
        let data = data(&der);
        let mut trust = std::ptr::null();
        let mut verdict = 0;
        // SAFETY: objects this test made, and writable out-parameters.
        unsafe {
            let certificate = SecCertificateCreateWithData(std::ptr::null(), data);
            assert!(!certificate.is_null(), "a DER certificate is accepted");
            let policy = SecPolicyCreateBasicX509();
            assert_eq!(
                SecTrustCreateWithCertificates(certificate, policy, &mut trust),
                SUCCESS
            );
            assert_eq!(SecTrustSetOptions(trust, ALLOW_EXPIRED), SUCCESS);
            assert_eq!(SecTrustEvaluate(trust, &mut verdict), SUCCESS);
            assert_eq!(verdict, result::RECOVERABLE);
            for object in [trust, policy, certificate, data] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// The test PKI: a root, and leaves it issued valid from 2025-01-01.
    fn pki(name: &str) -> Vec<u8> {
        match name {
            "ca" => include_bytes!("testdata/pki/ca.der").to_vec(),
            "server" => include_bytes!("testdata/pki/server.rosemary.test.der").to_vec(),
            "no-eku" => include_bytes!("testdata/pki/no-eku.rosemary.test.der").to_vec(),
            "client" => include_bytes!("testdata/pki/client.rosemary.test.der").to_vec(),
            "long" => include_bytes!("testdata/pki/long.rosemary.test.der").to_vec(),
            _ => unreachable!(),
        }
    }

    /// 2025-06-01, inside every test leaf's validity.
    const JUNE_2025: u64 = 1_748_736_000;

    /// Evaluate one test leaf under `policy`, anchored by the test root.
    fn ssl(leaf: &str, policy: Policy, at: u64) -> Evaluation {
        let root = pki("ca");
        let root = CertificateDer::from(root.as_slice());
        let anchor = webpki::anchor_from_trusted_cert(&root).expect("the test root");
        evaluate_against(
            &[pki(leaf)],
            0,
            &[policy],
            &[anchor],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(at)),
        )
    }

    fn server(hostname: &str) -> Policy {
        Policy::Ssl {
            server: true,
            hostname: Some(hostname.to_string()),
        }
    }

    fn failures(evaluation: &Evaluation) -> Vec<(usize, Check)> {
        evaluation.failures.clone()
    }

    #[test]
    fn a_server_certificate_for_its_own_name_is_trusted() {
        for name in [
            "server.rosemary.test",
            "SERVER.rosemary.test",
            "server.rosemary.test.",
            "127.0.0.1",
        ] {
            let evaluation = ssl("server", server(name), JUNE_2025);
            assert_eq!(evaluation.result, result::UNSPECIFIED, "{name}");
            assert!(evaluation.failures.is_empty(), "{name}");
        }
    }

    /// `*.cdn.rosemary.test` is one label and only one, and never the domain
    /// itself.
    #[test]
    fn a_wildcard_matches_exactly_one_label() {
        let evaluation = ssl("server", server("a.cdn.rosemary.test"), JUNE_2025);
        assert_eq!(evaluation.result, result::UNSPECIFIED);
        for name in [
            "a.b.cdn.rosemary.test",
            "cdn.rosemary.test",
            "other.rosemary.test",
            "127.0.0.2",
        ] {
            let evaluation = ssl("server", server(name), JUNE_2025);
            assert_eq!(evaluation.result, result::RECOVERABLE, "{name}");
            assert_eq!(failures(&evaluation), [(0, check::SSL_HOSTNAME)], "{name}");
        }
    }

    #[test]
    fn dns_matching_follows_apples_rules() {
        assert!(dns_match("www.example.com", "*.example.com"));
        assert!(
            !dns_match("example.com", "*.com"),
            "not before a single-label TLD"
        );
        assert!(
            !dns_match("www.example.com", "w*.example.com"),
            "no partial-label wildcards"
        );
        assert!(
            !dns_match("www.example.com", "www.*.com"),
            "only the left-most label"
        );
        assert!(!dns_match("", "example.com"));
        assert!(dns_match("Example.COM", "example.com"));
    }

    /// A system-anchored server's leaf must name server authentication, which
    /// the basic policy does not ask of it.
    #[test]
    fn a_server_leaf_without_server_auth_is_not_trusted_for_ssl() {
        let evaluation = ssl("no-eku", server("no-eku.rosemary.test"), JUNE_2025);
        assert_eq!(failures(&evaluation), [(0, check::SERVER_AUTH_EKU)]);
        let basic = ssl("no-eku", Policy::BasicX509, JUNE_2025);
        assert_eq!(basic.result, result::UNSPECIFIED);
    }

    #[test]
    fn a_client_certificate_is_a_client_s_and_not_a_server_s() {
        let evaluation = ssl("client", server("client.rosemary.test"), JUNE_2025);
        assert_eq!(failures(&evaluation), [(0, check::EXTENDED_KEY_USAGE)]);
        let client = ssl(
            "client",
            Policy::Ssl {
                server: false,
                hostname: None,
            },
            JUNE_2025,
        );
        assert_eq!(client.result, result::UNSPECIFIED);
    }

    /// Issued after 1 September 2020 and valid for 516 days, past the 398 a
    /// system-trusted leaf may have.
    #[test]
    fn a_leaf_valid_too_long_is_not_compliant() {
        let evaluation = ssl("long", server("long.rosemary.test"), JUNE_2025);
        assert_eq!(
            failures(&evaluation),
            [(0, check::SYSTEM_TRUST_VALIDITY_PERIOD)]
        );
    }

    #[test]
    fn an_expired_leaf_is_reported_as_expired() {
        // 2026-01-01, after the leaf's 2025-10-01.
        let evaluation = ssl("server", server("server.rosemary.test"), 1_767_225_600);
        assert_eq!(failures(&evaluation), [(0, check::TEMPORAL_VALIDITY)]);
    }

    /// Against the built-in roots the test PKI is nobody's: not trusted, with
    /// the reasons in Apple's words and its `OSStatus`.
    #[test]
    fn an_untrusted_chain_says_why_through_its_error() {
        foundation::bootstrap();
        let data = data(&pki("server"));
        // SAFETY: objects this test made, and writable out-parameters.
        unsafe {
            let certificate = SecCertificateCreateWithData(std::ptr::null(), data);
            let hostname = foundation::string::from_str("server.rosemary.test") as CFTypeRef;
            let policy = SecPolicyCreateSSL(1, hostname);
            let mut trust = std::ptr::null();
            assert_eq!(
                SecTrustCreateWithCertificates(certificate, policy, &mut trust),
                SUCCESS
            );
            let mut verdict = 0; // kSecTrustResultInvalid
            assert_eq!(SecTrustGetTrustResult(trust, &mut verdict), SUCCESS);
            assert_eq!(verdict, result::RECOVERABLE, "evaluated on demand");
            let mut error: CFTypeRef = std::ptr::null();
            assert_eq!(SecTrustEvaluateWithError(trust, &mut error), 0);
            assert!(!error.is_null());
            let send = |object: CFTypeRef, selector: &str| -> Id {
                let f: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                    std::mem::transmute(objc::msg::entry());
                f(object as Id, objc::sel::get(selector))
            };
            let text = |object: Id| {
                corefoundation::string::as_string(object as CFTypeRef)
                    .map(|s| String::from_utf16_lossy(&s.utf16()))
                    .unwrap_or_default()
            };
            assert_eq!(
                text(send(error, "localizedDescription")),
                "\u{201c}server.rosemary.test\u{201d} certificate is not trusted"
            );
            assert_eq!(text(send(error, "domain")), "NSOSStatusErrorDomain");
            assert_eq!(send(error, "code") as i64, -67843);
            for object in [error, trust, policy, hostname, certificate, data] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    #[test]
    fn bytes_that_are_not_a_certificate_make_no_certificate() {
        objc::bootstrap();
        let data = data(b"not a certificate");
        // SAFETY: a `CFData` this test made.
        unsafe {
            assert!(SecCertificateCreateWithData(std::ptr::null(), data).is_null());
            corefoundation::api::CFRelease(data);
        }
    }

    #[test]
    fn random_bytes_fill_the_buffer() {
        let mut buffer = [0u8; 64];
        // SAFETY: a writable buffer of the stated length.
        assert_eq!(
            unsafe { SecRandomCopyBytes(std::ptr::null(), buffer.len(), buffer.as_mut_ptr()) },
            0
        );
        assert!(buffer.iter().any(|&b| b != 0));
    }

    /// A self-signed P-256 certificate, `CN=rosemary test`, valid for a century
    /// from its making so the test does not expire.
    fn self_signed() -> Vec<u8> {
        include_bytes!("testdata/self_signed.der").to_vec()
    }

    fn data(bytes: &[u8]) -> CFTypeRef {
        // SAFETY: a live slice of the stated length.
        unsafe {
            corefoundation::api::CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as _)
        }
    }
}
