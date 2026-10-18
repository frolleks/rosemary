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

use corefoundation::base::{CFTypeID, CFTypeRef};
use objc::class::Class;
use objc::object::Id;
use rustls_pki_types::{CertificateDer, UnixTime};
use rustls_pki_types::TrustAnchor;

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
    /// `SecPolicyCreateRevocation`, with its `kSecRevocation*` flags.
    Revocation { flags: u64 },
}

/// `kSecRevocationRequirePositiveResponse`.
const REVOCATION_REQUIRE_POSITIVE_RESPONSE: u64 = 1 << 3;

enum Payload {
    Certificate(Vec<u8>),
    Policy(Policy),
    Trust {
        chain: Vec<Vec<u8>>,
        options: u32,
        policies: Vec<Policy>,
        /// The last evaluation, until something that changes it is set.
        evaluation: Option<Evaluation>,
        /// What `SecTrustGetCertificateAtIndex` and the other legacy calls hand
        /// out without a reference of the caller's own: the trust holds them.
        legacy: Legacy,
    },
}

/// The parts of a trust only the legacy calls read, and the objects the trust
/// keeps alive on their behalf.
#[derive(Default)]
struct Legacy {
    /// The certificates the trust was made with, as the caller's own objects:
    /// `SecTrustGetCertificateAtIndex(trust, 0)` is pointer-equal to the leaf
    /// passed in, which callers rely on (`SecTrustCopyConstructedChain`).
    inputs: Retained,
    /// `SecTrustSetAnchorCertificates`: none means the system's.
    anchors: Option<Vec<Vec<u8>>>,
    anchors_only: bool,
    /// `SecTrustSetOCSPResponse`'s responses, kept as given.
    ///
    /// FIXME (ACCURACY): never read. Revocation is not checked here at all, so
    /// a stapled response neither helps nor hurts an evaluation.
    responses: Vec<Vec<u8>>,
    /// `SecTrustSetSignedCertificateTimestamps`, as the caller's array.
    ///
    /// FIXME (ACCURACY): never read. Certificate Transparency is not checked
    /// here, as revocation is not.
    timestamps: Retained,
    /// `SecTrustSetVerifyDate`, as seconds since the Unix epoch.
    verify_date: Option<u64>,
    /// The constructed chain's certificate objects, made when first asked for
    /// and dropped with the evaluation they describe.
    chain: Retained,
    /// `SecTrustGetResult`'s evidence: one record a certificate, and the status
    /// codes they point into.
    evidence: Option<(Box<[Evidence]>, Box<[i32]>)>,
}

/// CoreFoundation objects owned by whatever holds this, released with it.
#[derive(Default)]
struct Retained(Vec<CFTypeRef>);

impl Drop for Retained {
    fn drop(&mut self) {
        for object in self.0.drain(..) {
            // SAFETY: each a reference this list took.
            unsafe { corefoundation::api::CFRelease(object) };
        }
    }
}

/// `CSSM_TP_APPLE_EVIDENCE_INFO`, as LP64 lays it out.
#[repr(C)]
pub struct Evidence {
    status_bits: u32,
    num_status_codes: u32,
    status_codes: *const i32,
    index: u32,
    /// `CSSM_DL_DB_HANDLE`: two `CSSM_HANDLE`s, zero for a certificate that
    /// did not come from a keychain - which none here do.
    dl_db_handle: [usize; 2],
    unique_record: *const c_void,
}

/// `CSSM_CERT_STATUS_*`.
mod status_bits {
    pub const EXPIRED: u32 = 0x1;
    pub const NOT_VALID_YET: u32 = 0x2;
    pub const IS_IN_INPUT_CERTS: u32 = 0x4;
    pub const IS_IN_ANCHORS: u32 = 0x8;
    pub const IS_ROOT: u32 = 0x10;
    pub const TRUST_SETTINGS_FOUND_SYSTEM: u32 = 0x100;
    pub const TRUST_SETTINGS_TRUST: u32 = 0x200;
}

#[repr(C)]
struct Body {
    isa: *const Class,
    payload: *mut Payload,
}

/// The class every certificate, policy and trust is an instance of a subclass
/// of: the one that owns the payload.
fn class() -> &'static Class {
    static CLASS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let pointer = *CLASS.get_or_init(|| {
        let class =
            corefoundation::base::register(c"__R3SecTrustObject", None, size_of::<Body>(), false);
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

/// What a payload is, which is also its CoreFoundation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Certificate,
    Policy,
    Trust,
}

impl Payload {
    fn kind(&self) -> Kind {
        match self {
            Payload::Certificate(_) => Kind::Certificate,
            Payload::Policy(_) => Kind::Policy,
            Payload::Trust { .. } => Kind::Trust,
        }
    }
}

/// The class of one kind of object: `SecCertificate`, `SecPolicy`, `SecTrust`,
/// each its own CoreFoundation type, as Apple's are. A program tells them apart
/// by type - `CFGetTypeID(item) == SecCertificateGetTypeID()` is how a keychain
/// search result is sorted - so one type for all three would make a policy pass
/// for a certificate.
fn kind_class(kind: Kind) -> &'static Class {
    static CLASSES: [std::sync::OnceLock<usize>; 3] = [const { std::sync::OnceLock::new() }; 3];
    let (cell, name) = match kind {
        Kind::Certificate => (&CLASSES[0], c"SecCertificate"),
        Kind::Policy => (&CLASSES[1], c"SecPolicy"),
        Kind::Trust => (&CLASSES[2], c"SecTrust"),
    };
    let pointer = *cell.get_or_init(|| {
        let class = corefoundation::base::register(name, Some(class()), size_of::<Body>(), true);
        objc::class::ptr(class) as usize
    });
    // SAFETY: a class registered above and kept for the process.
    unsafe { objc::class::from_ptr(pointer as *const Class).expect("a trust object class") }
}

/// `CFTypeID SecCertificateGetTypeID(void)`.
pub extern "C" fn SecCertificateGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(kind_class(Kind::Certificate))
}

/// `CFTypeID SecPolicyGetTypeID(void)`.
pub extern "C" fn SecPolicyGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(kind_class(Kind::Policy))
}

/// `CFTypeID SecTrustGetTypeID(void)`.
pub extern "C" fn SecTrustGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(kind_class(Kind::Trust))
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
    let body = unsafe { corefoundation::base::allocate::<Body>(kind_class(payload.kind())) };
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
    let mut inputs = Retained::default();
    // SAFETY: the caller's guarantee.
    for certificate in unsafe { one_or_many(certificates) } {
        // SAFETY: an element of a live array, or the object itself.
        match unsafe { payload(certificate) } {
            Some(Payload::Certificate(der)) => {
                chain.push(der.clone());
                // SAFETY: a live certificate.
                inputs.0.push(unsafe { corefoundation::api::CFRetain(certificate) });
            }
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
            legacy: Legacy {
                inputs,
                ..Legacy::default()
            },
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
            legacy,
            ..
        }) => {
            *options = flags;
            // Evaluated again next time, under the new options.
            needs_evaluation(evaluation, legacy);
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
            if allowed.iter().any(|oid| webpki::KeyPurposeId::new(oid) == id) {
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
            SubType::KeySize => format!("\u{201c}{summary}\u{201d} certificate is using a broken key size"),
            SubType::WeakHash => {
                format!("\u{201c}{summary}\u{201d} certificate is using a broken signature algorithm")
            }
            SubType::Compliance => format!("\u{201c}{summary}\u{201d} certificate is not standards compliant"),
            SubType::Trust => format!("\u{201c}{summary}\u{201d} certificate is not trusted"),
            SubType::Usage => {
                format!("\u{201c}{summary}\u{201d} certificate is not permitted for this usage")
            }
            SubType::Name => format!("\u{201c}{summary}\u{201d} certificate name does not match input"),
            SubType::Expired => format!("\u{201c}{summary}\u{201d} certificate is expired"),
            SubType::Invalid => format!("Unknown trust error for \u{201c}{summary}\u{201d} certificate"),
        }
    }
}

/// One of `SecPolicyChecks.list`'s checks: what it says when it fails
/// (`SEC_TRUST_ERROR_<name>`), its subtype, its `OSStatus`, its CSSM error -
/// what the legacy calls report - and whether its failure is fatal rather than
/// recoverable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Check {
    description: &'static str,
    subtype: SubType,
    status: OSStatus,
    cssm: u32,
    fatal: bool,
}

mod check {
    use super::{Check, SubType};

    pub const SSL_HOSTNAME: Check = Check {
        description: "SSL hostname does not match name(s) in certificate",
        subtype: SubType::Name,
        status: -67602, // errSecHostNameMismatch
        cssm: 0x80012400, // CSSMERR_APPLETP_HOSTNAME_MISMATCH
        fatal: false,
    };
    pub const TEMPORAL_VALIDITY: Check = Check {
        description: "Certificate is not temporally valid",
        subtype: SubType::Expired,
        status: -67818, // errSecCertificateExpired
        cssm: 0x8001210A, // CSSMERR_TP_CERT_EXPIRED
        fatal: false,
    };
    pub const EXTENDED_KEY_USAGE: Check = Check {
        description: "Extended key usage does not match certificate usage",
        subtype: SubType::Usage,
        status: -67609, // errSecInvalidExtendedKeyUsage
        cssm: 0x80012407, // CSSMERR_APPLETP_INVALID_EXTENDED_KEY_USAGE
        fatal: false,
    };
    pub const SERVER_AUTH_EKU: Check = Check {
        description: "Extended key usage does not match certificate usage",
        subtype: SubType::Usage,
        status: -67609, // errSecInvalidExtendedKeyUsage
        cssm: 0x80012407, // CSSMERR_APPLETP_INVALID_EXTENDED_KEY_USAGE
        fatal: false,
    };
    pub const ANCHOR_TRUSTED: Check = Check {
        description: "Root is not trusted",
        subtype: SubType::Trust,
        status: -67843, // errSecNotTrusted
        cssm: 0x8001212A, // CSSMERR_TP_NOT_TRUSTED
        fatal: false,
    };
    pub const SYSTEM_TRUST_VALIDITY_PERIOD: Check = Check {
        description: "Certificate exceeds maximum temporal validity period",
        subtype: SubType::Compliance,
        status: -67901, // errSecCertificateValidityPeriodTooLong
        cssm: 0x8001210D, // CSSMERR_TP_CERT_SUSPENDED
        fatal: false,
    };
    pub const BASIC_CONSTRAINTS: Check = Check {
        description: "Basic constraints are required but missing",
        subtype: SubType::Compliance,
        status: -67604, // errSecNoBasicConstraints
        cssm: 0x80012402, // CSSMERR_APPLETP_NO_BASIC_CONSTRAINTS
        fatal: false,
    };
    pub const WEAK_SIGNATURE: Check = Check {
        description: "Certificate is using a broken signature algorithm",
        subtype: SubType::WeakHash,
        status: -67815, // errSecInvalidDigestAlgorithm
        cssm: 0x80010955, // CSSMERR_CSP_INVALID_DIGEST_ALGORITHM
        fatal: true,
    };
    pub const WEAK_KEY_SIZE: Check = Check {
        description: "Key size is not permitted for this use",
        subtype: SubType::KeySize,
        status: -67735, // errSecUnsupportedKeySize
        cssm: 0x80012115, // CSSMERR_TP_INVALID_CERTIFICATE
        fatal: true,
    };
    /// A certificate `webpki` accepted and this crate's reader could not
    /// read, which leaves its names and usages unknown: never trusted.
    /// `RevocationResponseRequired`: a revocation policy that demands a
    /// positive response, which nothing here ever obtains.
    pub const REVOCATION_RESPONSE_REQUIRED: Check = Check {
        description: "Revocation response is required but missing",
        subtype: SubType::Trust,
        status: -67635, // errSecIncompleteCertRevocationCheck
        cssm: 0x80012423, // CSSMERR_APPLETP_INCOMPLETE_REVOCATION_CHECK
        fatal: false,
    };
    pub const UNREADABLE: Check = Check {
        description: "Certificate could not be read",
        subtype: SubType::Invalid,
        status: -67690, // errSecInvalidCertificateRef
        cssm: 0x80012115, // CSSMERR_TP_INVALID_CERTIFICATE
        fatal: true,
    };
}

/// What an evaluation found: the `SecTrustResultType`, and each failed check
/// with the index of the certificate it failed on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Evaluation {
    result: u32,
    failures: Vec<(usize, Check)>,
    /// The chain the evaluation built, leaf first and its anchor last when one
    /// was found - or, when none could be built, the certificates given.
    chain: Vec<Vec<u8>>,
    /// Whether the chain ended at one of the system's anchors rather than one
    /// the caller supplied.
    system_anchored: bool,
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
    leaf.ip_addresses.iter().any(|entry| *entry == address.as_slice())
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
/// anchors `legacy` names - the caller's, and the built-in roots unless it said
/// only its own - at its verify date or now.
///
/// FIXME (ACCURACY): the system anchors are Mozilla's root program
/// (`webpki-roots`), not the keychain's. The two sets largely agree for public
/// servers; a root only Apple ships is untrusted here.
fn evaluate(chain: &[Vec<u8>], options: u32, policies: &[Policy], legacy: &Legacy) -> Evaluation {
    let mut anchors = Vec::new();
    let mut custom = Vec::new();
    for der in legacy.anchors.as_deref().unwrap_or(&[]) {
        let certificate = CertificateDer::from(der.as_slice());
        // A caller's anchor that is not a certificate anchors nothing; Apple
        // refused it already when it was set, and so does this when it is used.
        if let Ok(anchor) = webpki::anchor_from_trusted_cert(&certificate) {
            anchors.push(anchor.to_owned());
            custom.push(der.as_slice());
        }
    }
    // `SecTrustSetAnchorCertificatesOnly`: false brings the system's back.
    if !legacy.anchors_only {
        anchors.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let now = legacy.verify_date.map_or_else(UnixTime::now, |seconds| {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds))
    });
    evaluate_with(chain, options, policies, &anchors, &custom, now)
}

/// [`evaluate`], against `anchors` - every one of which is treated as a
/// system anchor, as the built-in roots stand in for Apple's - at `now`.
#[cfg(test)]
fn evaluate_against(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    anchors: &[TrustAnchor<'_>],
    now: UnixTime,
) -> Evaluation {
    evaluate_with(chain, options, policies, anchors, &[], now)
}

/// Whether two anchors are the same one.
fn same_anchor(a: &TrustAnchor<'_>, b: &TrustAnchor<'_>) -> bool {
    a.subject.as_ref() == b.subject.as_ref()
        && a.subject_public_key_info.as_ref() == b.subject_public_key_info.as_ref()
}

/// The certificate of a system anchor, from the host's bundle: the built-in
/// roots carry only a name and a key, and a constructed chain ends in a
/// certificate.
fn system_anchor_certificate(anchor: &TrustAnchor<'_>) -> Option<Vec<u8>> {
    host_anchors()
        .iter()
        .find(|der| {
            let certificate = CertificateDer::from(der.as_slice());
            webpki::anchor_from_trusted_cert(&certificate)
                .is_ok_and(|candidate| same_anchor(&candidate, anchor))
        })
        .cloned()
}

/// The evaluation itself, against `anchors`, of which the first `custom.len()`
/// are the caller's, whose certificates `custom` holds.
///
/// FIXME (ACCURACY): Apple's SSL server policy also requires Certificate
/// Transparency for a system-trusted leaf (`SystemTrustedCTRequired`), checks
/// revocation where a certificate asks for it, and refuses leaves on its
/// block lists. None of those are checked here.
fn evaluate_with(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    anchors: &[TrustAnchor<'_>],
    custom: &[&[u8]],
    now: UnixTime,
) -> Evaluation {
    let unreadable = || Evaluation {
        result: result::FATAL,
        failures: vec![(0, check::UNREADABLE)],
        chain: chain.to_vec(),
        system_anchored: false,
    };
    let Some((leaf_der, rest)) = chain.split_first() else {
        return unreadable();
    };
    let leaf_certificate = CertificateDer::from(leaf_der.as_slice());
    let Ok(end_entity) = webpki::EndEntityCert::try_from(&leaf_certificate) else {
        return unreadable();
    };
    let Some(leaf) = der::certificate(leaf_der) else {
        return unreadable();
    };
    let intermediates: Vec<_> = rest
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    // Of several SSL policies the first decides; the basic policy asks
    // nothing more of a chain than any of them does.
    let ssl = policies.iter().find_map(|policy| match policy {
        Policy::Ssl { server, hostname } => Some((*server, hostname.as_deref())),
        _ => None,
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
    let mut built = chain.to_vec();
    let mut system_anchored = false;
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
                let index = anchors.iter().position(|a| same_anchor(a, path.anchor()));
                system_anchored = index.is_none_or(|i| i >= custom.len());
                built = std::iter::once(leaf_der.clone())
                    .chain(path.intermediate_certificates().map(|c| c.der().to_vec()))
                    .collect();
                let anchor = match index {
                    Some(i) if i < custom.len() => Some(custom[i].to_vec()),
                    _ => system_anchor_certificate(path.anchor()),
                };
                // The anchor, unless the caller's chain already ended in it.
                if let Some(anchor) = anchor
                    && built.last() != Some(&anchor)
                {
                    built.push(anchor);
                }
                // `SecPolicyCheckServerAuthEKU`, for a system-anchored server:
                // the leaf must name server authentication outright, and a
                // sub-CA that restricts its usages must allow it.
                if let Some((true, _)) = ssl
                    && system_anchored
                {
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
    // `SecPolicyCheckRevocationResponseRequired`: nothing here fetches or reads
    // a response, so a policy that requires one never gets it - which is what
    // Apple's reports for a certificate whose responder cannot be reached.
    let requires_response = policies.iter().any(|policy| {
        matches!(policy, Policy::Revocation { flags } if flags & REVOCATION_REQUIRE_POSITIVE_RESPONSE != 0)
    });
    if requires_response {
        failures.push((0, check::REVOCATION_RESPONSE_REQUIRED));
    }
    let result = match () {
        _ if failures.is_empty() => result::UNSPECIFIED,
        _ if failures.iter().any(|(_, check)| check.fatal) => result::FATAL,
        _ => result::RECOVERABLE,
    };
    Evaluation {
        result,
        failures,
        chain: built,
        system_anchored,
    }
}

/// The trust's evaluation, made now if it has not been since it last changed:
/// `SecTrustEvaluateIfNecessary`.
fn evaluated(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    legacy: &Legacy,
    cached: &mut Option<Evaluation>,
) -> Evaluation {
    cached
        .get_or_insert_with(|| evaluate(chain, options, policies, legacy))
        .clone()
}

/// An evaluation made afresh, as `SecTrustEvaluate` asks for. What the legacy
/// calls handed out stays valid when the answer is the same one.
fn reevaluated(
    chain: &[Vec<u8>],
    options: u32,
    policies: &[Policy],
    legacy: &mut Legacy,
    cached: &mut Option<Evaluation>,
) -> Evaluation {
    let fresh = evaluate(chain, options, policies, legacy);
    if cached.as_ref() != Some(&fresh) {
        legacy.chain = Retained::default();
        legacy.evidence = None;
    }
    *cached = Some(fresh.clone());
    fresh
}

/// `SecTrustSetNeedsEvaluation`: forget the last evaluation, and with it the
/// objects the legacy calls described it with.
fn needs_evaluation(evaluation: &mut Option<Evaluation>, legacy: &mut Legacy) {
    *evaluation = None;
    legacy.chain = Retained::default();
    legacy.evidence = None;
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
        legacy,
    }) = (unsafe { payload(trust) })
    else {
        return PARAM;
    };
    // An explicit evaluation is a fresh one, as Apple's is.
    let verdict = reevaluated(chain, *options, policies, legacy, evaluation).result;
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
        legacy,
    }) = (unsafe { payload(trust) })
    else {
        if !error.is_null() {
            // SAFETY: writable, per the caller.
            unsafe { error.write(status_error(PARAM)) };
        }
        return 0;
    };
    let evaluated = reevaluated(chain, *options, policies, legacy, evaluation);
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
        legacy,
    }) = (unsafe { payload(trust) })
    else {
        return PARAM;
    };
    let verdict = evaluated(chain, *options, policies, legacy, evaluation).result;
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
    foundation::error::create(OSSTATUS_DOMAIN, i64::from(status), status_message(status), &[])
        as CFTypeRef
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
    let mut indices: Vec<usize> = evaluation.failures.iter().map(|(index, _)| *index).collect();
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

/// The trust payload of `trust`, or `None` for anything else.
///
/// # Safety
///
/// As [`payload`].
unsafe fn trust_parts<'a>(
    trust: CFTypeRef,
) -> Option<(&'a [Vec<u8>], u32, &'a [Policy], &'a mut Option<Evaluation>, &'a mut Legacy)> {
    // SAFETY: the caller's guarantee.
    match unsafe { payload(trust) } {
        Some(Payload::Trust {
            chain,
            options,
            policies,
            evaluation,
            legacy,
        }) => Some((chain, *options, policies, evaluation, legacy)),
        _ => None,
    }
}

/// The constructed chain's certificates as objects the trust holds: the
/// caller's own for any certificate it passed in, as Apple's
/// `SecTrustCopyConstructedChain` keeps them, and new ones for the rest.
fn chain_objects<'a>(legacy: &'a mut Legacy, evaluation: &Evaluation) -> &'a [CFTypeRef] {
    if legacy.chain.0.is_empty() {
        for der in &evaluation.chain {
            // SAFETY: the inputs are live certificates the trust holds.
            let given = legacy
                .inputs
                .0
                .iter()
                .find(|&&object| unsafe { der_of(object) } == Some(der.as_slice()));
            let object = match given {
                // SAFETY: a live certificate.
                Some(&object) => unsafe { corefoundation::api::CFRetain(object) },
                None => new(Payload::Certificate(der.clone())),
            };
            legacy.chain.0.push(object);
        }
    }
    &legacy.chain.0
}

/// `CFIndex SecTrustGetCertificateCount(SecTrustRef)`: the length of the chain
/// the evaluation built, evaluating first if it has not been - one, the leaf,
/// when there is no trust to ask.
///
/// # Safety
///
/// `trust` is null or a live object.
pub unsafe extern "C" fn SecTrustGetCertificateCount(trust: CFTypeRef) -> isize {
    // SAFETY: the caller's guarantee.
    match unsafe { trust_parts(trust) } {
        Some((chain, options, policies, evaluation, legacy)) => {
            evaluated(chain, options, policies, legacy, evaluation).chain.len() as isize
        }
        None if trust.is_null() => 0,
        None => 1,
    }
}

/// `SecCertificateRef SecTrustGetCertificateAtIndex(SecTrustRef, CFIndex)`.
///
/// Not a reference of the caller's: the trust holds it. Index zero is the leaf
/// as given, with no evaluation; any other evaluates first.
///
/// # Safety
///
/// `trust` is null or a live object.
pub unsafe extern "C" fn SecTrustGetCertificateAtIndex(trust: CFTypeRef, index: isize) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    let Some((chain, options, policies, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return std::ptr::null();
    };
    if index == 0 {
        return legacy.inputs.0.first().copied().unwrap_or(std::ptr::null());
    }
    let evaluation = evaluated(chain, options, policies, legacy, evaluation);
    usize::try_from(index)
        .ok()
        .and_then(|index| chain_objects(legacy, &evaluation).get(index).copied())
        .unwrap_or(std::ptr::null())
}

/// `OSStatus SecTrustSetAnchorCertificates(SecTrustRef, CFArrayRef)`: the
/// anchors to evaluate against, and *only* those until
/// `SecTrustSetAnchorCertificatesOnly(false)` says otherwise. Null goes back to
/// the system's.
///
/// # Safety
///
/// `trust` is null or a live object; `anchors` is null or a live object.
pub unsafe extern "C" fn SecTrustSetAnchorCertificates(trust: CFTypeRef, anchors: CFTypeRef) -> OSStatus {
    use corefoundation::api::{CFArrayGetTypeID, CFGetTypeID};
    // SAFETY: the caller's guarantee.
    let Some((_, _, _, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    let given = match anchors.is_null() {
        true => None,
        // SAFETY: a live object.
        false if unsafe { CFGetTypeID(anchors) } != unsafe { CFArrayGetTypeID() } => return PARAM,
        false => {
            let mut certificates = Vec::new();
            // SAFETY: a live array.
            for certificate in unsafe { one_or_many(anchors) } {
                // SAFETY: an element of a live array.
                match unsafe { der_of(certificate) } {
                    Some(der) => certificates.push(der.to_vec()),
                    None => return PARAM,
                }
            }
            Some(certificates)
        }
    };
    legacy.anchors_only = given.is_some();
    legacy.anchors = given;
    needs_evaluation(evaluation, legacy);
    SUCCESS
}

/// `OSStatus SecTrustSetAnchorCertificatesOnly(SecTrustRef, Boolean)`.
///
/// # Safety
///
/// `trust` is null or a live object.
pub unsafe extern "C" fn SecTrustSetAnchorCertificatesOnly(trust: CFTypeRef, only: u8) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some((_, _, _, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    legacy.anchors_only = only != 0;
    needs_evaluation(evaluation, legacy);
    SUCCESS
}

/// `OSStatus SecTrustSetKeychains(SecTrustRef, CFTypeRef)`: nothing, and
/// success, as Apple's has been since 10.11 ("SecTrustSetKeychains does
/// nothing").
///
/// # Safety
///
/// None: neither argument is read.
pub unsafe extern "C" fn SecTrustSetKeychains(_trust: CFTypeRef, _keychains: CFTypeRef) -> OSStatus {
    SUCCESS
}

/// `OSStatus SecTrustSetOCSPResponse(SecTrustRef, CFTypeRef)`: one response or
/// an array of them, kept; null clears them.
///
/// # Safety
///
/// `trust` and `responses` are null or live objects.
pub unsafe extern "C" fn SecTrustSetOCSPResponse(trust: CFTypeRef, responses: CFTypeRef) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some((_, _, _, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    // SAFETY: null or a live object; anything not a `CFData` reads as none.
    legacy.responses = unsafe { one_or_many(responses) }
        .into_iter()
        .filter_map(|response| unsafe { corefoundation::collections::data(response) }.cloned())
        .collect();
    needs_evaluation(evaluation, legacy);
    SUCCESS
}

/// `OSStatus SecTrustSetSignedCertificateTimestamps(SecTrustRef, CFArrayRef)`:
/// the timestamps kept, as Apple's `CFRetainAssign` keeps them - null clears
/// them, and nothing about the value is checked.
///
/// # Safety
///
/// `trust` and `timestamps` are null or live objects.
pub unsafe extern "C" fn SecTrustSetSignedCertificateTimestamps(
    trust: CFTypeRef,
    timestamps: CFTypeRef,
) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some((_, _, _, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    needs_evaluation(evaluation, legacy);
    legacy.timestamps = match timestamps.is_null() {
        true => Retained::default(),
        // SAFETY: a live object.
        false => Retained(vec![unsafe { corefoundation::api::CFRetain(timestamps) }]),
    };
    SUCCESS
}

/// `CFArrayRef SecTrustCopyCertificateChain(SecTrustRef)`: the chain the
/// evaluation built - evaluating first if it has not been - from the leaf
/// toward the anchor, as a new array; NULL for no trust or no chain.
///
/// # Safety
///
/// `trust` is null or a live object.
pub unsafe extern "C" fn SecTrustCopyCertificateChain(trust: CFTypeRef) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    let Some((chain, options, policies, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return std::ptr::null();
    };
    let evaluation = evaluated(chain, options, policies, legacy, evaluation);
    let objects = chain_objects(legacy, &evaluation);
    if objects.is_empty() {
        return std::ptr::null();
    }
    corefoundation::collections::new_array(
        objects,
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    )
}

/// `OSStatus SecTrustSetVerifyDate(SecTrustRef, CFDateRef)`: evaluate as of
/// `date` rather than now.
///
/// # Safety
///
/// `trust` and `date` are null or live objects.
pub unsafe extern "C" fn SecTrustSetVerifyDate(trust: CFTypeRef, date: CFTypeRef) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some((_, _, _, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    let Some(seconds) = foundation::timer::interval_since_1970(date as Id) else {
        return PARAM;
    };
    legacy.verify_date = Some(seconds.max(0.0) as u64);
    needs_evaluation(evaluation, legacy);
    SUCCESS
}

/// `OSStatus SecTrustSetParameters(SecTrustRef, CSSM_TP_ACTION, CFDataRef)`:
/// Apple's bridge, which reads the `ActionFlags` of the
/// `CSSM_APPLE_TP_ACTION_DATA` - `{ uint32 Version; uint32 ActionFlags; }` - and
/// sets them as the trust's options, the two having the same meanings.
///
/// # Safety
///
/// `trust` and `data` are null or live objects.
pub unsafe extern "C" fn SecTrustSetParameters(trust: CFTypeRef, _action: u32, data: CFTypeRef) -> OSStatus {
    // SAFETY: null or a live object; anything not a `CFData` has no flags.
    let flags = unsafe { corefoundation::collections::data(data) }
        .and_then(|bytes| bytes.get(4..8))
        .map_or(0, |flags| u32::from_ne_bytes(flags.try_into().expect("four bytes")));
    // SAFETY: the caller's guarantee.
    unsafe { SecTrustSetOptions(trust, flags) }
}

/// Each failure's CSSM error at certificate `index`.
fn cssm_codes(evaluation: &Evaluation, index: usize) -> impl Iterator<Item = i32> + '_ {
    evaluation
        .failures
        .iter()
        .filter(move |(at, _)| *at == index)
        .map(|(_, check)| check.cssm as i32)
}

/// `convertCssmResultToPriority`: which CSSM error is the one to report.
fn cssm_priority(code: i32) -> u8 {
    match code as u32 {
        // CSSMERR_TP_CERT_REVOKED, CSSMERR_APPLETP_TRUST_SETTING_DENY
        0x8001210C | 0x80012425 => 1,
        // CSSMERR_APPLETP_NO_BASIC_CONSTRAINTS, ..._UNKNOWN_QUAL_CERT_STATEMENT,
        // ..._INVALID_EMPTY_SUBJECT, ..._INVALID_AUTHORITY_ID,
        // CSSMERR_TP_INVALID_CERTIFICATE, ..._UNKNOWN_CRITICAL_EXTEN
        0x80012402 | 0x80012420 | 0x8001241D | 0x80012419 | 0x80012115 | 0x80012403 => 2,
        // CSSMERR_TP_CERT_EXPIRED
        0x8001210A => 3,
        // CSSMERR_TP_NOT_TRUSTED, CSSMERR_APPLETP_CS_BAD_CERT_CHAIN_LENGTH
        0x8001212A | 0x80012411 => 4,
        _ => 5,
    }
}

/// `OSStatus SecTrustGetCssmResultCode(SecTrustRef, OSStatus *)`: zero for a
/// trusted chain, and otherwise the most telling CSSM error of any certificate
/// in it, by Apple's order of precedence.
///
/// # Safety
///
/// `trust` is null or a live object, and `out` is null or writable.
pub unsafe extern "C" fn SecTrustGetCssmResultCode(trust: CFTypeRef, out: *mut i32) -> OSStatus {
    if out.is_null() {
        return PARAM;
    }
    // SAFETY: the caller's guarantee.
    let Some((chain, options, policies, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    let evaluation = evaluated(chain, options, policies, legacy, evaluation);
    let mut code = 0;
    if !matches!(evaluation.result, result::PROCEED | result::UNSPECIFIED) {
        let mut best = u8::MAX;
        'certificates: for index in 0..evaluation.chain.len() {
            for candidate in cssm_codes(&evaluation, index) {
                let priority = cssm_priority(candidate);
                if priority < best {
                    (code, best) = (candidate, priority);
                }
                if best == 1 {
                    break 'certificates;
                }
            }
        }
    }
    // SAFETY: writable, checked above.
    unsafe { out.write(code) };
    SUCCESS
}

/// The legacy evidence for `evaluation`: `SecTrustGetEvidenceInfo`.
fn evidence(legacy: &Legacy, evaluation: &Evaluation) -> (Box<[Evidence]>, Box<[i32]>) {
    let now = legacy.verify_date.map_or_else(
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        },
        |seconds| seconds,
    ) as i64;
    // SAFETY: each input is a live certificate the trust holds.
    let inputs: Vec<&[u8]> = legacy
        .inputs
        .0
        .iter()
        .filter_map(|&object| unsafe { der_of(object) })
        .collect();
    let last = evaluation.chain.len().saturating_sub(1);
    // Each certificate's codes, then the slot Apple keeps after them for a
    // CRL reason - zero, as nothing is revoked here.
    let mut codes = Vec::new();
    let mut spans = Vec::new();
    let mut bits = Vec::new();
    for (index, der) in evaluation.chain.iter().enumerate() {
        let mut status = 0;
        if let Some(certificate) = der::certificate(der) {
            if certificate.not_after < now {
                status |= status_bits::EXPIRED;
            }
            if certificate.not_before > now {
                status |= status_bits::NOT_VALID_YET;
            }
        }
        if legacy.anchors.as_ref().is_some_and(|anchors| anchors.contains(der)) {
            status |= status_bits::IS_IN_ANCHORS;
        }
        if inputs.contains(&der.as_slice()) {
            status |= status_bits::IS_IN_INPUT_CERTS;
        }
        let self_signed = der::names(der).is_some_and(|(issuer, subject)| {
            der::normalized_name(issuer).is_some() && der::normalized_name(issuer) == der::normalized_name(subject)
        });
        if index == last && self_signed {
            status |= status_bits::IS_ROOT;
            // A system root is in the system domain's trust settings, as a
            // root trusted for everything: `SecTrustSettingsEvaluateCert`'s
            // answer for it.
            if host_anchors().contains(der) {
                status |= status_bits::TRUST_SETTINGS_TRUST | status_bits::TRUST_SETTINGS_FOUND_SYSTEM;
            }
        }
        let start = codes.len();
        codes.extend(cssm_codes(evaluation, index));
        spans.push((start, codes.len() - start));
        codes.push(0);
        bits.push(status);
    }
    let codes = codes.into_boxed_slice();
    let records = spans
        .iter()
        .zip(bits)
        .map(|(&(start, count), status_bits)| Evidence {
            status_bits,
            num_status_codes: count as u32,
            // Into the boxed slice, which never moves: the trust owns both.
            status_codes: codes[start..].as_ptr(),
            index: 0,
            dl_db_handle: [0; 2],
            unique_record: std::ptr::null(),
        })
        .collect();
    (records, codes)
}

/// `OSStatus SecTrustGetResult(SecTrustRef, SecTrustResultType *, CFArrayRef
/// *certChain, CSSM_TP_APPLE_EVIDENCE_INFO **statusChain)`.
///
/// The chain is the caller's to release; the evidence is the trust's, valid
/// until the trust is changed or released, as Apple's is.
///
/// # Safety
///
/// `trust` is null or a live object, and each out-parameter null or writable.
pub unsafe extern "C" fn SecTrustGetResult(
    trust: CFTypeRef,
    result: *mut u32,
    chain_out: *mut CFTypeRef,
    status_chain: *mut *const Evidence,
) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some((chain, options, policies, evaluation, legacy)) = (unsafe { trust_parts(trust) }) else {
        return PARAM;
    };
    let evaluation = evaluated(chain, options, policies, legacy, evaluation);
    if !result.is_null() {
        // SAFETY: writable, per the caller.
        unsafe { result.write(evaluation.result) };
    }
    if !chain_out.is_null() {
        let objects = chain_objects(legacy, &evaluation);
        let array = corefoundation::collections::new_array(
            objects,
            corefoundation::callbacks::Policy::from_type_callbacks(),
            false,
        );
        // SAFETY: writable, per the caller.
        unsafe { chain_out.write(array) };
    }
    if !status_chain.is_null() {
        if legacy.evidence.is_none() {
            legacy.evidence = Some(evidence(legacy, &evaluation));
        }
        let records = legacy.evidence.as_ref().map_or(std::ptr::null(), |(r, _)| r.as_ptr());
        // SAFETY: writable, per the caller.
        unsafe { status_chain.write(records) };
    }
    SUCCESS
}

/// `SecPolicyRef SecPolicyCreateRevocation(CFOptionFlags)`: null for no flags
/// or for a flag past the seven defined, as Apple's.
///
/// # Safety
///
/// None beyond being called as the C function it is.
pub unsafe extern "C" fn SecPolicyCreateRevocation(flags: u64) -> CFTypeRef {
    if flags == 0 || flags >> 7 != 0 {
        return std::ptr::null();
    }
    new(Payload::Policy(Policy::Revocation { flags }))
}

/// `CFDictionaryRef SecPolicyCopyProperties(SecPolicyRef)`: the policy's OID
/// under `kSecPolicyOid`, its host name under `kSecPolicyName` when it checks
/// one, and `kSecPolicyClient` true for the client side of SSL - the SSL OID
/// either way, as Apple's keeps it for the ABI.
///
/// # Safety
///
/// `policy` is null or a live object.
pub unsafe extern "C" fn SecPolicyCopyProperties(policy: CFTypeRef) -> CFTypeRef {
    use foundation::notification::name_object;
    // SAFETY: the caller's guarantee.
    let Some(Payload::Policy(policy)) = (unsafe { payload(policy) }) else {
        return std::ptr::null();
    };
    let key = |text: &'static str| name_object(text) as usize as CFTypeRef;
    let oid = match policy {
        Policy::BasicX509 => "1.2.840.113635.100.1.2",
        Policy::Ssl { .. } => "1.2.840.113635.100.1.3",
        Policy::Revocation { .. } => "1.2.840.113635.100.1.21",
    };
    let mut pairs = vec![(key("SecPolicyOid"), key(oid))];
    let mut made = Vec::new();
    if let Policy::Ssl { server, hostname } = policy {
        if let Some(hostname) = hostname {
            let name = foundation::string::from_str(hostname) as CFTypeRef;
            pairs.push((key("SecPolicyName"), name));
            made.push(name);
        }
        if !*server {
            pairs.push((key("SecPolicyClient"), corefoundation::collections::boolean(true)));
        }
    }
    let policy = corefoundation::callbacks::Policy::from_type_callbacks();
    let dictionary = corefoundation::collections::new_dictionary(&pairs, policy, policy, false);
    for object in made {
        // SAFETY: the dictionary took its own reference.
        unsafe { corefoundation::api::CFRelease(object) };
    }
    dictionary
}

/// `CFDataRef SecCertificateCopyNormalizedIssuerSequence(SecCertificateRef)`:
/// the issuer, normalized as `createNormalizedX501Name` does and wrapped back
/// in its `SEQUENCE`. What a keychain search by `kSecAttrIssuer` matches
/// against.
///
/// # Safety
///
/// `certificate` is null or a live object.
pub unsafe extern "C" fn SecCertificateCopyNormalizedIssuerSequence(certificate: CFTypeRef) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    let normalized = unsafe { der_of(certificate) }
        .and_then(der::names)
        .and_then(|(issuer, _)| der::normalized_name(issuer));
    match normalized {
        Some(content) => corefoundation::collections::new_data(der::sequence(&content)),
        None => std::ptr::null(),
    }
}

/// `CFDataRef SecCertificateCopyNormalizedSubjectSequence(SecCertificateRef)`.
///
/// # Safety
///
/// `certificate` is null or a live object.
pub unsafe extern "C" fn SecCertificateCopyNormalizedSubjectSequence(certificate: CFTypeRef) -> CFTypeRef {
    // SAFETY: the caller's guarantee.
    let normalized = unsafe { der_of(certificate) }
        .and_then(der::names)
        .and_then(|(_, subject)| der::normalized_name(subject));
    match normalized {
        Some(content) => corefoundation::collections::new_data(der::sequence(&content)),
        None => std::ptr::null(),
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
        "SecCertificateGetTypeID" => SecCertificateGetTypeID,
        "SecPolicyGetTypeID" => SecPolicyGetTypeID,
        "SecTrustGetTypeID" => SecTrustGetTypeID,
        "SecTrustGetCertificateCount" => SecTrustGetCertificateCount,
        "SecTrustGetCertificateAtIndex" => SecTrustGetCertificateAtIndex,
        "SecTrustSetAnchorCertificates" => SecTrustSetAnchorCertificates,
        "SecTrustSetAnchorCertificatesOnly" => SecTrustSetAnchorCertificatesOnly,
        "SecTrustSetKeychains" => SecTrustSetKeychains,
        "SecTrustSetOCSPResponse" => SecTrustSetOCSPResponse,
        "SecTrustSetSignedCertificateTimestamps" => SecTrustSetSignedCertificateTimestamps,
        "SecTrustCopyCertificateChain" => SecTrustCopyCertificateChain,
        "SecTrustSetVerifyDate" => SecTrustSetVerifyDate,
        "SecTrustSetParameters" => SecTrustSetParameters,
        "SecTrustGetCssmResultCode" => SecTrustGetCssmResultCode,
        "SecTrustGetResult" => SecTrustGetResult,
        "SecPolicyCreateRevocation" => SecPolicyCreateRevocation,
        "SecPolicyCopyProperties" => SecPolicyCopyProperties,
        "SecCertificateCopyNormalizedIssuerSequence" => SecCertificateCopyNormalizedIssuerSequence,
        "SecCertificateCopyNormalizedSubjectSequence" => SecCertificateCopyNormalizedSubjectSequence,
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
        for name in ["server.rosemary.test", "SERVER.rosemary.test", "server.rosemary.test.", "127.0.0.1"] {
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
        for name in ["a.b.cdn.rosemary.test", "cdn.rosemary.test", "other.rosemary.test", "127.0.0.2"] {
            let evaluation = ssl("server", server(name), JUNE_2025);
            assert_eq!(evaluation.result, result::RECOVERABLE, "{name}");
            assert_eq!(failures(&evaluation), [(0, check::SSL_HOSTNAME)], "{name}");
        }
    }

    #[test]
    fn dns_matching_follows_apples_rules() {
        assert!(dns_match("www.example.com", "*.example.com"));
        assert!(!dns_match("example.com", "*.com"), "not before a single-label TLD");
        assert!(!dns_match("www.example.com", "w*.example.com"), "no partial-label wildcards");
        assert!(!dns_match("www.example.com", "www.*.com"), "only the left-most label");
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
        assert_eq!(failures(&evaluation), [(0, check::SYSTEM_TRUST_VALIDITY_PERIOD)]);
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
            assert_eq!(SecTrustCreateWithCertificates(certificate, policy, &mut trust), SUCCESS);
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

    /// Apple's `TrustInterfaceTests` certificates (`TrustInterfaceTests_data.h`):
    /// store.apple.com, valid March 2018 to March 2019, and the DigiCert EV
    /// server CA that issued it.
    fn apple_chain() -> (CFTypeRef, CFTypeRef) {
        foundation::bootstrap();
        let make = |bytes: &[u8]| {
            let data = data(bytes);
            // SAFETY: a `CFData` this test made.
            let certificate = unsafe { SecCertificateCreateWithData(std::ptr::null(), data) };
            // SAFETY: as above.
            unsafe { corefoundation::api::CFRelease(data) };
            assert!(!certificate.is_null());
            certificate
        };
        (
            make(include_bytes!("testdata/apple/store.apple.com.der")),
            make(include_bytes!("testdata/apple/digicert-ev-server-ca.der")),
        )
    }

    fn array(values: &[CFTypeRef]) -> CFTypeRef {
        corefoundation::collections::new_array(
            values,
            corefoundation::callbacks::Policy::from_type_callbacks(),
            false,
        )
    }

    /// `testCreateWithCertificates`.
    #[test]
    fn test_create_with_certificates() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(0, std::ptr::null());
            let boolean = corefoundation::collections::boolean(true);
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(boolean, policy, &mut trust), PARAM);
            assert_eq!(SecTrustCreateWithCertificates(cert0, boolean, &mut trust), PARAM);
            let datas = array(&[data(include_bytes!("testdata/apple/store.apple.com.der"))]);
            assert_eq!(SecTrustCreateWithCertificates(datas, policy, &mut trust), PARAM);
            assert_eq!(SecTrustCreateWithCertificates(certs, datas, &mut trust), PARAM);
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            for object in [trust, datas, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `testGetCertificate`: counting evaluates, and index zero is the leaf as
    /// given. Apple's expects three - the leaf, the CA, and DigiCert's EV root -
    /// except on bridgeOS, "which has no system anchors"; that root is in
    /// neither Mozilla's program nor the host's bundle, so here the chain stops
    /// at the CA as it does there.
    #[test]
    fn test_get_certificate() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(0, std::ptr::null());
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            assert_eq!(SecTrustGetCertificateCount(trust), 2, "cert count is 2");
            assert_eq!(SecTrustGetCertificateAtIndex(trust, 0), cert0, "cert 0 is leaf");
            assert_eq!(SecTrustGetCertificateAtIndex(trust, 1), cert1, "the caller's own CA");
            assert!(SecTrustGetCertificateAtIndex(trust, 2).is_null());
            for object in [trust, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `testCopyCertificateChain`, with the bridgeOS count for the reason
    /// [`test_get_certificate`] gives.
    #[test]
    fn test_copy_certificate_chain() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(0, std::ptr::null());
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            let chain = SecTrustCopyCertificateChain(trust);
            assert!(!chain.is_null());
            assert_eq!(corefoundation::api::CFArrayGetCount(chain), 2, "cert count is 2");
            assert!(corefoundation::api::CFEqual(cert0, corefoundation::api::CFArrayGetValueAtIndex(chain, 0)) != 0);
            assert!(corefoundation::api::CFEqual(cert1, corefoundation::api::CFArrayGetValueAtIndex(chain, 1)) != 0);
            assert!(SecTrustCopyCertificateChain(std::ptr::null()).is_null());
            for object in [chain, trust, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// The setter half of `testSerialization`'s SCT step: any array, or none.
    #[test]
    fn signed_certificate_timestamps_are_kept_and_cleared() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(0, std::ptr::null());
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            let scts = array(&[]);
            assert_eq!(SecTrustSetSignedCertificateTimestamps(trust, scts), SUCCESS);
            assert_eq!(SecTrustSetSignedCertificateTimestamps(trust, std::ptr::null()), SUCCESS);
            assert_eq!(SecTrustSetSignedCertificateTimestamps(std::ptr::null(), scts), PARAM);
            for object in [scts, trust, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `testAnchorCerts`, with the bridgeOS expectations wherever the system's
    /// anchors decide, for the reason [`test_get_certificate`] gives.
    #[test]
    fn test_anchor_certs() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(0, std::ptr::null());
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            // Apr 14 2018, 12:00:00 UTC.
            let date = foundation::timer::date_since_1970(1_523_707_200.0);
            assert_eq!(SecTrustSetVerifyDate(trust, date as CFTypeRef), SUCCESS, "set date");

            let anchors = array(&[cert1]);
            assert_eq!(SecTrustSetAnchorCertificates(trust, anchors), SUCCESS, "set anchors");
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 1, "evaluate trust");
            assert_eq!(SecTrustGetCertificateCount(trust), 2, "cert count is 2");
            corefoundation::api::CFRelease(anchors);

            let anchors = array(&[]);
            assert_eq!(SecTrustSetAnchorCertificates(trust, anchors), SUCCESS, "set empty anchors list");
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 0, "evaluate trust");
            corefoundation::api::CFRelease(anchors);

            assert_eq!(SecTrustSetAnchorCertificatesOnly(trust, 0), SUCCESS);
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 0, "no system anchor for it");
            assert_eq!(SecTrustSetAnchorCertificatesOnly(trust, 1), SUCCESS);
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 0, "evaluate trust");

            assert_eq!(SecTrustSetAnchorCertificates(trust, std::ptr::null()), SUCCESS, "reset anchors");
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 0, "no system anchor for it");
            assert_eq!(SecTrustGetCertificateCount(trust), 2, "cert count is 2");

            let datas = array(&[data(include_bytes!("testdata/apple/store.apple.com.der"))]);
            assert_eq!(SecTrustSetAnchorCertificates(trust, datas), PARAM, "set anchor with data instead of certificate");
            assert_eq!(SecTrustEvaluateWithError(trust, std::ptr::null_mut()), 0);
            assert_eq!(SecTrustGetCertificateCount(trust), 2, "cert count is 2");
            for object in [datas, trust, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `testSetOCSPResponses`.
    #[test]
    fn test_set_ocsp_responses() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let hostname = foundation::string::from_str("example.com") as CFTypeRef;
            let policy = SecPolicyCreateSSL(1, hostname);
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(cert0, policy, &mut trust), SUCCESS);
            let response = data(&[0; 64]);
            assert_eq!(SecTrustSetOCSPResponse(std::ptr::null(), response), PARAM, "param 1 check OK");
            assert_eq!(SecTrustSetOCSPResponse(trust, std::ptr::null()), SUCCESS, "param 2 check OK");
            assert_eq!(SecTrustSetOCSPResponse(trust, response), SUCCESS, "SecTrustSetOCSPResponse OK");
            for object in [response, trust, policy, hostname, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `PolicyInterfaceTests`' `testCopyProperties`.
    #[test]
    fn test_copy_properties() {
        foundation::bootstrap();
        let text = |object: CFTypeRef| {
            // SAFETY: null or a live string.
            unsafe { corefoundation::string::as_string(object) }.map(|s| String::from_utf16_lossy(&s.utf16()))
        };
        // SAFETY: objects this test made.
        unsafe {
            let hostname = foundation::string::from_str("www.google.com") as CFTypeRef;
            let policy = SecPolicyCreateSSL(1, hostname);
            let properties = SecPolicyCopyProperties(policy);
            assert!(!properties.is_null(), "copy policy properties");
            let get = |key: &'static str| {
                corefoundation::api::CFDictionaryGetValue(
                    properties,
                    foundation::notification::name_object(key) as usize as CFTypeRef,
                )
            };
            assert_eq!(text(get("SecPolicyName")).as_deref(), Some("www.google.com"), "has policy name");
            assert_eq!(
                get("SecPolicyOid"),
                foundation::notification::name_object("1.2.840.113635.100.1.3") as usize as CFTypeRef,
                "has SSL policy"
            );
            assert!(get("SecPolicyClient").is_null(), "a server's policy");
            for object in [properties, policy, hostname] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `SecPolicyCreateRevocation` refuses no flags and undefined ones, and a
    /// policy that requires a positive response fails without one.
    #[test]
    fn a_revocation_policy_takes_only_defined_flags() {
        foundation::bootstrap();
        // SAFETY: plain calls, and objects this test made.
        unsafe {
            assert!(SecPolicyCreateRevocation(0).is_null());
            assert!(SecPolicyCreateRevocation(1 << 7).is_null());
            let policy = SecPolicyCreateRevocation(3);
            assert!(!policy.is_null());
            assert_eq!(corefoundation::api::CFGetTypeID(policy), SecPolicyGetTypeID());
            corefoundation::api::CFRelease(policy);
        }
        let root = pki("ca");
        let root = CertificateDer::from(root.as_slice());
        let anchor = webpki::anchor_from_trusted_cert(&root).expect("the test root");
        let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(JUNE_2025));
        let required = Policy::Revocation { flags: 3 | REVOCATION_REQUIRE_POSITIVE_RESPONSE };
        let evaluation = evaluate_against(&[pki("server")], 0, &[server("server.rosemary.test"), required], &[anchor.clone()], at);
        assert_eq!(failures(&evaluation), [(0, check::REVOCATION_RESPONSE_REQUIRED)]);
        let best_effort = Policy::Revocation { flags: 3 };
        let evaluation = evaluate_against(&[pki("server")], 0, &[server("server.rosemary.test"), best_effort], &[anchor], at);
        assert_eq!(evaluation.result, result::UNSPECIFIED);
    }

    /// Certificates, policies and trusts are three CoreFoundation types.
    #[test]
    fn each_kind_of_object_is_its_own_type() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made.
        unsafe {
            let policy = SecPolicyCreateBasicX509();
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(cert0, policy, &mut trust), SUCCESS);
            let ids = [SecCertificateGetTypeID(), SecPolicyGetTypeID(), SecTrustGetTypeID()];
            assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
            assert_eq!(corefoundation::api::CFGetTypeID(cert0), ids[0]);
            assert_eq!(corefoundation::api::CFGetTypeID(policy), ids[1]);
            assert_eq!(corefoundation::api::CFGetTypeID(trust), ids[2]);
            for object in [trust, policy, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// The legacy result calls, on a chain the caller anchored: the chain comes
    /// back as the caller's own objects with evidence for each, and a failure
    /// is reported as its CSSM error.
    #[test]
    fn the_legacy_result_describes_the_chain() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made and writable out-parameters.
        unsafe {
            let certs = array(&[cert0, cert1]);
            let policy = SecPolicyCreateSSL(1, std::ptr::null());
            let mut trust = std::ptr::null();
            assert_eq!(SecTrustCreateWithCertificates(certs, policy, &mut trust), SUCCESS);
            let anchors = array(&[cert1]);
            assert_eq!(SecTrustSetAnchorCertificates(trust, anchors), SUCCESS);
            let date = foundation::timer::date_since_1970(1_523_707_200.0);
            assert_eq!(SecTrustSetVerifyDate(trust, date as CFTypeRef), SUCCESS);

            let (mut verdict, mut chain, mut evidence) = (0, std::ptr::null(), std::ptr::null());
            assert_eq!(SecTrustGetResult(trust, &mut verdict, &mut chain, &mut evidence), SUCCESS);
            assert_eq!(verdict, result::UNSPECIFIED);
            assert_eq!(corefoundation::api::CFArrayGetCount(chain), 2);
            assert_eq!(corefoundation::api::CFArrayGetValueAtIndex(chain, 0), cert0);
            assert_eq!(corefoundation::api::CFArrayGetValueAtIndex(chain, 1), cert1);
            let records = std::slice::from_raw_parts(evidence, 2);
            assert_eq!(records[0].status_bits, status_bits::IS_IN_INPUT_CERTS);
            assert_eq!(records[0].num_status_codes, 0);
            assert_eq!(records[1].status_bits, status_bits::IS_IN_INPUT_CERTS | status_bits::IS_IN_ANCHORS);
            let mut code = -1;
            assert_eq!(SecTrustGetCssmResultCode(trust, &mut code), SUCCESS);
            assert_eq!(code, 0);
            corefoundation::api::CFRelease(chain);

            // Now, long after the leaf expired.
            assert_eq!(SecTrustSetVerifyDate(trust, foundation::timer::date_since_1970(1_700_000_000.0) as CFTypeRef), SUCCESS);
            assert_eq!(SecTrustGetResult(trust, &mut verdict, std::ptr::null_mut(), &mut evidence), SUCCESS);
            assert_eq!(verdict, result::RECOVERABLE);
            let records = std::slice::from_raw_parts(evidence, 2);
            assert_eq!(records[0].status_bits & status_bits::EXPIRED, status_bits::EXPIRED);
            assert_eq!(records[0].num_status_codes, 1);
            assert_eq!(*records[0].status_codes as u32, 0x8001210A);
            assert_eq!(SecTrustGetCssmResultCode(trust, &mut code), SUCCESS);
            assert_eq!(code as u32, 0x8001210A, "CSSMERR_TP_CERT_EXPIRED");
            for object in [anchors, trust, policy, certs, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// `createNormalizedX501Name` on a real issuer: PrintableString values
    /// upper-cased, and the result a `SEQUENCE` again.
    #[test]
    fn the_normalized_issuer_is_upper_cased() {
        let (cert0, cert1) = apple_chain();
        // SAFETY: objects this test made.
        unsafe {
            let issuer = SecCertificateCopyNormalizedIssuerSequence(cert0);
            let subject = SecCertificateCopyNormalizedSubjectSequence(cert1);
            assert!(!issuer.is_null() && !subject.is_null());
            let bytes = corefoundation::collections::data(issuer).expect("a CFData").clone();
            assert_eq!(bytes[0], 0x30);
            let text = String::from_utf8_lossy(&bytes);
            assert!(text.contains("DIGICERT SHA2 EXTENDED VALIDATION SERVER CA"), "{text}");
            // The leaf's issuer is its issuer's subject, normalized alike.
            assert_eq!(Some(&bytes), corefoundation::collections::data(subject).map(|d| &*d));
            for object in [issuer, subject, cert0, cert1] {
                corefoundation::api::CFRelease(object);
            }
        }
    }
}
