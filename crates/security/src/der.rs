//! Just enough DER to read the parts of a certificate the trust policies look
//! at: the validity dates, the subject's names, and the extended key usage
//! and subject alternative name extensions.
//!
//! `webpki` checks the chain - signatures, dates, constraints - but keeps
//! these to itself, and Apple's SSL policy needs them by name: the leaf's
//! validity period against a maximum, its usages against the server-auth
//! purpose, and its DNS names against the host the caller asked for.

/// One tag-length-value.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// The next TLV off the front of `input`, or `None` for anything malformed.
///
/// Single-byte tags only, which is every tag an X.509 certificate uses.
fn next<'a>(input: &mut &'a [u8]) -> Option<Tlv<'a>> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let length = match first {
        short if short < 0x80 => usize::from(short),
        0x81..=0x84 => {
            let count = usize::from(first & 0x7f);
            if rest.len() < count {
                return None;
            }
            let (bytes, after) = rest.split_at(count);
            rest = after;
            bytes.iter().fold(0usize, |n, &b| (n << 8) | usize::from(b))
        }
        _ => return None,
    };
    if rest.len() < length {
        return None;
    }
    let (value, after) = rest.split_at(length);
    *input = after;
    Some(Tlv { tag, value })
}

/// The next TLV, which must carry `tag`.
fn expect<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let tlv = next(input)?;
    (tlv.tag == tag).then_some(tlv.value)
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// The content bytes of the OIDs read here.
pub mod oid {
    /// `id-at-commonName`, 2.5.4.3.
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// `id-at-organizationalUnitName`, 2.5.4.11.
    pub const ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
    /// `id-at-organizationName`, 2.5.4.10.
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    /// `id-at-description`, 2.5.4.13.
    pub const DESCRIPTION: &[u8] = &[0x55, 0x04, 0x0d];
    /// `id-ce-extKeyUsage`, 2.5.29.37.
    pub const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// `id-ce-subjectAltName`, 2.5.29.17.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// `anyExtendedKeyUsage`, 2.5.29.37.0.
    pub const ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    /// `id-kp-serverAuth`, 1.3.6.1.5.5.7.3.1.
    pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// `id-kp-clientAuth`, 1.3.6.1.5.5.7.3.2.
    pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    /// Microsoft Server Gated Crypto, 1.3.6.1.4.1.311.10.3.3.
    pub const MICROSOFT_SGC: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x03];
    /// Netscape Server Gated Crypto, 2.16.840.1.113730.4.1.
    pub const NETSCAPE_SGC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01];
}

/// What the trust policies read out of one certificate.
#[derive(Debug, Default)]
pub struct Certificate<'a> {
    /// Seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// Each attribute of the subject, in the order it is encoded: the type's
    /// OID content bytes and the value as text.
    pub subject: Vec<(&'a [u8], String)>,
    /// The extended key usage purposes, or `None` when the extension is absent.
    pub extended_key_usage: Option<Vec<&'a [u8]>>,
    /// `dNSName` entries of the subject alternative name.
    pub dns_names: Vec<String>,
    /// `rfc822Name` entries.
    pub emails: Vec<String>,
    /// `iPAddress` entries, four or sixteen bytes each.
    pub ip_addresses: Vec<&'a [u8]>,
}

/// Read `der`, or `None` when it is not a certificate this can read.
pub fn certificate(der: &[u8]) -> Option<Certificate<'_>> {
    let mut input = der;
    let mut outer = expect(&mut input, SEQUENCE)?;
    let mut tbs = expect(&mut outer, SEQUENCE)?;
    let mut field = next(&mut tbs)?;
    // `[0] EXPLICIT Version DEFAULT v1`.
    if field.tag == 0xa0 {
        field = next(&mut tbs)?;
    }
    // `serialNumber`, then `signature`, `issuer`, `validity`, `subject`.
    if field.tag != 0x02 {
        return None;
    }
    expect(&mut tbs, SEQUENCE)?;
    expect(&mut tbs, SEQUENCE)?;
    let mut validity = expect(&mut tbs, SEQUENCE)?;
    let not_before = time(next(&mut validity)?)?;
    let not_after = time(next(&mut validity)?)?;
    let subject = name(expect(&mut tbs, SEQUENCE)?)?;
    let mut certificate = Certificate {
        not_before,
        not_after,
        subject,
        ..Certificate::default()
    };
    expect(&mut tbs, SEQUENCE)?; // subjectPublicKeyInfo
    while !tbs.is_empty() {
        let field = next(&mut tbs)?;
        // `[3] EXPLICIT Extensions`; the unique identifiers are skipped.
        if field.tag == 0xa3 {
            let mut wrapper = field.value;
            extensions(expect(&mut wrapper, SEQUENCE)?, &mut certificate)?;
        }
    }
    Some(certificate)
}

fn extensions<'a>(mut list: &'a [u8], into: &mut Certificate<'a>) -> Option<()> {
    while !list.is_empty() {
        let mut extension = expect(&mut list, SEQUENCE)?;
        let id = expect(&mut extension, OID)?;
        let mut tlv = next(&mut extension)?;
        if tlv.tag == BOOLEAN {
            tlv = next(&mut extension)?;
        }
        if tlv.tag != OCTET_STRING {
            return None;
        }
        let mut value = tlv.value;
        match id {
            oid::EXTENDED_KEY_USAGE => {
                let mut purposes = expect(&mut value, SEQUENCE)?;
                let mut found = Vec::new();
                while !purposes.is_empty() {
                    found.push(expect(&mut purposes, OID)?);
                }
                into.extended_key_usage = Some(found);
            }
            oid::SUBJECT_ALT_NAME => {
                let mut names = expect(&mut value, SEQUENCE)?;
                while !names.is_empty() {
                    let general = next(&mut names)?;
                    match general.tag {
                        // `[1] IMPLICIT IA5String`
                        0x81 => into
                            .emails
                            .push(String::from_utf8_lossy(general.value).into()),
                        // `[2] IMPLICIT IA5String`
                        0x82 => into
                            .dns_names
                            .push(String::from_utf8_lossy(general.value).into()),
                        // `[7] IMPLICIT OCTET STRING`
                        0x87 => into.ip_addresses.push(general.value),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// A `Name`: a sequence of sets of type-and-value pairs.
fn name(mut sequence: &[u8]) -> Option<Vec<(&[u8], String)>> {
    let mut attributes = Vec::new();
    while !sequence.is_empty() {
        let mut set = expect(&mut sequence, SET)?;
        while !set.is_empty() {
            let mut pair = expect(&mut set, SEQUENCE)?;
            let kind = expect(&mut pair, OID)?;
            let value = next(&mut pair)?;
            attributes.push((kind, text(value.tag, value.value)));
        }
    }
    Some(attributes)
}

/// A directory string as text.
fn text(tag: u8, bytes: &[u8]) -> String {
    match tag {
        // BMPString: UTF-16, big-endian.
        0x1e => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        // UniversalString: UTF-32, big-endian.
        0x1c => bytes
            .chunks_exact(4)
            .filter_map(|quad| {
                char::from_u32(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
            })
            .collect(),
        // T61String, read as Latin-1, which is what it holds in practice.
        0x14 => bytes.iter().map(|&b| char::from(b)).collect(),
        // UTF8String, PrintableString, IA5String and the rest.
        _ => String::from_utf8_lossy(bytes).into(),
    }
}

/// A `Time` as seconds since the Unix epoch.
fn time(tlv: Tlv<'_>) -> Option<i64> {
    let text = std::str::from_utf8(tlv.value).ok()?;
    let digits = text.strip_suffix('Z')?;
    let (year, rest) = match tlv.tag {
        // Two-digit years: 50 and above are the 1900s (RFC 5280, 4.1.2.5.1).
        UTC_TIME if digits.len() == 12 => {
            let yy: i64 = digits[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        GENERALIZED_TIME if digits.len() == 14 => (digits[..4].parse().ok()?, &digits[4..]),
        _ => return None,
    };
    let field = |at: usize| rest.get(at..at + 2)?.parse::<i64>().ok();
    let (month, day) = (field(0)?, field(2)?);
    let (hour, minute, second) = (field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `SecCertificateCopySubjectSummary`: every instance of the most telling
/// kind of subject attribute - a common name, then an organizational unit,
/// then an organization, then anything printable - joined in reverse order;
/// and without a common name, the first email address or else DNS name the
/// certificate names instead.
pub fn subject_summary(certificate: &Certificate<'_>) -> Option<String> {
    let rank = |kind: &[u8]| match kind {
        oid::COMMON_NAME => 3,
        oid::ORGANIZATIONAL_UNIT => 2,
        oid::ORGANIZATION => 1,
        _ => 0,
    };
    let best = certificate
        .subject
        .iter()
        .filter(|(kind, _)| *kind != oid::DESCRIPTION)
        .map(|(kind, _)| rank(kind))
        .max();
    let mut summary = best.map(|best| {
        let mut parts: Vec<&str> = certificate
            .subject
            .iter()
            .filter(|(kind, _)| *kind != oid::DESCRIPTION && rank(kind) == best)
            .map(|(_, value)| value.as_str())
            .collect();
        parts.reverse();
        parts.join(", ")
    });
    if best != Some(3)
        && let Some(name) = certificate.emails.first().or(certificate.dns_names.first())
    {
        summary = Some(name.clone());
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_certificate_reads_back_its_fields() {
        let der = include_bytes!("testdata/pki/server.rosemary.test.der");
        let certificate = certificate(der).expect("a certificate");
        // 2025-01-01T00:00:00Z and 2025-10-01T00:00:00Z.
        assert_eq!(certificate.not_before, 1_735_689_600);
        assert_eq!(certificate.not_after, 1_759_276_800);
        assert_eq!(
            certificate.dns_names,
            ["server.rosemary.test", "*.cdn.rosemary.test"]
        );
        assert_eq!(certificate.ip_addresses, [&[127u8, 0, 0, 1][..]]);
        assert_eq!(
            certificate.extended_key_usage.as_deref(),
            Some(&[oid::SERVER_AUTH][..])
        );
        assert_eq!(
            subject_summary(&certificate).as_deref(),
            Some("server.rosemary.test")
        );
    }

    #[test]
    fn a_certificate_without_the_extension_has_no_usages() {
        let der = include_bytes!("testdata/pki/no-eku.rosemary.test.der");
        assert!(
            certificate(der)
                .expect("a certificate")
                .extended_key_usage
                .is_none()
        );
    }

    #[test]
    fn days_are_counted_from_the_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2020, 9, 1) * 86_400, 1_598_918_400);
    }
}
