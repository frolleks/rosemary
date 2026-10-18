pub mod codesign;
mod constants;
mod der;
pub mod keychain;
pub mod seckeychain;
pub mod sectask;
pub mod trust;
pub mod trustsettings;

exports::group! {
    codesign,
    keychain,
    seckeychain,
    sectask,
    trust,
    trustsettings,
}

/// The `kSec*` key globals, each a cell holding an `NSString *`.
pub fn data_symbols() -> Vec<(String, u64)> {
    foundation::bootstrap();
    // Apple's constants, less any the keychain module lists itself.
    let constants = constants::CONSTANTS
        .iter()
        .filter(|(symbol, _)| !keychain::KEYS.iter().any(|(s, _)| s == symbol));
    let mut symbols: Vec<_> = keychain::KEYS
        .iter()
        .chain(constants)
        .map(|(symbol, text)| {
            (
                (*symbol).to_string(),
                corefoundation::base::global_cell(
                    symbol,
                    foundation::notification::name_object(text),
                ),
            )
        })
        .collect();
    // `const SecRandomRef kSecRandomDefault = NULL`: a word the guest reads.
    let random = "_kSecRandomDefault";
    symbols.push((
        random.to_string(),
        corefoundation::base::global_cell(random, 0),
    ));
    symbols
}
