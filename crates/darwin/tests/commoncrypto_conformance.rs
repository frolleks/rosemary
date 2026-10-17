//! CommonCrypto conformance: `CommonRandom.c` from Apple's CommonCrypto
//! regression suite (apple-oss-distributions/CommonCrypto,
//! `CCRegression/CommonCrypto/`), ported and run against what a guest binds.
//!
//! The test's own first calls are to the corecrypto generator states
//! (`ccDevRandomGetRngState`, `ccDRBGGetRngState`, `ccrng_generate`), which are
//! SPI. The adaptation keeps every assertion and generates through
//! `CCRandomGenerateBytes` where upstream generates through those states:
//! `CommonRandom.c`'s `CCRandomGenerateBytes` generates from that same state.
//!
//! ```text
//! cargo test -p darwin --test commoncrypto_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]

mod conformance;

use std::ffi::{c_int, c_void};

use conformance::{Case, Import, Kind, Stop, T, import, imports};

const UPSTREAM: &str = "CommonCrypto main CCRegression/CommonCrypto/CommonRandom.c";

const K_CC_SUCCESS: c_int = 0;

type CopyBytesFn = unsafe extern "C" fn(*const c_void, *mut c_void, usize) -> c_int;
type GenerateBytesFn = unsafe extern "C" fn(*mut c_void, usize) -> c_int;
type UniformFn = unsafe extern "C" fn(u64, *mut u64) -> c_int;
type GetRngStateFn = unsafe extern "C" fn() -> *mut c_void;
type RngGenerateFn = unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int;

const K_TEST_TEST_COUNT: usize = 1000;
const BUFMAX: usize = K_TEST_TEST_COUNT + 16;

/// `memcmp(a, b, len)`, as upstream's `ok(memcmp(..), "Buffers aren't the
/// same")` reads it.
fn differ(a: &[u8], b: &[u8], len: usize) -> bool {
    a[..len] != b[..len]
}

/// The generators upstream names, as a guest reads them: the value of the
/// `kCCRandomDefault` and `kCCRandomDevRandom` globals.
fn generator(t: &mut T, symbol: &'static str) -> *const c_void {
    let global: Import<*const *const c_void> = import(symbol);
    match global.get() {
        // SAFETY: the address of a `const CCRandomRef`.
        Ok(global) => unsafe { *global },
        Err(_) => {
            // `CommonRandom.c`'s `CCRandomCopyBytes` ignores its generator,
            // so null stands in, and the global is noted as unbound.
            t.note(format!("{symbol} unbound: NULL passed in its place"));
            std::ptr::null()
        }
    }
}

/// `CommonRandom`, as written.
fn common_random(t: &mut T) -> Result<(), Stop> {
    imports! {
        dev_random_state: GetRngStateFn = "_ccDevRandomGetRngState";
        drbg_state: GetRngStateFn = "_ccDRBGGetRngState";
        rng_generate: RngGenerateFn = "_ccrng_generate";
        copy_bytes: CopyBytesFn = "_CCRandomCopyBytes";
        generate_bytes: GenerateBytesFn = "_CCRandomGenerateBytes";
    }
    // SAFETY: the corecrypto states, which take nothing.
    let dev_random = unsafe { dev_random_state.get()?() };
    t.check(!dev_random.is_null(), || "Dev random first state ok".into());
    let drbg = unsafe { drbg_state.get()?() };
    t.check(!drbg.is_null(), || "DRBG first state ok".into());
    if dev_random.is_null() || drbg.is_null() {
        return Err(Stop::Fail("no generator state".into()));
    }
    let default = generator(t, "_kCCRandomDefault");
    let dev = generator(t, "_kCCRandomDevRandom");
    let mut bufs = [[0u8; BUFMAX]; 6];
    for i in 0..K_TEST_TEST_COUNT {
        let len = i + 16;
        let [b1, b2, b3, b4, b5, b6] = &mut bufs;
        // SAFETY: each buffer is `BUFMAX` bytes, and `len` is less.
        unsafe {
            random_success(t, copy_bytes.get()?(default, b1.as_mut_ptr().cast(), len));
            random_success(t, copy_bytes.get()?(dev, b2.as_mut_ptr().cast(), len));
            random_success(
                t,
                copy_bytes.get()?(std::ptr::null(), b3.as_mut_ptr().cast(), len),
            );
            random_success(
                t,
                rng_generate.get()?(dev_random, len, b4.as_mut_ptr().cast()),
            );
            random_success(t, rng_generate.get()?(drbg, len, b5.as_mut_ptr().cast()));
            random_success(t, generate_bytes.get()?(b6.as_mut_ptr().cast(), len));
        }
        all_differ(t, &bufs, len);
    }
    bad_inputs(t, copy_bytes, generate_bytes, default, dev)
}

/// `CommonRandom`, generating through `CCRandomGenerateBytes` where upstream
/// generates through the corecrypto states.
fn common_random_bound(t: &mut T) -> Result<(), Stop> {
    imports! {
        copy_bytes: CopyBytesFn = "_CCRandomCopyBytes";
        generate_bytes: GenerateBytesFn = "_CCRandomGenerateBytes";
    }
    let default = generator(t, "_kCCRandomDefault");
    let dev = generator(t, "_kCCRandomDevRandom");
    let mut bufs = [[0u8; BUFMAX]; 6];
    for i in 0..K_TEST_TEST_COUNT {
        let len = i + 16;
        let [b1, b2, b3, b4, b5, b6] = &mut bufs;
        // SAFETY: as in `common_random`.
        unsafe {
            random_success(t, copy_bytes.get()?(default, b1.as_mut_ptr().cast(), len));
            random_success(t, copy_bytes.get()?(dev, b2.as_mut_ptr().cast(), len));
            random_success(
                t,
                copy_bytes.get()?(std::ptr::null(), b3.as_mut_ptr().cast(), len),
            );
            // ccrng_generate(devRandom, ..) and ccrng_generate(drbg, ..)
            random_success(t, generate_bytes.get()?(b4.as_mut_ptr().cast(), len));
            random_success(t, generate_bytes.get()?(b5.as_mut_ptr().cast(), len));
            random_success(t, generate_bytes.get()?(b6.as_mut_ptr().cast(), len));
        }
        all_differ(t, &bufs, len);
    }
    bad_inputs(t, copy_bytes, generate_bytes, default, dev)
}

fn random_success(t: &mut T, status: c_int) {
    t.check(status == 0, || format!("Random success: got {status}"));
}

fn all_differ(t: &mut T, bufs: &[[u8; BUFMAX]; 6], len: usize) {
    let [b1, b2, b3, b4, b5, b6] = bufs;
    for (a, b) in [(b1, b2), (b3, b4), (b2, b3), (b5, b6), (b5, b2), (b6, b1)] {
        t.check(differ(a, b, len), || {
            format!("Buffers aren't the same (len {len})")
        });
    }
}

fn bad_inputs(
    t: &mut T,
    copy_bytes: Import<CopyBytesFn>,
    generate_bytes: Import<GenerateBytesFn>,
    default: *const c_void,
    dev: *const c_void,
) -> Result<(), Stop> {
    let mut buf = [0u8; BUFMAX];
    let null = std::ptr::null_mut();
    let (copy, generate) = (copy_bytes.get()?, generate_bytes.get()?);
    // SAFETY: `buf` is writable; the nulls are the inputs under test.
    unsafe {
        let zero = [
            copy(default, buf.as_mut_ptr().cast(), 0),
            copy(dev, buf.as_mut_ptr().cast(), 0),
            generate(buf.as_mut_ptr().cast(), 0),
        ];
        for status in zero {
            t.check(status == 0, || format!("Zero Length: got {status}"));
        }
        let null_one = [
            copy(default, null, 1),
            copy(dev, null, 1),
            generate(null, 1),
        ];
        for status in null_one {
            t.check(status != 0, || "NULL pointer: got 0".into());
        }
        let null_zero = [
            copy(default, null, 0),
            copy(dev, null, 0),
            generate(null, 0),
        ];
        for status in null_zero {
            t.check(status == 0, || {
                format!("Zero Length, NULL pointer: got {status}")
            });
        }
    }
    Ok(())
}

/// `chisq`.
fn chisq(cells: &[u64]) -> f64 {
    let sum: u64 = cells.iter().sum();
    let ei = sum as f64 / cells.len() as f64;
    cells.iter().map(|&oi| (oi as f64 - ei).powi(2) / ei).sum()
}

/// `CommonRandomUniform`, which `CommonRandom` calls last.
fn common_random_uniform(t: &mut T) -> Result<(), Stop> {
    imports! {
        uniform: UniformFn = "_CCRandomUniform";
        generate_bytes: GenerateBytesFn = "_CCRandomGenerateBytes";
    }
    let mut rand = 0u64;
    let uniform = |bound: u64, rand: &mut u64| -> Result<c_int, Stop> {
        // SAFETY: a `uint64_t` to write.
        Ok(unsafe { uniform.get()?(bound, rand) })
    };
    let generate = |out: &mut [u8]| -> Result<(), Stop> {
        // SAFETY: `out` is writable.
        unsafe { generate_bytes.get()?(out.as_mut_ptr().cast(), out.len()) };
        Ok(())
    };

    t.check(uniform(0, &mut rand)? != K_CC_SUCCESS, || {
        "reject bound = 0".into()
    });
    t.check(uniform(1, &mut rand)? == K_CC_SUCCESS, || {
        "accept bound = 1".into()
    });
    t.check(rand == 0, || "rand out of range (bound = 1)".into());
    t.check(uniform(u64::MAX, &mut rand)? == K_CC_SUCCESS, || {
        "accept bound = UINT64_MAX".into()
    });
    t.check(rand < u64::MAX, || {
        "rand out of range (bound = UINT64_MAX)".into()
    });

    let mut i = 0;
    while i < 1 << 10 {
        let mut nbits = [0u8; 4];
        generate(&mut nbits)?;
        let bound_nbits = (u32::from_ne_bytes(nbits) & 0x3f) + 1;
        if bound_nbits == 1 {
            continue;
        }
        let bound_mask = !0u64 >> (64 - bound_nbits);
        let mut bound = [0u8; 8];
        generate(&mut bound)?;
        let bound = u64::from_ne_bytes(bound) & bound_mask;
        if bound == 0 {
            continue;
        }
        t.check(uniform(bound, &mut rand)? == K_CC_SUCCESS, || {
            format!("accept bound = {bound}")
        });
        t.check(rand < bound, || {
            format!("rand out of range (bound = {bound})")
        });
        i += 1;
    }

    let mut cells = [0u64; 3];
    for _ in 0..1 << 20 {
        t.check(uniform(3, &mut rand)? == K_CC_SUCCESS, || {
            "accept bound = 3".into()
        });
        if !t.check(rand < 3, || {
            format!("rand out of range (bound = 3): {rand}")
        }) {
            continue;
        }
        cells[rand as usize] += 1;
    }
    let v = chisq(&cells);
    t.check(v < 44.36142, || {
        format!("chi-squared: reject null hypothesis ({v})")
    });
    Ok(())
}

const CASES: &[Case] = &[
    Case {
        name: "CommonRandom",
        kind: Kind::Upstream,
        source: "CommonRandom(), through its bad inputs",
        timeout_secs: 60,
        run: common_random,
    },
    Case {
        name: "CommonRandomUniform",
        kind: Kind::Upstream,
        source: "CommonRandomUniform(), which CommonRandom() ends with",
        timeout_secs: 60,
        run: common_random_uniform,
    },
    Case {
        name: "CommonRandom/CCRandomGenerateBytes",
        kind: Kind::Adapted,
        source: "CommonRandom(), ccrng_generate on the corecrypto states -> CCRandomGenerateBytes",
        timeout_secs: 60,
        run: common_random_bound,
    },
];

#[test]
fn commoncrypto_conformance() {
    conformance::run("commoncrypto_conformance", "CommonCrypto", UPSTREAM, CASES);
}
