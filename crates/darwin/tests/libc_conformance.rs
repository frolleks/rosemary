//! Libc conformance: the sorting tests of Apple's Libc test suite
//! (apple-oss-distributions/Libc, `tests/`), ported one for one and run
//! against what a guest binds.
//!
//! - `qsort.c`: `qsort_r`, with a context, on random elements of 1 to 10 bytes.
//! - `freebsd_qsort.c`: `qsort` and `qsort_b` on every prefix of a fixed vector.
//! - `psort.c`: `psort` against `qsort` on 20,480,000 random words.
//! - `qsort_perf.c`: `qsort` on 1,000,000 ints in four layouts.
//!
//! upstream's reference sorts (`ssort`, `szsort`) are O(n^2) exchange sorts.
//! Here the standard library's sort stands in: what is compared is the result,
//! and an ordering by `memcmp` or by `<` has one result, since elements that
//! compare equal are the same bytes.
//!
//! ```text
//! cargo test -p darwin --test libc_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]

mod conformance;

use std::ffi::{c_int, c_long, c_void};

use conformance::{Case, Kind, Stop, T, imports};

const UPSTREAM: &str = "Libc main tests/";

type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type CompareWithThunk = unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int;
type QsortFn = unsafe extern "C" fn(*mut c_void, usize, usize, Compare);
type QsortRFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void, CompareWithThunk);
type QsortBFn = unsafe extern "C" fn(*mut c_void, usize, usize, *const BlockLiteral);
type ArcRandomBufFn = unsafe extern "C" fn(*mut c_void, usize);
type RandomFn = unsafe extern "C" fn() -> c_long;

include!("conformance/freebsd_qsort_vector.rs");

/// `freebsd_qsort.h`'s `sorthelp`.
unsafe extern "C" fn sorthelp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: two elements of the `int` array being sorted.
    let (a, b) = unsafe { (*a.cast::<i32>(), *b.cast::<i32>()) };
    if a > b {
        return 1;
    }
    if a < b {
        return -1;
    }
    0
}

/// `freebsd_qsort.h`'s `szsorthelp`: the context is the element size.
unsafe extern "C" fn szsorthelp(sz: *mut c_void, a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: two elements of `sz` bytes of the array being sorted.
    unsafe { libc::memcmp(a, b, sz as usize) }
}

/// A block literal's layout (`Block_private.h`), for `sorthelp_b`.
#[repr(C)]
struct BlockLiteral {
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    invoke: unsafe extern "C" fn(*const BlockLiteral, *const c_void, *const c_void) -> c_int,
    descriptor: *const BlockDescriptor,
}

#[repr(C)]
struct BlockDescriptor {
    reserved: usize,
    size: usize,
}

const BLOCK_IS_GLOBAL: c_int = 1 << 28;

static SORTHELP_B_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: size_of::<BlockLiteral>(),
};

/// `freebsd_qsort.h`'s `sorthelp_b`: `sorthelp`, as a global block.
unsafe extern "C" fn sorthelp_b(
    _block: *const BlockLiteral,
    a: *const c_void,
    b: *const c_void,
) -> c_int {
    unsafe { sorthelp(a, b) }
}

/// `freebsd_qsort.h`'s `ssort`, by its result.
fn ssort(v: &mut [i32]) {
    v.sort_unstable();
}

/// `freebsd_qsort.h`'s `szsort`, by its result: `sz`-byte elements in
/// `memcmp` order.
fn szsort(v: &mut [u8], sz: usize) {
    let mut elements: Vec<&[u8]> = v.chunks_exact(sz).collect();
    elements.sort_unstable();
    let sorted: Vec<u8> = elements.concat();
    v[..sorted.len()].copy_from_slice(&sorted);
}

/// `qsort.c`'s `qsort_random`.
fn qsort_random(t: &mut T) -> Result<(), Stop> {
    imports! {
        arc4random_buf: ArcRandomBufFn = "_arc4random_buf";
        qsort_r: QsortRFn = "_qsort_r";
    }
    const BUFLEN: usize = 32 * 1024;
    let mut testvector = vec![0u8; BUFLEN];
    let mut tests = 10;
    loop {
        tests -= 1;
        if tests < 0 {
            break;
        }
        let elmsize = (tests % 32) as usize + 1;
        let elmcount = BUFLEN / elmsize;
        // SAFETY: a buffer of `BUFLEN` bytes.
        unsafe { arc4random_buf.get()?(testvector.as_mut_ptr().cast(), BUFLEN) };
        let mut sresvector = testvector.clone();

        // SAFETY: `elmcount` elements of `elmsize` bytes, and a comparator
        // whose context is that size.
        unsafe {
            qsort_r.get()?(
                testvector.as_mut_ptr().cast(),
                elmcount,
                elmsize,
                elmsize as *mut c_void,
                szsorthelp,
            )
        };
        szsort(&mut sresvector, elmsize);

        let first = (0..elmcount).find(|&i| {
            testvector[i * elmsize..][..elmsize] != sresvector[i * elmsize..][..elmsize]
        });
        match first {
            Some(i) => {
                // T_ASSERT_FAIL
                return Err(Stop::Fail(format!(
                    "{tests}: item at index {i} should match (size {elmsize}, count {elmcount})"
                )));
            }
            None => {
                t.check(true, String::new);
            }
        }
    }
    Ok(())
}

/// `freebsd_qsort.c`'s `qsort` and `qsort_b`, which differ only in the sort
/// called.
fn prefixes(t: &mut T, sort: &mut dyn FnMut(&mut [i32]) -> Result<(), Stop>) -> Result<(), Stop> {
    for j in 2..INITVECTOR.len() {
        let mut testvector = INITVECTOR[..j].to_vec();
        let mut sresvector = testvector.clone();
        sort(&mut testvector)?;
        ssort(&mut sresvector);
        for i in 0..j {
            // T_QUIET; T_EXPECT_EQ
            t.check(testvector[i] == sresvector[i], || {
                format!(
                    "j = {j}: item at index {i} should match ({} != {})",
                    testvector[i], sresvector[i]
                )
            });
        }
    }
    Ok(())
}

fn qsort(t: &mut T) -> Result<(), Stop> {
    imports! { qsort: QsortFn = "_qsort"; }
    prefixes(t, &mut |v| {
        // SAFETY: `v.len()` ints and a comparator of two ints.
        unsafe { qsort.get()?(v.as_mut_ptr().cast(), v.len(), size_of::<i32>(), sorthelp) };
        Ok(())
    })
}

fn qsort_b(t: &mut T) -> Result<(), Stop> {
    imports! {
        qsort_b: QsortBFn = "_qsort_b";
        global_block: *const c_void = "__NSConcreteGlobalBlock";
    }
    let block = BlockLiteral {
        isa: global_block.get().unwrap_or(std::ptr::null()),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke: sorthelp_b,
        descriptor: &SORTHELP_B_DESCRIPTOR,
    };
    prefixes(t, &mut |v| {
        // SAFETY: as in `qsort`, with the comparator a block.
        unsafe { qsort_b.get()?(v.as_mut_ptr().cast(), v.len(), size_of::<i32>(), &block) };
        Ok(())
    })
}

/// `psort.c`'s `comparT`.
unsafe extern "C" fn compar_t(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: two elements of the `unsigned long` array being sorted.
    let (x, y) = unsafe { (*a.cast::<u64>(), *b.cast::<u64>()) };
    match x.cmp(&y) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    }
}

/// `psort.c`'s `psort`.
fn psort(t: &mut T) -> Result<(), Stop> {
    imports! {
        arc4random_buf: ArcRandomBufFn = "_arc4random_buf";
        psort: QsortFn = "_psort";
        qsort: QsortFn = "_qsort";
    }
    // Its first call is to `psort`, after filling the buffers: an unbound
    // `psort` is that call's fault, and nothing before it is observable.
    let psort = psort.get()?;
    const NEL: usize = 20_480_000;
    let width = size_of::<u64>();
    let mut buf = vec![0u64; NEL];
    // SAFETY: `NEL` words.
    unsafe { arc4random_buf.get()?(buf.as_mut_ptr().cast(), NEL * width) };
    let mut sorted = buf.clone();

    let cpu = || {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: a `rusage` to fill.
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        usage.ru_utime.tv_sec as f64 * 1e6 + usage.ru_utime.tv_usec as f64
    };

    let (wall, user) = (std::time::Instant::now(), cpu());
    // SAFETY: `NEL` words and a comparator of two words.
    unsafe { psort(sorted.as_mut_ptr().cast(), NEL, width, compar_t) };
    let (pwt, put) = (wall.elapsed().as_secs_f64() * 1e6, cpu() - user);
    t.note(format!(
        "psort: wall-time={pwt:.0} us; user-time={put:.0} us"
    ));

    let (wall, user) = (std::time::Instant::now(), cpu());
    // SAFETY: as above.
    unsafe { qsort.get()?(buf.as_mut_ptr().cast(), NEL, width, compar_t) };
    let (qwt, qut) = (wall.elapsed().as_secs_f64() * 1e6, cpu() - user);
    t.note(format!(
        "qsort: wall-time={qwt:.0} us; user-time={qut:.0} us"
    ));

    if let Some(i) = (0..NEL).find(|&i| buf[i] != sorted[i]) {
        // T_ASSERT_EQ
        return Err(Stop::Fail(format!(
            "index {i}: {} != {}",
            buf[i], sorted[i]
        )));
    }
    t.check(pwt / qwt <= 1.2, || {
        format!("psort/qsort wall time {:.2} > 1.2", pwt / qwt)
    });
    t.check(qut / put <= 1.2, || {
        format!("qsort/psort user time {:.2} > 1.2", qut / put)
    });
    Ok(())
}

/// `qsort_perf.c`'s `cmp_int`.
unsafe extern "C" fn cmp_int(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: two elements of the `int` array being sorted.
    let (a, b) = unsafe { (*a.cast::<c_int>(), *b.cast::<c_int>()) };
    a.wrapping_sub(b)
}

/// `qsort_perf.c`'s `qsort_perf`, its `qsort` steps.
fn qsort_perf(t: &mut T) -> Result<(), Stop> {
    imports! {
        qsort: QsortFn = "_qsort";
        random: RandomFn = "_random";
    }
    const NELM: usize = 1_000_000;
    let mut save = vec![0i32; NELM];
    let mut layouts: Vec<(&str, Vec<i32>)> = Vec::new();

    // 25-75 and 50-50: `save[i] = i` up to `k`, and `i - k` from there.
    for (name, k) in [("25-75", NELM / 4), ("50-50", NELM / 2)] {
        let (low, high) = save.split_at_mut(k);
        for (i, v) in low.iter_mut().enumerate() {
            *v = i as i32;
        }
        for (i, v) in high.iter_mut().enumerate() {
            *v = i as i32;
        }
        layouts.push((name, save.clone()));
    }

    // median-of-3 killer
    let k = NELM / 2;
    for i in 1..=k {
        if i % 2 == 1 {
            save[i - 1] = i as i32;
            save[i] = (k + i) as i32;
        }
        save[k + i - 1] = 2 * i as i32;
    }
    layouts.push(("median-of-3 killer", save.clone()));

    for (name, save) in layouts {
        sort_and_check(t, qsort, name, save)?;
    }

    // random
    let random = random.get()?;
    // SAFETY: `random(3)` takes nothing.
    let save: Vec<i32> = (0..NELM).map(|_| unsafe { random() } as i32).collect();
    sort_and_check(t, qsort, "random", save)
}

fn sort_and_check(
    t: &mut T,
    qsort: conformance::Import<QsortFn>,
    name: &str,
    mut arr: Vec<i32>,
) -> Result<(), Stop> {
    let start = std::time::Instant::now();
    // SAFETY: `arr.len()` ints and a comparator of two ints.
    unsafe {
        qsort.get()?(
            arr.as_mut_ptr().cast(),
            arr.len(),
            size_of::<i32>(),
            cmp_int,
        )
    };
    t.note(format!(
        "{name} (qsort): {} ms",
        start.elapsed().as_millis()
    ));
    if let Some(i) = (1..arr.len()).find(|&i| arr[i - 1] > arr[i]) {
        // T_ASSERT_FAIL
        return Err(Stop::Fail(format!(
            "{name}: arr[{}]={} > arr[{i}]={}",
            i - 1,
            arr[i - 1],
            arr[i]
        )));
    }
    t.check(true, String::new);
    Ok(())
}

const CASES: &[Case] = &[
    Case {
        name: "qsort_random",
        kind: Kind::Upstream,
        source: "qsort.c",
        timeout_secs: 120,
        run: qsort_random,
    },
    Case {
        name: "qsort",
        kind: Kind::Upstream,
        source: "freebsd_qsort.c",
        timeout_secs: 120,
        run: qsort,
    },
    Case {
        name: "qsort_b",
        kind: Kind::Upstream,
        source: "freebsd_qsort.c",
        timeout_secs: 120,
        run: qsort_b,
    },
    Case {
        name: "psort",
        kind: Kind::Upstream,
        source: "psort.c",
        timeout_secs: 300,
        run: psort,
    },
    Case {
        name: "qsort_perf",
        kind: Kind::Excerpt,
        source: "qsort_perf.c; without qsort1, the test's own Bentley sort it times qsort against",
        timeout_secs: 300,
        run: qsort_perf,
    },
];

#[test]
fn libc_conformance() {
    conformance::run("libc_conformance", "Libc", UPSTREAM, CASES);
}
