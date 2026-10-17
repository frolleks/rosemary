use core::ffi::{c_int, c_void};
use std::cell::RefCell;

type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// `qsort_r`'s comparator, which on Darwin takes the caller's context first.
type CompareWithThunk = unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int;

/// `void qsort(void *base, size_t nel, size_t width, int (*compar)(const void *, const void *))`
///
/// # Safety
///
/// `base` is `nel` elements of `width` bytes and `compar` is callable, which is
/// `qsort`'s own contract.
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    nel: usize,
    width: usize,
    compar: Option<Compare>,
) {
    // SAFETY: the caller's array and comparator, sorted by the host's own
    // `qsort` - which calls the comparator, so the boundary covers the sort.
    unsafe { crate::call_as_darwin!(libc::qsort(base, nel, width, compar)) }
}

thread_local! {
    /// The context and comparator of every [`qsort_r`] this thread is inside,
    /// innermost last: a comparator may itself sort.
    static SORTS: RefCell<Vec<(*mut c_void, CompareWithThunk)>> = const { RefCell::new(Vec::new()) };
}

/// The comparator the host's `qsort` calls for a [`qsort_r`]: the innermost
/// sort's, given its context in the place Darwin's puts it.
unsafe extern "C" fn with_thunk(a: *const c_void, b: *const c_void) -> c_int {
    let Some((thunk, compar)) = SORTS.with_borrow(|sorts| sorts.last().copied()) else {
        return 0;
    };
    // SAFETY: the comparator and context the guest gave the sort calling this.
    unsafe { compar(thunk, a, b) }
}

/// `void qsort_r(void *base, size_t nel, size_t width, void *thunk,
/// int (*compar)(void *, const void *, const void *))`
///
/// Darwin's, from FreeBSD's `qsort.c`: `thunk` is the sort's fourth argument and
/// the comparator's first. glibc's takes the comparator before the context and
/// hands the context last, which is why the host's is never bound (see
/// `crate::divergent`). This sorts with the host's `qsort`, and keeps the context
/// where the comparator it calls can find it.
///
/// # Safety
///
/// As [`qsort`], with `compar` callable on `thunk` and two elements.
pub unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nel: usize,
    width: usize,
    thunk: *mut c_void,
    compar: Option<CompareWithThunk>,
) {
    let Some(compar) = compar else {
        // SAFETY: the caller's array, with the comparator it gave: none.
        return unsafe { qsort(base, nel, width, None) };
    };
    /// Leaves [`SORTS`] as it was however the sort ends.
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            SORTS.with_borrow_mut(|sorts| sorts.pop());
        }
    }
    SORTS.with_borrow_mut(|sorts| sorts.push((thunk, compar)));
    let _done = Done;
    // SAFETY: the caller's array; `with_thunk` calls the caller's comparator.
    unsafe { qsort(base, nel, width, Some(with_thunk)) }
}

/// `void *bsearch(const void *key, const void *base, size_t nel, size_t width,
/// int (*compar)(const void *, const void *))`
///
/// # Safety
///
/// As [`qsort`], with `key` readable.
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nel: usize,
    width: usize,
    compar: Option<Compare>,
) -> *mut c_void {
    unsafe { crate::call_as_darwin!(libc::bsearch(key, base, nel, width, compar)) }
}

exports::exports! {
    functions {
        "qsort" => qsort,
        "qsort_r" => qsort_r,
        "bsearch" => bsearch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the wrappers exist for: the comparator is entered with the Darwin
    /// thread pointer even though the thread that called `qsort` had the host's.
    ///
    /// Run on a thread of this test's own, because the boundary is free - and so
    /// proves nothing - on a thread that is inside Darwin code already.
    #[test]
    fn a_comparator_runs_with_the_guests_thread_pointer() {
        static SAW_DARWIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

        unsafe extern "C" fn compare(a: *const c_void, b: *const c_void) -> c_int {
            if !crate::tls::entered() {
                SAW_DARWIN.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            // SAFETY: `qsort` below is sorting `i32`s.
            unsafe { *a.cast::<i32>() - *b.cast::<i32>() }
        }

        std::thread::spawn(|| {
            // The premise the wrappers rest on, asserted rather than assumed: a
            // thread this runtime started is not inside Darwin code.
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            assert!(
                !crate::tls::entered(),
                "a fresh thread already had the guest's thread pointer"
            );

            let mut values = [5i32, 3, 9, 1];
            // SAFETY: four `i32`s and a comparator that reads two of them.
            unsafe {
                qsort(
                    values.as_mut_ptr().cast(),
                    values.len(),
                    size_of::<i32>(),
                    Some(compare),
                )
            };
            assert_eq!(values, [1, 3, 5, 9]);

            let key = 9i32;
            // SAFETY: as above, over the array just sorted.
            let found = unsafe {
                bsearch(
                    (&raw const key).cast(),
                    values.as_ptr().cast(),
                    values.len(),
                    size_of::<i32>(),
                    Some(compare),
                )
            };
            assert!(!found.is_null(), "the key is in the array");
        })
        .join()
        .expect("the sorting thread");

        assert!(
            SAW_DARWIN.load(std::sync::atomic::Ordering::Relaxed),
            "the comparator ran with the host's thread pointer"
        );
    }

    /// The context reaches the comparator first, as Darwin's `qsort_r` passes
    /// it, and a sort inside a comparator does not take the outer one's.
    #[test]
    fn qsort_r_hands_the_comparator_its_context_first() {
        /// The `usize`s being sorted, ordered by the `[i32; 4]` of keys the
        /// context points at.
        unsafe extern "C" fn by_key(
            thunk: *mut c_void,
            a: *const c_void,
            b: *const c_void,
        ) -> c_int {
            // SAFETY: as the comparator's contract above.
            unsafe {
                let keys = &*thunk.cast::<[i32; 4]>();
                let (a, b) = (*a.cast::<usize>(), *b.cast::<usize>());
                keys[a].cmp(&keys[b]) as c_int
            }
        }
        /// As [`by_key`], sorting another array with a context of its own
        /// first, which must not take the place of the outer sort's.
        unsafe extern "C" fn by_key_nesting(
            thunk: *mut c_void,
            a: *const c_void,
            b: *const c_void,
        ) -> c_int {
            let mut inner = [2usize, 0, 1];
            let mut inner_keys = [30i32, 10, 20, 0];
            // SAFETY: three `usize`s, and keys for each.
            unsafe {
                qsort_r(
                    inner.as_mut_ptr().cast(),
                    inner.len(),
                    size_of::<usize>(),
                    (&raw mut inner_keys).cast(),
                    Some(by_key),
                )
            };
            assert_eq!(inner, [1, 2, 0]);
            // SAFETY: the outer sort's own arguments.
            unsafe { by_key(thunk, a, b) }
        }

        let mut keys = [40i32, 10, 30, 20];
        let mut order = [0usize, 1, 2, 3];
        // SAFETY: four `usize`s, and keys for each.
        unsafe {
            qsort_r(
                order.as_mut_ptr().cast(),
                order.len(),
                size_of::<usize>(),
                (&raw mut keys).cast(),
                Some(by_key_nesting),
            )
        };
        assert_eq!(order, [1, 3, 2, 0]);
    }
}
