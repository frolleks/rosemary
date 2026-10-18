//! xnu VM conformance: Apple's memory entry and `mach_vm_map` tests
//! (apple-oss-distributions/xnu, `tests/vm/mach_vm_map.c`,
//! `tests/vm/vm_memory_entry.c` and `tests/vm/vm_memory_entry_parent_test.c`)
//! against the `mach_make_memory_entry_64`, `mach_vm_map`,
//! `mach_memory_object_memory_entry_64` and
//! `mach_memory_entry_get_page_counts` a guest binds.
//!
//! Upstream builds these for x86_64 with `PAGE_SIZE` 4096, which is the page
//! size here too, and runs `vm_memory_entry_parent` down its Intel branch, as
//! a guest that is not translated.
//!
//! ```text
//! cargo test -p darwin --test xnu_vm_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]

mod conformance;

use std::ffi::{c_int, c_uint, c_void};

use conformance::{Case, Kind, Stop, T, imports};

const UPSTREAM: &str = "xnu main tests/vm";

const KERN_SUCCESS: c_int = 0;
const KERN_INVALID_ARGUMENT: c_int = 4;
const KERN_PROTECTION_FAILURE: c_int = 2;
const KERN_INVALID_RIGHT: c_int = 17;

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

const VM_PROT_READ: c_int = 0x1;
const VM_PROT_WRITE: c_int = 0x2;
const VM_PROT_ALL: c_int = 0x7;
const VM_PROT_DEFAULT: c_int = VM_PROT_READ | VM_PROT_WRITE;
const VM_PROT_IS_MASK: c_int = 0x40;

const MAP_MEM_NAMED_CREATE: c_int = 0x0002_0000;
const MAP_MEM_NAMED_REUSE: c_int = 0x0008_0000;
const MAP_MEM_USE_DATA_ADDR: c_int = 0x0010_0000;
const MAP_MEM_VM_COPY: c_int = 0x0020_0000;
const MAP_MEM_VM_SHARE: c_int = 0x0040_0000;
const MAP_MEM_LEDGER_TAGGED: c_int = 0x0000_2000;

const VM_FLAGS_ANYWHERE: c_int = 0x0001;
const VM_FLAGS_RETURN_DATA_ADDR: c_int = 0x0010_0000;
const VM_MEMORY_SCENEKIT: c_int = 86;

const VM_INHERIT_DEFAULT: c_uint = 1;
const VM_INHERIT_NONE: c_uint = 2;

const VM_REGION_BASIC_INFO_64: c_int = 9;
const VM_REGION_BASIC_INFO_COUNT_64: c_uint = 9;

/// Darwin's `MADV_PAGEOUT`.
const MADV_PAGEOUT: c_int = 10;

const KB4: u64 = 4 * 1024;
const KB16: u64 = 16 * 1024;

type MakeEntryFn = unsafe extern "C" fn(c_uint, *mut u64, u64, c_int, *mut c_uint, c_uint) -> c_int;
type MapFn = unsafe extern "C" fn(
    c_uint,
    *mut u64,
    u64,
    u64,
    c_int,
    c_uint,
    u64,
    c_int,
    c_int,
    c_int,
    c_uint,
) -> c_int;
type RegionFn = unsafe extern "C" fn(
    c_uint,
    *mut u64,
    *mut u64,
    c_int,
    *mut c_void,
    *mut c_uint,
    *mut c_uint,
) -> c_int;
type AllocateFn = unsafe extern "C" fn(c_uint, *mut u64, u64, c_int) -> c_int;
type DeallocateFn = unsafe extern "C" fn(c_uint, u64, u64) -> c_int;
type PortDeallocateFn = unsafe extern "C" fn(c_uint, c_uint) -> c_int;
type ObjectEntryFn = unsafe extern "C" fn(c_uint, c_int, u64, c_int, c_uint, *mut c_uint) -> c_int;
type PageCountsFn = unsafe extern "C" fn(c_uint, *mut u64, *mut u64, *mut u64) -> c_int;
type HostSelfFn = unsafe extern "C" fn() -> c_uint;
type LockFn = unsafe extern "C" fn(*const c_void, usize) -> c_int;
type MadviseFn = unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int;

fn trunc_page(x: u64) -> u64 {
    x & !PAGE_MASK
}

fn round_page(x: u64) -> u64 {
    x.wrapping_add(PAGE_MASK) & !PAGE_MASK
}

fn task_self() -> Result<c_uint, Stop> {
    imports! { task_self: *const c_uint = "_mach_task_self_"; }
    // SAFETY: `mach_task_self_` is a word the runtime filled in.
    Ok(unsafe { *task_self.get()? })
}

/// The word in memory at `address`.
fn word(address: u64) -> u32 {
    // SAFETY: the caller's mapping, read as upstream reads it.
    unsafe { (address as *const u32).read() }
}

/// `vm_region_basic_info_data_64_t`, as `mach_vm_region` writes it.
#[repr(C, packed(4))]
#[derive(Default)]
struct BasicInfo64 {
    protection: c_int,
    max_protection: c_int,
    inheritance: c_uint,
    shared: c_uint,
    reserved: c_uint,
    offset: u64,
    behavior: c_int,
    user_wired_count: u16,
}

// --- tests/vm/mach_vm_map.c ------------------------------------------------

const MO_SPECS: &[(c_int, &str)] = &[
    (0, "0"),
    (MAP_MEM_VM_COPY, "MAP_MEM_VM_COPY"),
    (MAP_MEM_VM_SHARE, "MAP_MEM_VM_SHARE"),
    (MAP_MEM_USE_DATA_ADDR, "MAP_MEM_USE_DATA_ADDR"),
    (
        MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR,
        "MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR",
    ),
    (
        MAP_MEM_VM_SHARE | MAP_MEM_USE_DATA_ADDR,
        "MAP_MEM_VM_SHARE | MAP_MEM_USE_DATA_ADDR",
    ),
];

const SZ16K: u64 = 16 << 10;
const SCRATCH_SIZE: u64 = 3 * SZ16K;
const MO_OFFSET: u64 = SZ16K - 128;
const MO_SIZE: u64 = SZ16K + 256;

fn range_specs() -> [(u64, u64); 40] {
    const P: u64 = PAGE_SIZE;
    [
        (0, 64),
        (0, 128),
        (0, 256),
        (0, P),
        (0, P + 64),
        (0, 2 * P - 64),
        (0, 2 * P),
        (64, P),
        (64, P + 64),
        (64, 2 * P - 64),
        (64, 2 * P),
        (P - 64, P),
        (P - 64, P + 64),
        (P - 64, 2 * P - 64),
        (P - 64, 2 * P),
        (P, P + 64),
        (P, 2 * P - 64),
        (P, 2 * P),
        (P + 64, 2 * P - 64),
        (P + 64, 2 * P),
        (0, SZ16K + 64),
        (0, SZ16K + 128),
        (0, SZ16K + 256),
        (0, SZ16K + P),
        (0, SZ16K + P + 64),
        (0, SZ16K + 2 * P - 64),
        (0, SZ16K + 2 * P),
        (64, SZ16K + P),
        (64, SZ16K + P + 64),
        (64, SZ16K + 2 * P - 64),
        (64, SZ16K + 2 * P),
        (P - 64, SZ16K + P),
        (P - 64, SZ16K + P + 64),
        (P - 64, SZ16K + 2 * P - 64),
        (P - 64, SZ16K + 2 * P),
        (P, SZ16K + P + 64),
        (P, SZ16K + 2 * P - 64),
        (P, SZ16K + 2 * P),
        (P + 64, SZ16K + 2 * P - 64),
        (P + 64, SZ16K + 2 * P),
    ]
}

/// `mach_vm_map_unaligned_test`.
fn map_unaligned_one(
    t: &mut T,
    scratch: u64,
    mo_flags: c_int,
    vmflags: c_int,
    map_offset: u64,
    map_size: u64,
) -> Result<(), Stop> {
    imports! {
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
        region: RegionFn = "_mach_vm_region";
        deallocate: DeallocateFn = "_mach_vm_deallocate";
        port_deallocate: PortDeallocateFn = "_mach_port_deallocate";
    }
    let me = task_self()?;
    let tag = VM_MEMORY_SCENEKIT << 24;
    let what = format!(
        "[mo {mo_flags:#x}, vmflags {vmflags:#x}, offset {map_offset:#x}, size {map_size:#x}]"
    );

    let mut size = MO_SIZE;
    let mut mo_port: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut size,
            scratch + MO_OFFSET,
            VM_PROT_DEFAULT | mo_flags,
            &mut mo_port,
            0,
        )
    };

    let used_offset_for_size = match vmflags & VM_FLAGS_RETURN_DATA_ADDR != 0 {
        true if mo_flags & MAP_MEM_USE_DATA_ADDR != 0 => map_offset + MO_OFFSET,
        true => map_offset,
        false => 0,
    };
    let mut should_fail =
        round_page(used_offset_for_size + map_size) > round_page(MO_OFFSET + MO_SIZE);
    if map_offset & PAGE_MASK != 0
        && vmflags & VM_FLAGS_RETURN_DATA_ADDR == 0
        && mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE) == 0
    {
        should_fail = true;
    }

    t.require(kr == KERN_SUCCESS, || {
        format!("{what} made memory entry: {kr}")
    })?;
    let want_size = match mo_flags & MAP_MEM_USE_DATA_ADDR != 0 {
        true => (MO_OFFSET & PAGE_MASK) + MO_SIZE,
        false => round_page((MO_OFFSET & PAGE_MASK) + MO_SIZE),
    };
    t.check(size == want_size, || {
        format!("{what} memory entry's size {size:#x}, want {want_size:#x}")
    });

    let mut map_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe {
        map.get()?(
            me,
            &mut map_addr,
            map_size,
            0,
            tag | vmflags,
            mo_port,
            map_offset,
            1,
            VM_PROT_DEFAULT,
            VM_PROT_DEFAULT,
            VM_INHERIT_DEFAULT,
        )
    };
    match should_fail {
        true => t.check(kr == KERN_INVALID_ARGUMENT, || {
            format!("{what} mach_vm_map: {kr}, want KERN_INVALID_ARGUMENT")
        }),
        false => t.check(kr == KERN_SUCCESS, || {
            format!("{what} mach_vm_map: {kr}, want KERN_SUCCESS")
        }),
    };

    if kr == KERN_SUCCESS {
        match vmflags & VM_FLAGS_RETURN_DATA_ADDR != 0 {
            true => t.check(
                map_addr & PAGE_MASK == used_offset_for_size & PAGE_MASK,
                || format!("{what} returned address {map_addr:#x} lost its offset"),
            ),
            false => t.check(map_addr & PAGE_MASK == 0, || {
                format!("{what} returned address {map_addr:#x} unaligned")
            }),
        };

        let mut info = BasicInfo64::default();
        let mut icount = VM_REGION_BASIC_INFO_COUNT_64;
        let mut r_addr = map_addr;
        let mut r_size = 0;
        let mut object: c_uint = 0;
        // SAFETY: writable out-parameters and a buffer `icount` words long.
        let kr = unsafe {
            region.get()?(
                me,
                &mut r_addr,
                &mut r_size,
                VM_REGION_BASIC_INFO_64,
                (&raw mut info).cast(),
                &mut icount,
                &mut object,
            )
        };

        if !should_fail {
            let want_addr = trunc_page(map_addr);
            let want_size = match mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE) != 0 {
                // "mach_vm_map() only does full objects"
                true => round_page(MO_OFFSET + MO_SIZE) - trunc_page(MO_OFFSET),
                false => {
                    round_page(used_offset_for_size + map_size) - trunc_page(used_offset_for_size)
                }
            };
            let want_data = if mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE) != 0 {
                (trunc_page(MO_OFFSET) / 4) as u32
            } else if mo_flags & MAP_MEM_USE_DATA_ADDR != 0 {
                (trunc_page(map_offset + MO_OFFSET) / 4) as u32
            } else {
                ((trunc_page(map_offset) + trunc_page(MO_OFFSET)) / 4) as u32
            };
            t.check(kr == KERN_SUCCESS, || {
                format!("{what} mach_vm_region: {kr}")
            });
            t.check(r_addr == want_addr, || {
                format!("{what} region base {r_addr:#x}, want {want_addr:#x}")
            });
            t.check(r_size == want_size, || {
                format!("{what} region size {r_size:#x}, want {want_size:#x}")
            });
            if kr == KERN_SUCCESS && r_addr == want_addr {
                let mut offs = 4;
                while offs < r_size {
                    let got = word(r_addr + offs);
                    let want = want_data.wrapping_add((offs / 4) as u32);
                    t.check(got == want, || {
                        format!("{what} content at {offs:#x}: {got:#x}, want {want:#x}")
                    });
                    offs += PAGE_SIZE;
                }
            }
        }

        // SAFETY: the region just mapped.
        let kr = unsafe { deallocate.get()?(me, r_addr, r_size) };
        t.require(kr == KERN_SUCCESS, || {
            format!("{what} vm_deallocate({r_addr:#x}, {r_size:#x}): {kr}")
        })?;
    }

    // SAFETY: a send right this case holds.
    let kr = unsafe { port_deallocate.get()?(me, mo_port) };
    t.require(kr == KERN_SUCCESS, || {
        format!("{what} m_p_d(mo_port): {kr}")
    })
}

/// `T_DECL(mach_vm_map_unaligned)`.
fn mach_vm_map_unaligned(t: &mut T) -> Result<(), Stop> {
    imports! { map: MapFn = "_mach_vm_map"; }
    let me = task_self()?;
    let mut scratch = 0;
    // SAFETY: a writable address.
    let kr = unsafe {
        map.get()?(
            me,
            &mut scratch,
            SCRATCH_SIZE,
            (64 << 10) - 1,
            VM_FLAGS_ANYWHERE,
            0,
            0,
            1,
            VM_PROT_DEFAULT,
            VM_PROT_DEFAULT,
            VM_INHERIT_DEFAULT,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("allocated scratch space: {kr}")
    });
    t.require(kr == KERN_SUCCESS, || "no scratch space".into())?;
    for i in 0..(SCRATCH_SIZE / 4) as u32 {
        // SAFETY: the scratch space just allocated.
        unsafe { (scratch as *mut u32).add(i as usize).write(i) };
    }

    for vmflags in [
        VM_FLAGS_ANYWHERE,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
    ] {
        for &(mo_flags, _) in MO_SPECS {
            for (start, end) in range_specs() {
                map_unaligned_one(t, scratch, mo_flags, vmflags, start, end - start)?;
            }
        }
    }
    Ok(())
}

/// `T_DECL(vm_map_enter_mem_object_overflow)`.
fn vm_map_enter_mem_object_overflow(t: &mut T) -> Result<(), Stop> {
    imports! {
        allocate: AllocateFn = "_mach_vm_allocate";
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
    }
    let me = task_self()?;
    let size_16kb = KB16;
    let mut alloced_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe { allocate.get()?(me, &mut alloced_addr, 2 * size_16kb, VM_FLAGS_ANYWHERE) };
    t.require(kr == KERN_SUCCESS, || format!("set up allocation: {kr}"))?;

    let mut entry_size = size_16kb;
    let entry_offset = alloced_addr + size_16kb / 2;
    let mut entry_handle: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut entry_size,
            entry_offset,
            MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR | VM_PROT_ALL,
            &mut entry_handle,
            0,
        )
    };
    t.require(kr == KERN_SUCCESS, || {
        format!("set up copy memory entry: {kr}")
    })?;

    let map = map.get()?;
    let mut target_addr = 0;
    let mut attempt = |size: u64, flags: c_int, offset: u64| {
        // SAFETY: a writable address.
        unsafe {
            map(
                me,
                &mut target_addr,
                size,
                0,
                flags,
                entry_handle,
                offset,
                1,
                VM_PROT_ALL,
                VM_PROT_ALL,
                VM_INHERIT_DEFAULT,
            )
        }
    };

    let kr = attempt(u64::MAX, VM_FLAGS_ANYWHERE, 0);
    t.check(kr == KERN_INVALID_ARGUMENT, || {
        format!("obj_size overflow case: {kr}")
    });

    let flags = VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR;
    let kr = attempt(size_16kb, flags, u64::MAX);
    t.check(kr == KERN_INVALID_ARGUMENT, || {
        format!("obj_offs overflow case: {kr}")
    });

    let kr = attempt(size_16kb, flags, (size_16kb + 1).wrapping_neg());
    t.check(kr == KERN_INVALID_ARGUMENT, || {
        format!("obj_end overflow case: {kr}")
    });

    let kr = attempt(size_16kb, flags, (2 * size_16kb).wrapping_neg());
    t.check(kr == KERN_INVALID_ARGUMENT, || {
        format!("round-to-0 case should be detected: {kr}")
    });
    Ok(())
}

// --- tests/vm/vm_memory_entry.c ----------------------------------------------

/// `T_DECL(memory_entry_page_counts)`.
fn memory_entry_page_counts(t: &mut T) -> Result<(), Stop> {
    imports! {
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
        counts: PageCountsFn = "_mach_memory_entry_get_page_counts";
        deallocate: DeallocateFn = "_mach_vm_deallocate";
        port_deallocate: PortDeallocateFn = "_mach_port_deallocate";
        mlock: LockFn = "_mlock";
        munlock: LockFn = "_munlock";
        madvise: MadviseFn = "_madvise";
    }
    let me = task_self()?;
    let pages: u64 = 1024;
    let mut size = pages * PAGE_SIZE;
    let mut memory_entry: c_uint = 0;
    // SAFETY: writable size and handle.
    let err = unsafe {
        make_entry.get()?(
            me,
            &mut size,
            0,
            MAP_MEM_NAMED_CREATE | MAP_MEM_LEDGER_TAGGED | VM_PROT_DEFAULT,
            &mut memory_entry,
            0,
        )
    };
    t.require(err == KERN_SUCCESS, || {
        format!("mach_make_memory_entry(): {err}")
    })?;
    t.require(memory_entry != 0, || "memory entry is null".into())?;

    let mut addr = 0;
    // SAFETY: a writable address.
    let err = unsafe {
        map.get()?(
            me,
            &mut addr,
            size,
            0,
            VM_FLAGS_ANYWHERE,
            memory_entry,
            0,
            0,
            VM_PROT_DEFAULT,
            VM_PROT_DEFAULT,
            VM_INHERIT_NONE,
        )
    };
    t.require(err == KERN_SUCCESS, || format!("mach_vm_map(): {err}"))?;

    let counts = counts.get()?;
    let query = |t: &mut T| -> Result<(u64, u64, u64), Stop> {
        let (mut resident, mut dirty, mut swapped) = (0, 0, 0);
        // SAFETY: three writable counts.
        let ret = unsafe { counts(memory_entry, &mut resident, &mut dirty, &mut swapped) };
        t.require(ret == KERN_SUCCESS, || {
            format!("mach_memory_entry_get_page_counts(): {ret}")
        })?;
        Ok((resident, dirty, swapped))
    };

    let (resident, dirty, swapped) = query(t)?;
    t.check(resident == 0, || {
        format!("Entry should have no resident pages: {resident}")
    });
    t.check(dirty == 0, || {
        format!("Entry should have no dirty pages: {dirty}")
    });
    t.check(swapped == 0, || {
        format!("Entry should have no swapped pages: {swapped}")
    });

    // SAFETY: the mapping just made, writable.
    unsafe { std::ptr::write_bytes(addr as *mut u8, 0xAB, size as usize) };
    // SAFETY: the same mapping.
    let ret = unsafe { mlock.get()?(addr as *const c_void, size as usize) };
    t.require(ret == 0, || {
        format!("mlock(): errno {}", conformance::errno())
    })?;

    let (resident, dirty, swapped) = query(t)?;
    t.check(resident == pages, || {
        format!("Entry should have all resident pages: {resident}")
    });
    t.check(dirty == pages, || {
        format!("Entry should have all dirty pages: {dirty}")
    });
    t.check(swapped == 0, || {
        format!("Entry should have no swapped pages: {swapped}")
    });

    // SAFETY: the same mapping.
    let ret = unsafe { munlock.get()?(addr as *const c_void, size as usize) };
    t.require(ret == 0, || {
        format!("munlock(): errno {}", conformance::errno())
    })?;
    // SAFETY: the same mapping.
    let ret = unsafe { madvise.get()?(addr as *mut c_void, size as usize, MADV_PAGEOUT) };
    t.require(ret == 0, || {
        format!("madvise(): errno {}", conformance::errno())
    })?;
    // "MADV_PAGEOUT is asynchronous"
    std::thread::sleep(std::time::Duration::from_secs(1));

    let (resident, dirty, swapped) = query(t)?;
    if !host_has_swap() && resident == pages {
        t.note("the host has no swap, so MADV_PAGEOUT keeps every page resident");
    }
    t.check(resident == 0, || {
        format!("Entry should have no resident pages: {resident}")
    });
    t.check(dirty == 0, || {
        format!("Entry should have no dirty pages: {dirty}")
    });
    t.check(swapped == pages, || {
        format!("Entry should have all swapped pages: {swapped}")
    });

    // SAFETY: the mapping, and the entry's send right.
    let err = unsafe { deallocate.get()?(me, addr, size) };
    t.require(err == KERN_SUCCESS, || {
        format!("mach_vm_deallocate(): {err}")
    })?;
    // SAFETY: as above.
    let err = unsafe { port_deallocate.get()?(me, memory_entry) };
    t.require(err == KERN_SUCCESS, || {
        format!("mach_port_deallocate(): {err}")
    })
}

/// Whether the host has anywhere to page anonymous memory out to.
fn host_has_swap() -> bool {
    std::fs::read_to_string("/proc/swaps")
        .map(|swaps| swaps.lines().count() > 1)
        .unwrap_or(true)
}

// --- tests/vm/vm_memory_entry_parent_test.c -----------------------------------

/// `T_DECL(vm_memory_entry_parent)`.
fn vm_memory_entry_parent(t: &mut T) -> Result<(), Stop> {
    imports! {
        allocate: AllocateFn = "_mach_vm_allocate";
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
    }
    let me = task_self()?;
    let size = KB16 * 2;
    let mut src_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe { allocate.get()?(me, &mut src_addr, size, VM_FLAGS_ANYWHERE) };
    t.check(kr == KERN_SUCCESS, || format!("vm_allocate: {kr}"));
    t.require(kr == KERN_SUCCESS, || "no source".into())?;
    for i in 0..size / KB4 {
        // SAFETY: the allocation just made.
        unsafe {
            std::ptr::write_bytes(
                (src_addr + KB4 * i) as *mut u8,
                ((i + 1) * 0x11) as u8,
                KB4 as usize,
            )
        };
    }

    let parent_offset = KB4 * 2;
    let mut parent_entry_size = size;
    let mut named_me_port: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut parent_entry_size,
            src_addr + parent_offset,
            VM_PROT_READ | VM_PROT_WRITE,
            &mut named_me_port,
            0,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("parent mach_make_memory_entry(): {kr}")
    });

    let child_offset = KB4 * 3;
    let mut child_entry_size = KB4;
    let mut child_me_port: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut child_entry_size,
            child_offset,
            VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_USE_DATA_ADDR,
            &mut child_me_port,
            named_me_port,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("child mach_make_memory_entry(): {kr}")
    });

    let mut mapped_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe {
        map.get()?(
            me,
            &mut mapped_addr,
            child_entry_size,
            0,
            VM_FLAGS_ANYWHERE,
            child_me_port,
            0,
            0,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE,
        )
    };
    t.check(kr == KERN_SUCCESS, || format!("mach_vm_map(): {kr}"));
    t.require(kr == KERN_SUCCESS, || "nothing mapped to compare".into())?;

    // The Intel, untranslated branch: offset by the parent's and the child's.
    // SAFETY: both ranges are mapped and `child_entry_size` long.
    let same = unsafe {
        std::slice::from_raw_parts(mapped_addr as *const u8, child_entry_size as usize)
            == std::slice::from_raw_parts(
                (src_addr + parent_offset + child_offset) as *const u8,
                child_entry_size as usize,
            )
    };
    t.require(same, || "Mapped values equal src values".into())
}

/// `T_DECL(vm_memory_entry_named_reuse_parent)`.
fn vm_memory_entry_named_reuse_parent(t: &mut T) -> Result<(), Stop> {
    imports! {
        host_self: HostSelfFn = "_mach_host_self";
        object_entry: ObjectEntryFn = "_mach_memory_object_memory_entry_64";
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
    }
    let me = task_self()?;
    let mut parent_handle: c_uint = 0;
    // SAFETY: a writable handle.
    let kr = unsafe {
        object_entry.get()?(
            host_self.get()?(),
            1,
            KB16,
            VM_PROT_READ | VM_PROT_WRITE,
            0,
            &mut parent_handle,
        )
    };
    t.require(kr == KERN_SUCCESS, || {
        format!("make parent_handle return value: {kr}")
    })?;

    let mut alloced_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe {
        map.get()?(
            me,
            &mut alloced_addr,
            KB16,
            0,
            VM_FLAGS_ANYWHERE,
            parent_handle,
            0,
            0,
            VM_PROT_DEFAULT,
            VM_PROT_DEFAULT,
            VM_INHERIT_DEFAULT,
        )
    };
    t.require(kr == KERN_SUCCESS, || format!("map parent_handle: {kr}"))?;

    let mut entry_size = KB16;
    let mut entry_handle: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut entry_size,
            alloced_addr,
            MAP_MEM_NAMED_REUSE | VM_PROT_DEFAULT,
            &mut entry_handle,
            parent_handle,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("make entry_handle return value: {kr}")
    });
    t.check(parent_handle == entry_handle, || {
        format!("NAMED_REUSE should re-use parent_handle: {parent_handle:#x} != {entry_handle:#x}")
    });
    Ok(())
}

/// `T_DECL(vm_memory_entry_parent_copy)`.
fn vm_memory_entry_parent_copy(t: &mut T) -> Result<(), Stop> {
    imports! {
        allocate: AllocateFn = "_mach_vm_allocate";
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
    }
    let me = task_self()?;
    let mut alloced_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe { allocate.get()?(me, &mut alloced_addr, KB16, VM_FLAGS_ANYWHERE) };
    t.require(kr == KERN_SUCCESS, || format!("mach_vm_allocate: {kr}"))?;

    let mut parent_size = KB16;
    let mut parent_handle: c_uint = 0;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut parent_size,
            alloced_addr,
            MAP_MEM_VM_COPY | VM_PROT_DEFAULT,
            &mut parent_handle,
            0,
        )
    };
    t.require(kr == KERN_SUCCESS, || {
        format!("make parent_handle return value: {kr}")
    })?;

    let mut entry_size = KB16;
    let invalid_handle: c_uint = 0xdeadbeef;
    let mut entry_handle = invalid_handle;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut entry_size,
            alloced_addr,
            MAP_MEM_VM_COPY | VM_PROT_DEFAULT,
            &mut entry_handle,
            parent_handle,
        )
    };
    t.check(kr == KERN_INVALID_ARGUMENT, || {
        format!("make entry_handle return value: {kr}")
    });
    t.check(entry_handle == invalid_handle, || {
        "make entry_handle handle unchanged on error".into()
    });
    t.check(entry_size == KB16, || {
        "make entry_handle size unchanged on error".into()
    });
    Ok(())
}

/// `T_DECL(vm_memory_entry_from_parent_entry_insufficient_permissions)`.
fn vm_memory_entry_from_parent_entry_insufficient_permissions(t: &mut T) -> Result<(), Stop> {
    imports! {
        host_self: HostSelfFn = "_mach_host_self";
        object_entry: ObjectEntryFn = "_mach_memory_object_memory_entry_64";
        make_entry: MakeEntryFn = "_mach_make_memory_entry_64";
        map: MapFn = "_mach_vm_map";
    }
    let me = task_self()?;
    let mut parent_handle: c_uint = 0;
    // SAFETY: a writable handle.
    let kr = unsafe {
        object_entry.get()?(
            host_self.get()?(),
            1,
            KB16,
            VM_PROT_READ,
            0,
            &mut parent_handle,
        )
    };
    t.require(kr == KERN_SUCCESS, || {
        format!("make parent_handle return value: {kr}")
    })?;

    let mut entry_size = KB16;
    let invalid_handle: c_uint = 0xdeadbeef;
    let mut entry_handle = invalid_handle;
    // SAFETY: writable size and handle.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut entry_size,
            0,
            VM_PROT_READ | VM_PROT_WRITE,
            &mut entry_handle,
            parent_handle,
        )
    };
    t.check(kr == KERN_PROTECTION_FAILURE, || {
        format!("return value without mask_permissions: {kr}")
    });
    t.check(entry_handle == invalid_handle, || {
        "handle unchanged on failure".into()
    });
    t.check(entry_size == KB16, || "size unchanged on failure".into());

    // SAFETY: as above.
    let kr = unsafe {
        make_entry.get()?(
            me,
            &mut entry_size,
            0,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_IS_MASK,
            &mut entry_handle,
            parent_handle,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("return value with mask_permissions: {kr}")
    });

    let map = map.get()?;
    let mut alloced_addr = 0;
    // SAFETY: a writable address.
    let kr = unsafe {
        map(
            me,
            &mut alloced_addr,
            KB16,
            0,
            VM_FLAGS_ANYWHERE,
            parent_handle,
            0,
            0,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_DEFAULT,
        )
    };
    t.check(kr == KERN_INVALID_RIGHT, || {
        format!("entry shouldn't have write permissions: {kr}")
    });
    // SAFETY: as above.
    let kr = unsafe {
        map(
            me,
            &mut alloced_addr,
            KB16,
            0,
            VM_FLAGS_ANYWHERE,
            parent_handle,
            0,
            0,
            VM_PROT_READ,
            VM_PROT_READ,
            VM_INHERIT_DEFAULT,
        )
    };
    t.check(kr == KERN_SUCCESS, || {
        format!("entry should have read permissions: {kr}")
    });
    Ok(())
}

const CASES: &[Case] = &[
    Case {
        name: "mach_vm_map_unaligned",
        kind: Kind::Upstream,
        source: "tests/vm/mach_vm_map.c",
        timeout_secs: 60,
        run: mach_vm_map_unaligned,
    },
    Case {
        name: "vm_map_enter_mem_object_overflow",
        kind: Kind::Upstream,
        source: "tests/vm/mach_vm_map.c",
        timeout_secs: 20,
        run: vm_map_enter_mem_object_overflow,
    },
    Case {
        name: "memory_entry_page_counts",
        kind: Kind::Upstream,
        source: "tests/vm/vm_memory_entry.c",
        timeout_secs: 20,
        run: memory_entry_page_counts,
    },
    Case {
        name: "vm_memory_entry_parent",
        kind: Kind::Upstream,
        source: "tests/vm/vm_memory_entry_parent_test.c",
        timeout_secs: 20,
        run: vm_memory_entry_parent,
    },
    Case {
        name: "vm_memory_entry_named_reuse_parent",
        kind: Kind::Upstream,
        source: "tests/vm/vm_memory_entry_parent_test.c",
        timeout_secs: 20,
        run: vm_memory_entry_named_reuse_parent,
    },
    Case {
        name: "vm_memory_entry_parent_copy",
        kind: Kind::Upstream,
        source: "tests/vm/vm_memory_entry_parent_test.c",
        timeout_secs: 20,
        run: vm_memory_entry_parent_copy,
    },
    Case {
        name: "vm_memory_entry_from_parent_entry_insufficient_permissions",
        kind: Kind::Upstream,
        source: "tests/vm/vm_memory_entry_parent_test.c",
        timeout_secs: 20,
        run: vm_memory_entry_from_parent_entry_insufficient_permissions,
    },
];

#[test]
fn xnu_vm_conformance() {
    conformance::run("xnu_vm_conformance", "xnu", UPSTREAM, CASES);
}
