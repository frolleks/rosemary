//! xnu task_policy conformance: Apple's `tests/task_policy.c`
//! (apple-oss-distributions/xnu at xnu-12377.1.9) built with `UNENTITLED`, as
//! the programs rosemary runs are, against the `task_policy_set`,
//! `task_policy_get` and `task_*_for_pid` a guest binds.
//!
//! The `foreign` cases spawn `sleep` and ask after its task. Here that needs
//! a second guest, which this harness - no process server, no Darwin `sleep`
//! - cannot start, so they are skipped, as are those upstream runs as root.
//!
//! ```text
//! cargo test -p darwin --test xnu_task_policy_conformance -- --nocapture
//! ```
#![cfg(not(target_os = "macos"))]

mod conformance;

use std::ffi::{c_int, c_uint};

use conformance::{Case, Kind, Stop, T, imports};

const UPSTREAM: &str = "xnu-12377.1.9 tests/task_policy.c";

const KERN_SUCCESS: c_int = 0;
const KERN_INVALID_ARGUMENT: c_int = 4;

const TASK_CATEGORY_POLICY: c_uint = 1;
const TASK_BASE_QOS_POLICY: c_uint = 8;
const TASK_QOS_POLICY_COUNT: c_uint = 2;
const TASK_CATEGORY_POLICY_COUNT: c_uint = 1;
const LATENCY_QOS_TIER_0: c_int = (0xFF << 16) | 1;
const THROUGHPUT_QOS_TIER_0: c_int = (0xFE << 16) | 1;

type ForPidFn = unsafe extern "C" fn(c_uint, c_int, *mut c_uint) -> c_int;
type PolicySetFn = unsafe extern "C" fn(c_uint, c_uint, *const c_int, c_uint) -> c_int;
type PolicyGetFn =
    unsafe extern "C" fn(c_uint, c_uint, *mut c_int, *mut c_uint, *mut c_uint) -> c_int;
type GetpidFn = unsafe extern "C" fn() -> c_int;

/// Which `*_for_pid` a case's setup takes its port from.
#[derive(Clone, Copy)]
enum Port {
    Task,
    Name,
    Inspect,
}

/// The port to this task a case's setup asks for: `mach_task_self()`, or
/// `task_name_for_pid`/`task_inspect_for_pid` on `getpid()` under
/// `T_SETUPBEGIN`.
fn own_port(t: &mut T, port: Port) -> Result<c_uint, Stop> {
    imports! {
        task_self: *const c_uint = "_mach_task_self_";
        getpid: GetpidFn = "_getpid";
        name_for_pid: ForPidFn = "_task_name_for_pid";
        inspect_for_pid: ForPidFn = "_task_inspect_for_pid";
    }
    // SAFETY: `mach_task_self_` is a word the runtime filled in.
    let me = unsafe { *task_self.get()? };
    let for_pid = match port {
        Port::Task => return Ok(me),
        Port::Name => name_for_pid.get()?,
        Port::Inspect => inspect_for_pid.get()?,
    };
    let mut out: c_uint = 0;
    // SAFETY: a writable `mach_port_name_t`.
    let kr = unsafe { for_pid(me, getpid.get()?(), &mut out) };
    t.require(kr == KERN_SUCCESS, || {
        format!("setup: *_for_pid returned {kr}")
    })?;
    Ok(out)
}

/// `task_policy_set(port, TASK_BASE_QOS_POLICY, tier 0, ...)`.
fn set_case(t: &mut T, port: Port, expected: c_int) -> Result<(), Stop> {
    imports! { policy_set: PolicySetFn = "_task_policy_set"; }
    let task = own_port(t, port)?;
    let qos = [LATENCY_QOS_TIER_0, THROUGHPUT_QOS_TIER_0];
    // SAFETY: the two words `TASK_QOS_POLICY_COUNT` says.
    let kr = unsafe {
        policy_set.get()?(
            task,
            TASK_BASE_QOS_POLICY,
            qos.as_ptr(),
            TASK_QOS_POLICY_COUNT,
        )
    };
    t.require(kr == expected, || {
        format!("task_policy_set returned {kr}, expected {expected}")
    })
}

/// `task_policy_get(port, TASK_CATEGORY_POLICY, ...)`.
fn get_case(t: &mut T, port: Port, expected: c_int) -> Result<(), Stop> {
    imports! { policy_get: PolicyGetFn = "_task_policy_get"; }
    let task = own_port(t, port)?;
    let mut role: [c_int; TASK_CATEGORY_POLICY_COUNT as usize] = [0];
    let mut count = TASK_CATEGORY_POLICY_COUNT;
    let mut get_default: c_uint = 0;
    // SAFETY: room for `count` words, and the count and flag are locals.
    let kr = unsafe {
        policy_get.get()?(
            task,
            TASK_CATEGORY_POLICY,
            role.as_mut_ptr(),
            &mut count,
            &mut get_default,
        )
    };
    t.require(kr == expected, || {
        format!("task_policy_get returned {kr}, expected {expected}")
    })
}

fn foreign(_t: &mut T) -> Result<(), Stop> {
    Err(Stop::Skip(
        "spawns `sleep` and takes its task: a second guest task, which this harness cannot start"
            .into(),
    ))
}

fn foreign_as_root(_t: &mut T) -> Result<(), Stop> {
    Err(Stop::Skip(
        "T_META_ASROOT, and a second guest task this harness cannot start".into(),
    ))
}

macro_rules! case {
    ($name:literal, $run:expr) => {
        Case {
            name: $name,
            kind: Kind::Upstream,
            source: "task_policy.c, UNENTITLED",
            timeout_secs: 30,
            run: $run,
        }
    };
}

const CASES: &[Case] = &[
    case!("task_policy_set_task_name", |t| set_case(
        t,
        Port::Name,
        KERN_INVALID_ARGUMENT
    )),
    case!("task_policy_set_task", |t| set_case(
        t,
        Port::Task,
        KERN_SUCCESS
    )),
    case!("task_policy_set_inspect", |t| set_case(
        t,
        Port::Inspect,
        KERN_INVALID_ARGUMENT
    )),
    case!("task_policy_set_foreign_task", foreign_as_root),
    case!("task_policy_set_foreign_task_name", foreign_as_root),
    case!("task_policy_set_foreign_task_inspect", foreign_as_root),
    case!("task_policy_get_name", |t| get_case(
        t,
        Port::Name,
        KERN_INVALID_ARGUMENT
    )),
    case!("task_policy_get_task", |t| get_case(
        t,
        Port::Task,
        KERN_SUCCESS
    )),
    case!("task_policy_get_inspect", |t| get_case(
        t,
        Port::Inspect,
        KERN_SUCCESS
    )),
    case!("task_policy_get_foreign_task_inspect", foreign_as_root),
    case!("task_policy_get_foreign_task", foreign_as_root),
    case!("task_policy_get_foreign_task_name", foreign),
];

#[test]
fn xnu_task_policy_conformance() {
    conformance::run("xnu_task_policy_conformance", "xnu", UPSTREAM, CASES);
}
