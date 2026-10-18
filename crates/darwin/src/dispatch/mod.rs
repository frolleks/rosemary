pub mod block;
pub mod data;
pub mod object;
pub mod queue;
pub mod source;
pub mod sync;
pub mod time;

use std::ffi::c_void;
use std::sync::atomic::{AtomicI64, Ordering};

/// The states a `dispatch_once_t` passes through.
///
/// Darwin's is a `long` the caller zero-initializes, so zero has to mean "not
/// yet". The other two values are this implementation's own: nothing reads a
/// `dispatch_once_t` except `dispatch_once`.
const NOT_YET: i64 = 0;
const RUNNING: i64 = 1;
const DONE: i64 = -1;

/// `void dispatch_once_f(dispatch_once_t *, void *context, dispatch_function_t)`.
///
/// # Safety
///
/// `predicate` must be a `long` that started at zero and is used for nothing
/// else, and `function` must be callable with `context`.
unsafe extern "C" fn once_f(
    predicate: *mut c_void,
    context: *mut c_void,
    function: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    let Some(function) = function else {
        return;
    };
    // SAFETY: the caller's obligation for the predicate, and `function` is
    // callable with `context` by the same.
    unsafe { once_with(predicate, || function(context)) };
}

/// `void dispatch_once(dispatch_once_t *, dispatch_block_t)`.
///
/// The block is not copied: it has run before this returns, so it cannot outlive
/// the caller's frame the way an asynchronous one would.
///
/// # Safety
///
/// As [`once_f`], and `block` is a block whose `invoke` is callable here.
unsafe extern "C" fn once(predicate: *mut c_void, block: u64) {
    if block == 0 {
        return;
    }
    unsafe { once_with(predicate, || block::invoke(block)) };
}

/// Run `body` the first time this predicate is used, and never again.
///
/// # Safety
///
/// `predicate` must be a `long` that started at zero and is used for nothing
/// else, and `body` must be callable from this thread.
unsafe fn once_with(predicate: *mut c_void, body: impl FnOnce()) {
    if predicate.is_null() {
        return;
    }
    // SAFETY: the caller's obligation. `AtomicI64` and `long` have the same
    // size and alignment, and nothing else touches this word.
    let state = unsafe { &*(predicate as *const AtomicI64) };
    if state.load(Ordering::Acquire) == DONE {
        return;
    }
    // Spun rather than parked. A `dispatch_once` body is short by construction -
    // it is what a lazy global is initialized by - and a wait here would need a
    // futex per predicate, which is a table keyed on an address a caller may
    // free. Recursion into the same predicate is a deadlock on Darwin too.
    loop {
        match state.compare_exchange(NOT_YET, RUNNING, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(DONE) => return,
            Err(_) => std::hint::spin_loop(),
        }
    }
    body();
    state.store(DONE, Ordering::Release);
}

/// `_dispatch_main_q`, and a note that the thread binding it is the main one.
///
/// Recorded here rather than at start-up because this is the call that runs on
/// the thread the program was loaded on, which is what `dispatch_get_main_queue`
/// means by main.
fn main_queue() -> u64 {
    queue::note_main_thread();
    queue::main_queue()
}

/// `void dispatch_suspend(dispatch_object_t)`.
unsafe extern "C" fn suspend(handle: u64) {
    // SAFETY: the guest's live object.
    match unsafe { object::header(handle) }.map(object::Header::kind) {
        Some(object::Kind::Queue) => queue::suspend(handle),
        Some(object::Kind::Source) => source::suspend(handle),
        _ => {}
    }
}

/// `void dispatch_resume(dispatch_object_t)`.
unsafe extern "C" fn resume(handle: u64) {
    // SAFETY: the guest's live object.
    match unsafe { object::header(handle) }.map(object::Header::kind) {
        Some(object::Kind::Queue) => queue::resume(handle),
        Some(object::Kind::Source) => source::resume(handle),
        _ => {}
    }
}

/// `void dispatch_activate(dispatch_object_t)`. Queues here are never created
/// inactive, so only a source has anything to do.
unsafe extern "C" fn activate(handle: u64) {
    source::activate(handle);
}

/// `boolean_t voucher_mach_msg_set(mach_msg_header_t *)`: put the current
/// voucher in an outgoing message.
///
/// There are no Mach vouchers here, which makes this libdispatch's own
/// `!VOUCHER_USE_MACH_VOUCHER` build of it: false, and the message untouched -
/// the answer Apple's gives a message that already carries a voucher, and so
/// one every caller handles.
unsafe extern "C" fn voucher_mach_msg_set(_msg: *mut std::ffi::c_void) -> u32 {
    0
}

/// `void voucher_mach_msg_clear(mach_msg_header_t *)`: the build above's
/// does nothing, there being no voucher it could have set.
unsafe extern "C" fn voucher_mach_msg_clear(_msg: *mut std::ffi::c_void) {}

exports::exports! {
    functions {
        "dispatch_queue_create" => queue::queue_create,
        "voucher_mach_msg_set" => voucher_mach_msg_set,
        "voucher_mach_msg_clear" => voucher_mach_msg_clear,
        "dispatch_queue_create_with_target" => queue::queue_create_with_target,
        "dispatch_queue_get_label" => queue::queue_get_label,
        "dispatch_queue_set_specific" => queue::queue_set_specific,
        "dispatch_queue_get_specific" => queue::queue_get_specific,
        "dispatch_get_specific" => queue::get_specific,
        "dispatch_set_target_queue" => queue::set_target_queue,
        "dispatch_get_global_queue" => queue::get_global_queue,
        "dispatch_async" => queue::async_,
        "dispatch_async_f" => queue::async_f,
        "dispatch_sync" => queue::sync,
        "dispatch_sync_f" => queue::sync_f,
        "dispatch_after" => queue::after,
        "dispatch_after_f" => queue::after_f,
        "dispatch_once" => once,
        "dispatch_once_f" => once_f,
        "dispatch_group_create" => sync::group_create,
        "dispatch_group_enter" => sync::group_enter,
        "dispatch_group_leave" => sync::group_leave,
        "dispatch_group_notify" => sync::group_notify,
        "dispatch_group_notify_f" => sync::group_notify_f,
        "dispatch_group_async_f" => sync::group_async_f,
        "dispatch_group_async" => sync::group_async,
        "dispatch_apply_f" => sync::apply_f,
        "dispatch_group_wait" => sync::group_wait,
        "dispatch_semaphore_create" => sync::semaphore_create,
        "dispatch_semaphore_signal" => sync::semaphore_signal,
        "dispatch_semaphore_wait" => sync::semaphore_wait,
        "dispatch_time" => time::time,
        "dispatch_walltime" => time::walltime,
        "dispatch_queue_attr_make_with_qos_class" => queue::attr_make_with_qos_class,
        "dispatch_main" => queue::dispatch_main,
        "dispatch_suspend" => suspend,
        "dispatch_resume" => resume,
        "dispatch_activate" => activate,
        "dispatch_source_create" => source::create,
        "dispatch_source_cancel" => source::cancel,
        "dispatch_source_testcancel" => source::testcancel,
        "dispatch_source_get_data" => source::get_data,
        "dispatch_source_get_extended_data" => source::get_extended_data,
        "dispatch_source_get_mask" => source::get_mask,
        "dispatch_source_get_handle" => source::get_handle,
        "dispatch_source_merge_data" => source::merge_data,
        "dispatch_source_set_timer" => source::set_timer,
        "dispatch_source_set_event_handler" => source::set_event_handler,
        "dispatch_source_set_event_handler_f" => source::set_event_handler_f,
        "dispatch_source_set_cancel_handler" => source::set_cancel_handler,
        "dispatch_source_set_cancel_handler_f" => source::set_cancel_handler_f,
        "dispatch_source_set_mandatory_cancel_handler" => source::set_mandatory_cancel_handler,
        "dispatch_source_set_mandatory_cancel_handler_f" => source::set_mandatory_cancel_handler_f,
        "dispatch_source_set_registration_handler" => source::set_registration_handler,
        "dispatch_source_set_registration_handler_f" => source::set_registration_handler_f,
        "dispatch_data_create" => data::create,
        "dispatch_data_get_size" => data::get_size,
        "dispatch_retain" => object::retain_entry,
        "dispatch_release" => object::release_entry,
        "dispatch_set_context" => object::set_context,
        "dispatch_get_context" => object::get_context,
        "dispatch_set_finalizer_f" => object::set_finalizer_f,
    }
    data {
        "__dispatch_main_q" => main_queue(),
        "__dispatch_queue_attr_concurrent" => queue::concurrent_attr(),
        "__dispatch_data_destructor_free" => data::destructor_free(),
        "__dispatch_source_type_data_add" => source::type_address(source::Type::DataAdd),
        "__dispatch_source_type_data_or" => source::type_address(source::Type::DataOr),
        "__dispatch_source_type_data_replace" => source::type_address(source::Type::DataReplace),
        "__dispatch_source_type_mach_send" => source::type_address(source::Type::MachSend),
        "__dispatch_source_type_mach_recv" => source::type_address(source::Type::MachRecv),
        "__dispatch_source_type_memorypressure" => source::type_address(source::Type::MemoryPressure),
        "__dispatch_source_type_proc" => source::type_address(source::Type::Proc),
        "__dispatch_source_type_read" => source::type_address(source::Type::Read),
        "__dispatch_source_type_signal" => source::type_address(source::Type::Signal),
        "__dispatch_source_type_timer" => source::type_address(source::Type::Timer),
        "__dispatch_source_type_vnode" => source::type_address(source::Type::Vnode),
        "__dispatch_source_type_write" => source::type_address(source::Type::Write),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn count(_context: *mut c_void) {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn the_body_runs_once_however_many_threads_ask() {
        let predicate = Box::leak(Box::new(0i64)) as *mut i64 as *mut c_void;
        let address = predicate as usize;
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(move || {
                    // SAFETY: a zero-initialized `long` this test owns.
                    unsafe { once_f(address as *mut c_void, std::ptr::null_mut(), Some(count)) };
                });
            }
        });
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        // And a null predicate is declined rather than dereferenced.
        // SAFETY: the null case returns before any load.
        unsafe { once_f(std::ptr::null_mut(), std::ptr::null_mut(), Some(count)) };
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    }
}
