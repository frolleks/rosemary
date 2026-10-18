//! The legacy keychain calls - `SecKeychain*` and `SecKeychainItem*` - over the
//! store `SecItem*` keeps, as Apple's are over the same file-based keychain.
//!
//! Apple: Security, `OSX/libsecurity_keychain/lib/SecKeychain.cpp` and
//! `SecKeychainItem.cpp`, and `CCallbackMgr.cp` for the callbacks.
//!
//! One keychain holds items: the login keychain, which is the default and the
//! whole search list. Any other path opens - `SecKeychainOpen` never checks -
//! and holds nothing, as a keychain file that does not exist holds nothing; an
//! item added to one goes to the default keychain instead, which is what
//! Apple's `SecKeychainAddGenericPassword` does with a keychain that is not
//! there.

#![allow(non_snake_case)]

use std::ffi::{c_char, c_void};
use std::sync::{Arc, Mutex};

use corefoundation::base::{CFTypeID, CFTypeRef};
use corefoundation::runloop::{self, RunLoop};
use objc::class::Class;
use objc::object::Id;

use crate::keychain::{self, Identity};

type OSStatus = i32;
const SUCCESS: OSStatus = 0;
/// `errSecParam`.
const PARAM: OSStatus = -50;
/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: OSStatus = -25300;
/// `errSecDuplicateItem`.
const DUPLICATE_ITEM: OSStatus = -25299;
/// `errSecDuplicateCallback`: "A callback with the same name already exists."
const DUPLICATE_CALLBACK: OSStatus = -25297;
/// `errSecInvalidCallback`: "The specified callback function is not valid."
const INVALID_CALLBACK: OSStatus = -25298;
/// `errSecInvalidItemRef`.
const INVALID_ITEM_REF: OSStatus = -25304;
/// `errSecInvalidKeychain`.
const INVALID_KEYCHAIN: OSStatus = -25295;
/// `errSecNoSuchAttr`.
const NO_SUCH_ATTRIBUTE: OSStatus = -25303;
/// `errSecAllocate`.
const ALLOCATE: OSStatus = -108;

/// `SecKeychainEvent`.
pub(crate) mod event {
    pub const ADD: u32 = 3;
    pub const DELETE: u32 = 4;
    pub const UPDATE: u32 = 5;
}

/// The four-character codes the legacy calls name item classes and attributes
/// by.
const fn four(code: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*code)
}

/// `kSecGenericPasswordItemClass`, the class these calls store under - the
/// same `"genp"` `kSecClassGenericPassword` is.
const GENERIC_PASSWORD: &str = "genp";

/// `kSecServiceItemAttr`, `kSecAccountItemAttr`, `kSecLabelItemAttr`.
const SERVICE: u32 = four(b"svce");
const ACCOUNT: u32 = four(b"acct");
const LABEL: u32 = four(b"labl");

enum Payload {
    Keychain {
        path: String,
    },
    Item {
        /// A reference of the item's own, as Apple's item holds its keychain.
        keychain: CFTypeRef,
        identity: Identity,
    },
}

impl Drop for Payload {
    fn drop(&mut self) {
        if let Payload::Item { keychain, .. } = self {
            // SAFETY: the reference `item_object` took.
            unsafe { corefoundation::api::CFRelease(*keychain) };
        }
    }
}

#[repr(C)]
struct Body {
    isa: *const Class,
    payload: *mut Payload,
}

unsafe extern "C" fn dealloc(receiver: Id, _sel: objc::sel::Sel) {
    // SAFETY: this module's layout, and the payload `new` boxed.
    unsafe {
        let body = receiver as *mut Body;
        drop(Box::from_raw((*body).payload));
        objc::arc::finalize(receiver);
    }
}

/// `SecKeychain` or `SecKeychainItem`: each its own CoreFoundation type.
fn class(item: bool) -> &'static Class {
    static CLASSES: [std::sync::OnceLock<usize>; 2] = [const { std::sync::OnceLock::new() }; 2];
    let (cell, name) = match item {
        false => (&CLASSES[0], c"SecKeychain"),
        true => (&CLASSES[1], c"SecKeychainItem"),
    };
    let pointer = *cell.get_or_init(|| {
        let class = corefoundation::base::register(name, None, size_of::<Body>(), true);
        class.replace_method(
            objc::sel::get("dealloc"),
            dealloc as *const c_void,
            c"v16@0:8",
        );
        objc::class::ptr(class) as usize
    });
    // SAFETY: a class registered above and kept for the process.
    unsafe { objc::class::from_ptr(pointer as *const Class).expect("a keychain class") }
}

fn new(payload: Payload) -> CFTypeRef {
    let item = matches!(payload, Payload::Item { .. });
    // SAFETY: `Body` is the registered layout.
    let body = unsafe { corefoundation::base::allocate::<Body>(class(item)) };
    if body.is_null() {
        return std::ptr::null();
    }
    // SAFETY: a freshly allocated body.
    unsafe { (*body).payload = Box::into_raw(Box::new(payload)) };
    body as CFTypeRef
}

/// # Safety
///
/// `object` is null or an object this runtime allocated, live for `'a`.
unsafe fn payload<'a>(object: CFTypeRef, item: bool) -> Option<&'a Payload> {
    // SAFETY: the caller's guarantee.
    if object.is_null() || !unsafe { corefoundation::base::is_kind_of(object, class(item)) } {
        return None;
    }
    // SAFETY: a body of this class, whose payload lives as long as it does.
    Some(unsafe { &*(*(object as *const Body)).payload })
}

/// `CFTypeID SecKeychainGetTypeID(void)`.
pub extern "C" fn SecKeychainGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(class(false))
}

/// `CFTypeID SecKeychainItemGetTypeID(void)`.
pub extern "C" fn SecKeychainItemGetTypeID() -> CFTypeID {
    corefoundation::base::type_id_of(class(true))
}

/// The login keychain's path, which is where Apple's lives.
fn default_path() -> String {
    format!(
        "{}/Library/Keychains/login.keychain-db",
        foundation::home_directory()
    )
}

/// A keychain name as the storage manager files it: a bare name is in
/// `~/Library/Keychains`, and the login keychain answers to its pre-10.12 name
/// too, which is the one most callers still spell.
fn canonical(path: &str) -> String {
    let path = match path.starts_with('/') {
        true => path.to_string(),
        false => format!("{}/Library/Keychains/{path}", foundation::home_directory()),
    };
    let default = default_path();
    match default.strip_suffix("-db") == Some(path.as_str()) {
        true => default,
        false => path,
    }
}

/// Every keychain object made, by path, each held for the process.
///
/// Apple's storage manager keeps one `KeychainImpl` per database and hands the
/// same one to every caller that names it, so two opens of one path are one
/// object and compare equal by identity.
static KEYCHAINS: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

/// The keychain at `path`, as a reference the caller owns.
fn keychain_object(path: &str) -> CFTypeRef {
    let path = canonical(path);
    let mut table = KEYCHAINS.lock().unwrap_or_else(|e| e.into_inner());
    let object = match table.iter().find(|(p, _)| *p == path) {
        Some(&(_, object)) => object as CFTypeRef,
        None => {
            let object = new(Payload::Keychain { path: path.clone() });
            if object.is_null() {
                return object;
            }
            table.push((path, object as usize));
            object
        }
    };
    // SAFETY: a live keychain the table holds.
    unsafe { corefoundation::api::CFRetain(object) }
}

/// The path of a keychain object.
///
/// # Safety
///
/// As [`payload`].
unsafe fn keychain_path<'a>(object: CFTypeRef) -> Option<&'a str> {
    // SAFETY: the caller's guarantee.
    match unsafe { payload(object, false) } {
        Some(Payload::Keychain { path }) => Some(path),
        _ => None,
    }
}

/// An item object for a stored item, in the login keychain, owned by the
/// caller.
fn item_object(identity: &Identity) -> CFTypeRef {
    new(Payload::Item {
        keychain: keychain_object(&default_path()),
        identity: identity.clone(),
    })
}

/// # Safety
///
/// As [`payload`].
unsafe fn item_identity<'a>(object: CFTypeRef) -> Option<&'a Identity> {
    // SAFETY: the caller's guarantee.
    match unsafe { payload(object, true) } {
        Some(Payload::Item { identity, .. }) => Some(identity),
        _ => None,
    }
}

/// Whether a search through `keychain_or_array` reaches the login keychain:
/// `StorageManager::optionalSearchList`, where null is the search list - the
/// login keychain - and anything but a keychain or an array of them is refused.
///
/// # Safety
///
/// `keychain_or_array` is null or a live object.
unsafe fn searches_default(keychain_or_array: CFTypeRef) -> Result<bool, OSStatus> {
    use corefoundation::api::{
        CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFGetTypeID,
    };
    if keychain_or_array.is_null() {
        return Ok(true);
    }
    let default = default_path();
    // SAFETY: a live object, per the caller.
    if let Some(path) = unsafe { keychain_path(keychain_or_array) } {
        return Ok(path == default);
    }
    // SAFETY: as above.
    if unsafe { CFGetTypeID(keychain_or_array) } != unsafe { CFArrayGetTypeID() } {
        return Err(PARAM);
    }
    let mut found = false;
    // SAFETY: a live array and its elements.
    for index in 0..unsafe { CFArrayGetCount(keychain_or_array) } {
        let element = unsafe { CFArrayGetValueAtIndex(keychain_or_array, index) };
        match unsafe { keychain_path(element) } {
            Some(path) => found |= path == default,
            None => return Err(INVALID_KEYCHAIN),
        }
    }
    Ok(found)
}

/// `OSStatus SecKeychainOpen(const char *pathName, SecKeychainRef *)`: a
/// keychain object for the path, whether or not there is a keychain there -
/// Apple's opens lazily, and reports a missing file only when it is used.
///
/// # Safety
///
/// `path` is null or a C string, and `keychain` is null or writable.
pub unsafe extern "C" fn SecKeychainOpen(
    path: *const c_char,
    keychain: *mut CFTypeRef,
) -> OSStatus {
    if path.is_null() || keychain.is_null() {
        return PARAM;
    }
    // SAFETY: a C string, per the caller.
    let path = unsafe { std::ffi::CStr::from_ptr(path) }.to_string_lossy();
    let object = keychain_object(&path);
    if object.is_null() {
        return ALLOCATE;
    }
    // SAFETY: writable, checked above.
    unsafe { keychain.write(object) };
    SUCCESS
}

/// `OSStatus SecKeychainCopySearchList(CFArrayRef *)`: the login keychain.
///
/// # Safety
///
/// `list` is null or writable.
pub unsafe extern "C" fn SecKeychainCopySearchList(list: *mut CFTypeRef) -> OSStatus {
    if list.is_null() {
        return PARAM;
    }
    let login = keychain_object(&default_path());
    let array = corefoundation::collections::new_array(
        &[login],
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    // SAFETY: the array took its own reference.
    unsafe { corefoundation::api::CFRelease(login) };
    // SAFETY: writable, checked above.
    unsafe { list.write(array) };
    SUCCESS
}

/// `OSStatus SecKeychainCopyDefault(SecKeychainRef *)`: the login keychain.
///
/// # Safety
///
/// `keychain` is null or writable.
pub unsafe extern "C" fn SecKeychainCopyDefault(keychain: *mut CFTypeRef) -> OSStatus {
    if keychain.is_null() {
        return PARAM;
    }
    // SAFETY: writable, checked above.
    unsafe { keychain.write(keychain_object(&default_path())) };
    SUCCESS
}

/// A C string argument of a stated length, or `None` for an absent one -
/// either a null pointer or a zero length, which is how Apple's tells a
/// wildcard from a name.
///
/// # Safety
///
/// `text` is null or readable for `length` bytes.
unsafe fn counted(length: u32, text: *const c_char) -> Option<String> {
    if text.is_null() || length == 0 {
        return None;
    }
    // SAFETY: readable for `length` bytes, per the caller.
    let bytes = unsafe { std::slice::from_raw_parts(text as *const u8, length as usize) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// `bytes` in a block the caller frees with `SecKeychainItemFreeContent` - from
/// the allocator the guest's own `free` uses, since a caller that frees it with
/// `free` is common enough to have to work too.
fn allocated(bytes: &[u8]) -> Option<*mut c_void> {
    // SAFETY: a fresh block, at least one byte so that even an empty value has
    // a pointer to free.
    let block = unsafe { darwin::heap::malloc(bytes.len().max(1)) };
    if block.is_null() {
        return None;
    }
    // SAFETY: writable for at least `bytes.len()`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), block as *mut u8, bytes.len()) };
    Some(block)
}

/// `OSStatus SecKeychainAddGenericPassword(SecKeychainRef, UInt32
/// serviceNameLength, const char *serviceName, UInt32 accountNameLength, const
/// char *accountName, UInt32 passwordLength, const void *passwordData,
/// SecKeychainItemRef *itemRef)`.
///
/// `errSecDuplicateItem`, with `*itemRef` left alone, for a service and account
/// already stored - Apple's primary key for a generic password.
///
/// # Safety
///
/// The strings and the password are null or readable for their lengths;
/// `keychain` is null or a live object; `item` is null or writable.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn SecKeychainAddGenericPassword(
    _keychain: CFTypeRef,
    service_length: u32,
    service: *const c_char,
    account_length: u32,
    account: *const c_char,
    password_length: u32,
    password: *const c_void,
    item: *mut CFTypeRef,
) -> OSStatus {
    if password_length != 0 && password.is_null() {
        return PARAM;
    }
    let identity = Identity {
        class: GENERIC_PASSWORD.to_string(),
        // SAFETY: the caller's guarantee.
        service: unsafe { counted(service_length, service) }.unwrap_or_default(),
        account: unsafe { counted(account_length, account) }.unwrap_or_default(),
    };
    let value = match password_length {
        0 => Vec::new(),
        // SAFETY: readable for `password_length`, per the caller.
        n => unsafe { std::slice::from_raw_parts(password as *const u8, n as usize) }.to_vec(),
    };
    {
        let mut items = keychain::items();
        if items.contains_key(&identity) {
            return DUPLICATE_ITEM;
        }
        items.insert(identity.clone(), value);
        keychain::save(&items);
    }
    alert(event::ADD, &identity);
    if !item.is_null() {
        // SAFETY: writable, per the caller.
        unsafe { item.write(item_object(&identity)) };
    }
    SUCCESS
}

/// `OSStatus SecKeychainFindGenericPassword(CFTypeRef keychainOrArray, UInt32
/// serviceNameLength, const char *serviceName, UInt32 accountNameLength, const
/// char *accountName, UInt32 *passwordLength, void **passwordData,
/// SecKeychainItemRef *itemRef)`.
///
/// The first generic password matching what was named - an absent service or
/// account matches any - with its data in a block for
/// `SecKeychainItemFreeContent`.
///
/// # Safety
///
/// As [`SecKeychainAddGenericPassword`], with the out-parameters null or
/// writable.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn SecKeychainFindGenericPassword(
    keychain_or_array: CFTypeRef,
    service_length: u32,
    service: *const c_char,
    account_length: u32,
    account: *const c_char,
    password_length: *mut u32,
    password: *mut *mut c_void,
    item: *mut CFTypeRef,
) -> OSStatus {
    // SAFETY: the caller's guarantee.
    match unsafe { searches_default(keychain_or_array) } {
        Ok(true) => {}
        Ok(false) => return ITEM_NOT_FOUND,
        Err(status) => return status,
    }
    // SAFETY: the caller's guarantee.
    let service = unsafe { counted(service_length, service) };
    let account = unsafe { counted(account_length, account) };
    let found = keychain::items()
        .iter()
        .find(|(identity, _)| {
            identity.class == GENERIC_PASSWORD
                && service.as_ref().is_none_or(|s| *s == identity.service)
                && account.as_ref().is_none_or(|a| *a == identity.account)
        })
        .map(|(identity, value)| (identity.clone(), value.clone()));
    let Some((identity, value)) = found else {
        return ITEM_NOT_FOUND;
    };
    if !password.is_null() {
        let Some(block) = allocated(&value) else {
            return ALLOCATE;
        };
        // SAFETY: writable, per the caller.
        unsafe { password.write(block) };
    }
    if !password_length.is_null() {
        // SAFETY: as above.
        unsafe { password_length.write(value.len() as u32) };
    }
    if !item.is_null() {
        // SAFETY: as above.
        unsafe { item.write(item_object(&identity)) };
    }
    SUCCESS
}

/// `SecKeychainAttribute`: a tag, a length, and the bytes.
#[repr(C)]
pub struct Attribute {
    tag: u32,
    length: u32,
    data: *mut c_void,
}

/// `SecKeychainAttributeList`.
#[repr(C)]
pub struct AttributeList {
    count: u32,
    attributes: *mut Attribute,
}

/// `OSStatus SecKeychainItemCopyContent(SecKeychainItemRef, SecItemClass *,
/// SecKeychainAttributeList *attrList, UInt32 *length, void **outData)`: the
/// item's class, the attributes the list asks for by tag, and its data - each
/// value in a block for `SecKeychainItemFreeContent`.
///
/// # Safety
///
/// `item` is null or a live object; `list` is null or a list whose attributes
/// are writable; the other out-parameters are null or writable.
pub unsafe extern "C" fn SecKeychainItemCopyContent(
    item: CFTypeRef,
    item_class: *mut u32,
    list: *mut AttributeList,
    length: *mut u32,
    data: *mut *mut c_void,
) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some(identity) = (unsafe { item_identity(item) }) else {
        return INVALID_ITEM_REF;
    };
    let Some(value) = keychain::items().get(identity).cloned() else {
        return ITEM_NOT_FOUND;
    };
    if !item_class.is_null() {
        let code = match <[u8; 4]>::try_from(identity.class.as_bytes()) {
            Ok(code) => u32::from_be_bytes(code),
            Err(_) => 0,
        };
        // SAFETY: writable, per the caller.
        unsafe { item_class.write(code) };
    }
    // SAFETY: as above.
    if let Some(list) = unsafe { list.as_mut() }
        && list.count > 0
    {
        // SAFETY: `count` attributes, per the caller.
        let attributes =
            unsafe { std::slice::from_raw_parts_mut(list.attributes, list.count as usize) };
        // Every tag checked before any is filled, so that a failed call leaves
        // nothing behind to free.
        if attributes
            .iter()
            .any(|attribute| !matches!(attribute.tag, SERVICE | LABEL | ACCOUNT))
        {
            return NO_SUCH_ATTRIBUTE;
        }
        for attribute in attributes.iter_mut() {
            let text = match attribute.tag {
                ACCOUNT => identity.account.as_bytes(),
                _ => identity.service.as_bytes(),
            };
            attribute.length = text.len() as u32;
            attribute.data = allocated(text).unwrap_or(std::ptr::null_mut());
        }
    }
    if !data.is_null() {
        let Some(block) = allocated(&value) else {
            return ALLOCATE;
        };
        // SAFETY: writable, per the caller.
        unsafe { data.write(block) };
    }
    if !length.is_null() {
        // SAFETY: as above.
        unsafe { length.write(value.len() as u32) };
    }
    SUCCESS
}

/// `OSStatus SecKeychainItemFreeContent(SecKeychainAttributeList *, void
/// *data)`: `ItemImpl::freeContent` - the data, then each attribute's value,
/// which it clears.
///
/// # Safety
///
/// Each pointer is null or what a copy call of this module handed out.
pub unsafe extern "C" fn SecKeychainItemFreeContent(
    list: *mut AttributeList,
    data: *mut c_void,
) -> OSStatus {
    if !data.is_null() {
        // SAFETY: a block `allocated` made, per the caller.
        unsafe { darwin::heap::free(data) };
    }
    // SAFETY: as above.
    if let Some(list) = unsafe { list.as_mut() }
        && list.count > 0
        && !list.attributes.is_null()
    {
        // SAFETY: `count` attributes, per the caller.
        let attributes =
            unsafe { std::slice::from_raw_parts_mut(list.attributes, list.count as usize) };
        for attribute in attributes {
            if !attribute.data.is_null() {
                // SAFETY: a block `allocated` made.
                unsafe { darwin::heap::free(attribute.data) };
            }
            attribute.data = std::ptr::null_mut();
        }
    }
    SUCCESS
}

/// `OSStatus SecKeychainItemDelete(SecKeychainItemRef)`.
///
/// # Safety
///
/// `item` is null or a live object.
pub unsafe extern "C" fn SecKeychainItemDelete(item: CFTypeRef) -> OSStatus {
    // SAFETY: the caller's guarantee.
    let Some(identity) = (unsafe { item_identity(item) }) else {
        return INVALID_ITEM_REF;
    };
    {
        let mut items = keychain::items();
        if items.remove(identity).is_none() {
            return ITEM_NOT_FOUND;
        }
        keychain::save(&items);
    }
    alert(event::DELETE, identity);
    SUCCESS
}

/// `SecKeychainCallback`.
type Callback = unsafe extern "C" fn(u32, *mut CallbackInfo, *mut c_void) -> OSStatus;

/// `SecKeychainCallbackInfo`.
#[repr(C)]
pub struct CallbackInfo {
    version: u32,
    item: CFTypeRef,
    keychain: CFTypeRef,
    pid: i32,
}

/// One registered callback: `CCallbackMgr`'s `CallbackInfo`.
struct Registration {
    callback: usize,
    mask: u32,
    context: usize,
    /// The run loop of the thread that registered, where its events are
    /// delivered.
    run_loop: Arc<RunLoop>,
    /// Whether that run loop has been seen running. Apple's sends nothing to a
    /// loop it has not seen turn - "assume it's not being pumped" - since each
    /// event queued on one that never runs is a leak.
    active: bool,
    /// Events raised before the loop was seen to turn, sent when it is.
    ///
    /// Apple's events arrive from securityd a moment after the change, by which
    /// time a loop that is running has turned; here they are raised by the very
    /// call that made the change, before the loop has had any chance to. Held
    /// rather than dropped, then, and only a few: a loop that never runs gets
    /// the most recent [`PENDING_LIMIT`] and no more, which bounds the leak
    /// Apple's rule exists to prevent.
    pending: Vec<Box<Delivery>>,
}

/// How many events wait for a loop not yet seen to run.
const PENDING_LIMIT: usize = 64;

static CALLBACKS: Mutex<Vec<Registration>> = Mutex::new(Vec::new());

fn callbacks() -> std::sync::MutexGuard<'static, Vec<Registration>> {
    CALLBACKS.lock().unwrap_or_else(|e| e.into_inner())
}

/// `CCallbackMgr::cfrunLoopActive`: the loop with this address has turned, so
/// every callback registered on it may now be sent events.
unsafe extern "C" fn run_loop_active(_timer: CFTypeRef, info: *mut c_void) {
    let mut due = Vec::new();
    for registration in callbacks().iter_mut() {
        if Arc::as_ptr(&registration.run_loop) as usize == info as usize {
            registration.active = true;
            for delivery in registration.pending.drain(..) {
                due.push((Arc::clone(&registration.run_loop), delivery));
            }
        }
    }
    for (run_loop, delivery) in due {
        schedule(&run_loop, delivery);
    }
}

/// `OSStatus SecKeychainAddCallback(SecKeychainCallback, SecKeychainEventMask,
/// void *userContext)`: call `callback` for each event in `mask`, on this
/// thread's run loop.
///
/// Keyed by the function alone, as `CallbackInfo::operator==` is: a second
/// registration of the same function is `errSecDuplicateCallback`, whatever its
/// context.
///
/// The events delivered are this process's own: items it adds, changes and
/// deletes through either API. Apple's also carries other processes' events,
/// through securityd; here no other process shares this keychain store's
/// notifications, and the lock, unlock, password, list and trust settings
/// events have nothing that raises them.
///
/// # Safety
///
/// `callback` is null or a function of the `SecKeychainCallback` type.
pub unsafe extern "C" fn SecKeychainAddCallback(
    callback: Option<Callback>,
    mask: u32,
    context: *mut c_void,
) -> OSStatus {
    let Some(callback) = callback else {
        return PARAM;
    };
    let run_loop = runloop::current();
    {
        let mut table = callbacks();
        if table.iter().any(|r| r.callback == callback as usize) {
            return DUPLICATE_CALLBACK;
        }
        table.push(Registration {
            callback: callback as usize,
            mask,
            context: context as usize,
            run_loop: Arc::clone(&run_loop),
            active: false,
            pending: Vec::new(),
        });
    }
    // Apple's way to learn the loop is serviced: a timer due now, which fires
    // the first time the loop runs in its default mode.
    let timer = runloop::new_timer(
        std::time::Duration::ZERO,
        None,
        Some(run_loop_active),
        Arc::as_ptr(&run_loop) as usize,
    );
    run_loop.add_timer(&timer, runloop::DEFAULT_MODE);
    SUCCESS
}

/// `OSStatus SecKeychainRemoveCallback(SecKeychainCallback)`:
/// `errSecInvalidCallback` for a function not registered.
///
/// # Safety
///
/// None: the function is compared, not called.
pub unsafe extern "C" fn SecKeychainRemoveCallback(callback: Option<Callback>) -> OSStatus {
    let Some(callback) = callback else {
        return PARAM;
    };
    let mut table = callbacks();
    let before = table.len();
    table.retain(|r| r.callback != callback as usize);
    match table.len() == before {
        true => INVALID_CALLBACK,
        false => SUCCESS,
    }
}

/// One event on its way to one callback: `CallbackMgrInfo`.
struct Delivery {
    event: u32,
    info: CallbackInfo,
    callback: usize,
    context: usize,
}

// SAFETY: the two objects are references this delivery owns, and retaining and
// releasing a CoreFoundation object is safe from any thread.
unsafe impl Send for Delivery {}

impl Drop for Delivery {
    fn drop(&mut self) {
        for object in [self.info.item, self.info.keychain] {
            if !object.is_null() {
                // SAFETY: the references `alert` took for this delivery.
                unsafe { corefoundation::api::CFRelease(object) };
            }
        }
    }
}

/// Queue a delivery on `run_loop`, in its default mode, as Apple's does with a
/// timer due now.
fn schedule(run_loop: &Arc<RunLoop>, delivery: Box<Delivery>) {
    let timer = runloop::new_timer(
        std::time::Duration::ZERO,
        None,
        Some(tell_client),
        Box::into_raw(delivery) as usize,
    );
    run_loop.add_timer(&timer, runloop::DEFAULT_MODE);
}

/// `CCallbackMgr::tellClient`: call the callback, then let go of the item and
/// keychain it was shown.
unsafe extern "C" fn tell_client(_timer: CFTypeRef, info: *mut c_void) {
    // SAFETY: the box `schedule` leaked for this timer, taken back once.
    let mut delivery = unsafe { Box::from_raw(info as *mut Delivery) };
    // SAFETY: a `SecKeychainCallback` the program registered.
    let callback: Callback = unsafe { std::mem::transmute(delivery.callback) };
    // SAFETY: as above, with the info this delivery owns.
    unsafe {
        callback(
            delivery.event,
            &mut delivery.info,
            delivery.context as *mut c_void,
        )
    };
}

/// `CCallbackMgr::AlertClients`: send `event` about `identity` to every
/// callback that asked for it, on its run loop in the default mode - now if
/// the loop is known to run, and once it is seen to otherwise.
pub(crate) fn alert(event: u32, identity: &Identity) {
    let bit = 1u32 << event;
    let pid = darwin::process::guest_pid(starnix::process::me());
    let mut due = Vec::new();
    for registration in callbacks().iter_mut().filter(|r| r.mask & bit != 0) {
        let delivery = Box::new(Delivery {
            event,
            info: CallbackInfo {
                version: 0,
                item: item_object(identity),
                keychain: keychain_object(&default_path()),
                pid,
            },
            callback: registration.callback,
            context: registration.context,
        });
        match registration.active {
            true => due.push((Arc::clone(&registration.run_loop), delivery)),
            false => {
                if registration.pending.len() == PENDING_LIMIT {
                    registration.pending.remove(0);
                }
                registration.pending.push(delivery);
            }
        }
    }
    // Outside the table's lock: a loop on another thread may fire at once, and
    // its callback is entitled to add or remove callbacks.
    for (run_loop, delivery) in due {
        schedule(&run_loop, delivery);
    }
}

exports::exports! {
    functions {
        "SecKeychainGetTypeID" => SecKeychainGetTypeID,
        "SecKeychainItemGetTypeID" => SecKeychainItemGetTypeID,
        "SecKeychainOpen" => SecKeychainOpen,
        "SecKeychainCopySearchList" => SecKeychainCopySearchList,
        "SecKeychainCopyDefault" => SecKeychainCopyDefault,
        "SecKeychainAddGenericPassword" => SecKeychainAddGenericPassword,
        "SecKeychainFindGenericPassword" => SecKeychainFindGenericPassword,
        "SecKeychainItemCopyContent" => SecKeychainItemCopyContent,
        "SecKeychainItemFreeContent" => SecKeychainItemFreeContent,
        "SecKeychainItemDelete" => SecKeychainItemDelete,
        "SecKeychainAddCallback" => SecKeychainAddCallback,
        "SecKeychainRemoveCallback" => SecKeychainRemoveCallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// One keychain test at a time, as Apple's run: a callback registered for
    /// add events hears of every item added - another test's too - and
    /// `kc-21`'s deletes what it hears of.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn retain_count(object: CFTypeRef) -> isize {
        // SAFETY: a live object of the test's.
        unsafe { corefoundation::api::CFGetRetainCount(object) as isize }
    }

    /// Apple's `kc-10-item-add-generic`, on the login keychain rather than a
    /// keychain file of the test's own, which this store has no way to make.
    #[test]
    fn kc_10_item_add_generic() {
        foundation::bootstrap();
        let _serial = serial();
        let mut keychain: CFTypeRef = std::ptr::null();
        // SAFETY: writable out-parameters, and the strings at their lengths.
        unsafe {
            assert_eq!(SecKeychainCopyDefault(&mut keychain), SUCCESS);
            let mut item: CFTypeRef = std::ptr::null();
            let add = |item: &mut CFTypeRef| {
                SecKeychainAddGenericPassword(
                    keychain,
                    7,
                    c"service".as_ptr(),
                    7,
                    c"account".as_ptr(),
                    4,
                    c"test".as_ptr() as *const c_void,
                    item,
                )
            };
            assert_eq!(add(&mut item), SUCCESS, "add generic password");
            assert!(!item.is_null(), "is item non NULL");
            let mut old_item = item;
            assert_eq!(
                add(&mut old_item),
                DUPLICATE_ITEM,
                "add generic password again"
            );
            assert_eq!(item, old_item, "item is unchanged");

            let mut item_class = 0u32;
            let mut attributes = [
                Attribute {
                    tag: ACCOUNT,
                    length: 0,
                    data: std::ptr::null_mut(),
                },
                Attribute {
                    tag: SERVICE,
                    length: 0,
                    data: std::ptr::null_mut(),
                },
            ];
            let mut list = AttributeList {
                count: 2,
                attributes: attributes.as_mut_ptr(),
            };
            let (mut length, mut data) = (0u32, std::ptr::null_mut());
            assert_eq!(
                SecKeychainItemCopyContent(
                    item,
                    &mut item_class,
                    &mut list,
                    &mut length,
                    &mut data
                ),
                SUCCESS,
                "SecKeychainItemCopyContent"
            );
            assert_eq!(length, 4, "item data is right length");
            assert_eq!(
                std::slice::from_raw_parts(data as *const u8, 4),
                b"test",
                "Item data is right"
            );
            assert_eq!(item_class, four(b"genp"));
            assert_eq!(
                std::slice::from_raw_parts(
                    attributes[0].data as *const u8,
                    attributes[0].length as usize
                ),
                b"account"
            );
            assert_eq!(
                SecKeychainItemFreeContent(&mut list, data),
                SUCCESS,
                "SecKeychainItemFreeContent"
            );
            assert!(attributes.iter().all(|a| a.data.is_null()));

            assert_eq!(retain_count(item), 1, "item retaincount is 1");
            assert!(
                retain_count(keychain) >= 2,
                "keychain retaincount is at least 2"
            );
            assert_eq!(SecKeychainItemDelete(item), SUCCESS);
            corefoundation::api::CFRelease(item);
            assert!(
                retain_count(keychain) >= 1,
                "keychain retaincount is at least 1"
            );
            corefoundation::api::CFRelease(keychain);
        }
    }

    static CALLBACK_CALLED: AtomicBool = AtomicBool::new(false);
    /// What `kc-21`'s callback checked, in its order: each a check's name and
    /// whether it held. A callback cannot panic across the C boundary.
    static CALLBACK_CHECKS: Mutex<Vec<(&str, bool)>> = Mutex::new(Vec::new());
    const PASSWORD: &[u8] = b"password\0";

    unsafe extern "C" fn kc_21_callback(
        event: u32,
        info: *mut CallbackInfo,
        context: *mut c_void,
    ) -> OSStatus {
        let mut checks = CALLBACK_CHECKS.lock().unwrap();
        checks.push(("Got an incorrect keychain event", event == event::ADD));
        checks.push(("context is null", !context.is_null()));
        checks.push(("info is NULL", !info.is_null()));
        // SAFETY: the info the delivery owns, for this call.
        let info = unsafe { &*info };
        checks.push(("info->item is NULL", !info.item.is_null()));
        // What Chromium's `CertDatabase` notifier checks before anything else.
        checks.push(("version is VERS1 or older", info.version <= 1));
        checks.push((
            "the pid is this process's",
            info.pid == darwin::process::guest_pid(starnix::process::me()),
        ));

        let mut item_class = 0u32;
        let mut attributes = [
            Attribute {
                tag: LABEL,
                length: 0,
                data: std::ptr::null_mut(),
            },
            Attribute {
                tag: ACCOUNT,
                length: 0,
                data: std::ptr::null_mut(),
            },
            Attribute {
                tag: SERVICE,
                length: 0,
                data: std::ptr::null_mut(),
            },
        ];
        let mut list = AttributeList {
            count: 3,
            attributes: attributes.as_mut_ptr(),
        };
        let (mut length, mut data) = (0u32, std::ptr::null_mut());
        // SAFETY: the item the delivery holds, and writable out-parameters.
        unsafe {
            let status = SecKeychainItemCopyContent(
                info.item,
                &mut item_class,
                &mut list,
                &mut length,
                &mut data,
            );
            checks.push(("get item data in callback", status == SUCCESS));
            checks.push((
                "SecKeychainItemCopyContent() returns bad data",
                length as usize == PASSWORD.len(),
            ));
            checks.push(("received data from item", !data.is_null()));
            checks.push((
                "password data matches.",
                !data.is_null()
                    && std::slice::from_raw_parts(data as *const u8, length as usize) == PASSWORD,
            ));
            checks.push((
                "free item data in callback",
                SecKeychainItemFreeContent(&mut list, data) == SUCCESS,
            ));
            *(context as *mut u32) = 1;
            checks.push(("delete item", SecKeychainItemDelete(info.item) == SUCCESS));
        }
        CALLBACK_CALLED.store(true, Ordering::SeqCst);
        runloop::current().stop();
        0
    }

    /// Apple's `kc-21-item-use-callback`: a callback registered for add events
    /// hears of an item this process adds, on its run loop, can read the item
    /// it is shown, and can delete it.
    #[test]
    fn kc_21_item_use_callback() {
        foundation::bootstrap();
        let _serial = serial();
        let run_loop = runloop::current();
        // "Run the CFRunLoop to clear out existing notifications."
        run_loop.run_in_mode(runloop::DEFAULT_MODE, 1.0, false);
        let mut did_get_notification = 0u32;
        let (account, service) = (b"account\0", b"service\0");
        // SAFETY: a callback of the right type, the strings at their lengths,
        // and writable out-parameters.
        unsafe {
            assert_eq!(
                SecKeychainAddCallback(
                    Some(kc_21_callback),
                    1 << event::ADD,
                    &mut did_get_notification as *mut u32 as *mut c_void
                ),
                SUCCESS,
                "add callback"
            );
            let mut keychain: CFTypeRef = std::ptr::null();
            assert_eq!(SecKeychainCopyDefault(&mut keychain), SUCCESS);
            let mut item: CFTypeRef = std::ptr::null();
            assert_eq!(
                SecKeychainAddGenericPassword(
                    keychain,
                    account.len() as u32,
                    account.as_ptr() as *const c_char,
                    service.len() as u32,
                    service.as_ptr() as *const c_char,
                    PASSWORD.len() as u32,
                    PASSWORD.as_ptr() as *const c_void,
                    &mut item,
                ),
                SUCCESS,
                "add generic password, release and wait for callback"
            );
            // "Run the CFRunLoop to process events (and call our callback)."
            run_loop.run_in_mode(runloop::DEFAULT_MODE, 10.0, false);
            assert!(
                CALLBACK_CALLED.load(Ordering::SeqCst),
                "Keychain callback function was not called or did not finish"
            );
            for (name, held) in CALLBACK_CHECKS.lock().unwrap().iter() {
                assert!(held, "{name}");
            }
            assert_eq!(did_get_notification, 1);
            corefoundation::api::CFRelease(item);
            assert_eq!(
                SecKeychainRemoveCallback(Some(kc_21_callback)),
                SUCCESS,
                "Remove callback"
            );
            corefoundation::api::CFRelease(keychain);
        }
    }

    static SECOND_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn counting_callback(
        _event: u32,
        _info: *mut CallbackInfo,
        _context: *mut c_void,
    ) -> OSStatus {
        SECOND_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// `CCallbackMgr`'s rules: a function is registered once whatever its
    /// context, and removing one that is not registered is an error.
    #[test]
    fn a_callback_is_keyed_by_its_function() {
        foundation::bootstrap();
        let _serial = serial();
        // SAFETY: a callback of the right type; the contexts are never read.
        unsafe {
            assert_eq!(SecKeychainAddCallback(None, 0, std::ptr::null_mut()), PARAM);
            assert_eq!(
                SecKeychainAddCallback(Some(counting_callback), 1 << 12, std::ptr::null_mut()),
                SUCCESS
            );
            assert_eq!(
                SecKeychainAddCallback(Some(counting_callback), 1 << 3, 1 as *mut c_void),
                DUPLICATE_CALLBACK
            );
            assert_eq!(SecKeychainRemoveCallback(Some(counting_callback)), SUCCESS);
            assert_eq!(
                SecKeychainRemoveCallback(Some(counting_callback)),
                INVALID_CALLBACK
            );
        }
        assert_eq!(SECOND_CALLS.load(Ordering::SeqCst), 0);
    }

    /// A search names what it matches: an absent account matches any, and a
    /// keychain other than the login keychain holds nothing.
    #[test]
    fn a_search_matches_what_it_names() {
        foundation::bootstrap();
        let _serial = serial();
        let service = b"rosemary.test.find";
        // SAFETY: the strings at their lengths and writable out-parameters.
        unsafe {
            assert_eq!(
                SecKeychainAddGenericPassword(
                    std::ptr::null(),
                    service.len() as u32,
                    service.as_ptr() as *const c_char,
                    4,
                    c"user".as_ptr(),
                    6,
                    c"secret".as_ptr() as *const c_void,
                    std::ptr::null_mut(),
                ),
                SUCCESS
            );
            let (mut length, mut data, mut item) = (0u32, std::ptr::null_mut(), std::ptr::null());
            assert_eq!(
                SecKeychainFindGenericPassword(
                    std::ptr::null(),
                    service.len() as u32,
                    service.as_ptr() as *const c_char,
                    0,
                    std::ptr::null(),
                    &mut length,
                    &mut data,
                    &mut item,
                ),
                SUCCESS
            );
            assert_eq!(
                std::slice::from_raw_parts(data as *const u8, length as usize),
                b"secret"
            );
            assert_eq!(
                SecKeychainItemFreeContent(std::ptr::null_mut(), data),
                SUCCESS
            );
            assert_eq!(
                corefoundation::api::CFGetTypeID(item),
                SecKeychainItemGetTypeID()
            );

            let mut other: CFTypeRef = std::ptr::null();
            assert_eq!(
                SecKeychainOpen(c"/nonexistent/other.keychain".as_ptr(), &mut other),
                SUCCESS
            );
            assert_eq!(
                corefoundation::api::CFGetTypeID(other),
                SecKeychainGetTypeID()
            );
            assert_eq!(
                SecKeychainFindGenericPassword(
                    other,
                    service.len() as u32,
                    service.as_ptr() as *const c_char,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                ITEM_NOT_FOUND
            );
            assert_eq!(SecKeychainItemDelete(item), SUCCESS);
            assert_eq!(SecKeychainItemDelete(item), ITEM_NOT_FOUND);
            for object in [item, other] {
                corefoundation::api::CFRelease(object);
            }
        }
    }

    /// The search list is the login keychain, the same object every time it
    /// is named - by its path, by its old name, or as the default.
    #[test]
    fn the_search_list_is_the_login_keychain() {
        foundation::bootstrap();
        let _serial = serial();
        // SAFETY: writable out-parameters and C strings.
        unsafe {
            let mut list: CFTypeRef = std::ptr::null();
            assert_eq!(SecKeychainCopySearchList(&mut list), SUCCESS);
            assert_eq!(corefoundation::api::CFArrayGetCount(list), 1);
            let first = corefoundation::api::CFArrayGetValueAtIndex(list, 0);
            let mut login: CFTypeRef = std::ptr::null();
            assert_eq!(
                SecKeychainOpen(c"login.keychain".as_ptr(), &mut login),
                SUCCESS
            );
            let mut default: CFTypeRef = std::ptr::null();
            assert_eq!(SecKeychainCopyDefault(&mut default), SUCCESS);
            assert_eq!(first, login);
            assert_eq!(login, default);
            for object in [list, login, default] {
                corefoundation::api::CFRelease(object);
            }
        }
    }
}
