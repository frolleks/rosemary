//! Backup Core: which items Time Machine skips.
//!
//! An item is excluded in one of two ways, as on macOS. A sticky exclusion is
//! an extended attribute on the item, so it follows the item when it moves. An
//! exclusion by path is an entry in the `SkipPaths` list of Time Machine's
//! preferences, which only root may change.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_void};

use corefoundation::base::CFTypeRef;
use corefoundation::plist::{self, Value};

type OSStatus = i32;

const NO_ERR: OSStatus = 0;
/// `paramErr`.
const PARAM_ERR: OSStatus = -50;
/// `fnfErr`: the item is not there.
const FNF_ERR: OSStatus = -43;
/// `permErr`.
const PERM_ERR: OSStatus = -54;
/// `ioErr`: the host refused for a reason with no closer word.
const IO_ERR: OSStatus = -36;

/// The attribute a sticky exclusion is, as `tmutil addexclusion` writes it.
const STICKY: &CStr = c"com.apple.metadata:com_apple_backup_excludeItem";

/// The attribute's value: a binary property list of the string
/// "com.apple.backupd", byte for byte what Time Machine writes.
const STICKY_VALUE: &[u8] = &[
    b'b', b'p', b'l', b'i', b's', b't', b'0', b'0', 0x5f, 0x10, 0x11, b'c', b'o', b'm', b'.', b'a',
    b'p', b'p', b'l', b'e', b'.', b'b', b'a', b'c', b'k', b'u', b'p', b'd', 0x08, 0, 0, 0, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1c,
];

/// Time Machine's preferences, whose `SkipPaths` are the exclusions by path.
const PREFERENCES: &CStr = c"/Library/Preferences/com.apple.TimeMachine.plist";
const SKIP_PATHS: &str = "SkipPaths";

/// The guest path a `file:` URL names.
///
/// # Safety
///
/// `item` is null or a CF object.
unsafe fn path_of(item: CFTypeRef) -> Option<String> {
    let url = unsafe { corefoundation::url::as_url(item) }?;
    url.file_path().filter(|path| path.starts_with('/'))
}

/// `path`, then each directory above it, ending with `/`.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(path), |path| match path.rfind('/') {
        Some(0) if path.len() > 1 => Some("/"),
        Some(0) | None => None,
        Some(at) => Some(&path[..at]),
    })
}

fn has_sticky(path: &str) -> bool {
    let Ok(path) = CString::new(path) else {
        return false;
    };
    // SAFETY: two NUL-terminated strings and a size of zero, which asks only
    // whether the attribute is there.
    unsafe {
        darwin::xattr::getxattr(
            path.as_ptr(),
            STICKY.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        ) >= 0
    }
}

fn preferences_file() -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let host = prefix::ns::to_host(PREFERENCES);
    std::ffi::OsStr::from_bytes(host.to_bytes()).into()
}

/// Time Machine's preferences, or an empty dictionary when there are none.
fn preferences() -> BTreeMap<String, Value> {
    let bytes = std::fs::read(preferences_file());
    match bytes.ok().and_then(|bytes| plist::parse(&bytes).ok()) {
        Some(Value::Dictionary(entries)) => entries,
        _ => BTreeMap::new(),
    }
}

fn skip_paths(preferences: &BTreeMap<String, Value>) -> Vec<String> {
    match preferences.get(SKIP_PATHS) {
        Some(Value::Array(paths)) => paths
            .iter()
            .filter_map(|path| match path {
                Value::String(path) => Some(path.trim_end_matches('/').to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `Boolean CSBackupIsItemExcluded(CFURLRef item, Boolean *excludeByPath)`:
/// "true if the item or any of its ancestors are excluded from backup", and
/// in `excludeByPath` whether that exclusion is by path rather than sticky.
///
/// # Safety
///
/// `item` is null or a CF object; `by_path` is null or writable.
pub unsafe extern "C" fn CSBackupIsItemExcluded(item: CFTypeRef, by_path: *mut u8) -> u8 {
    let found = unsafe { path_of(item) }.and_then(|path| {
        let skipped = skip_paths(&preferences());
        ancestors(&path).find_map(|level| {
            if skipped.iter().any(|skip| skip == level) {
                Some(true)
            } else {
                has_sticky(level).then_some(false)
            }
        })
    });
    if !by_path.is_null() {
        // SAFETY: the caller's out-parameter.
        unsafe { *by_path = found.unwrap_or(false) as u8 };
    }
    found.is_some() as u8
}

/// The File Manager's word for the `errno` an attribute call left.
fn status_of_errno() -> OSStatus {
    match darwin::errno::get() {
        libc::ENOENT | libc::ENOTDIR => FNF_ERR,
        libc::EACCES | libc::EPERM | libc::EROFS => PERM_ERR,
        _ => IO_ERR,
    }
}

/// Add `path` to `SkipPaths`, or take it out.
fn set_skipped(path: &str, exclude: bool) -> OSStatus {
    let mut preferences = preferences();
    let mut paths = skip_paths(&preferences);
    let path = path.trim_end_matches('/');
    let present = paths.iter().any(|skip| skip == path);
    match (exclude, present) {
        (true, false) => paths.push(path.to_string()),
        (false, true) => paths.retain(|skip| skip != path),
        _ => return NO_ERR,
    }
    preferences.insert(
        SKIP_PATHS.to_string(),
        Value::Array(paths.into_iter().map(Value::String).collect()),
    );
    match std::fs::write(
        preferences_file(),
        plist::write_xml(&Value::Dictionary(preferences)),
    ) {
        Ok(()) => NO_ERR,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => PERM_ERR,
        Err(_) => IO_ERR,
    }
}

/// `OSStatus CSBackupSetItemExcluded(CFURLRef item, Boolean exclude,
/// Boolean excludeByPath)`.
///
/// A sticky exclusion needs the item to exist; one by path does not, but
/// needs root, as it changes Time Machine's own preferences. Apple does not
/// document the status a non-root caller gets; `permErr` is the File
/// Manager's word for that refusal.
///
/// # Safety
///
/// `item` is null or a CF object.
pub unsafe extern "C" fn CSBackupSetItemExcluded(
    item: CFTypeRef,
    exclude: u8,
    by_path: u8,
) -> OSStatus {
    let Some(path) = (unsafe { path_of(item) }) else {
        return PARAM_ERR;
    };
    if by_path != 0 {
        if darwin::credentials::geteuid() != 0 {
            return PERM_ERR;
        }
        return set_skipped(&path, exclude != 0);
    }
    let Ok(guest) = CString::new(path) else {
        return PARAM_ERR;
    };
    // SAFETY: NUL-terminated strings and a value of the length given.
    let rc = unsafe {
        match exclude != 0 {
            true => darwin::xattr::setxattr(
                guest.as_ptr(),
                STICKY.as_ptr(),
                STICKY_VALUE.as_ptr().cast::<c_void>(),
                STICKY_VALUE.len(),
                0,
                0,
            ),
            false => darwin::xattr::removexattr(guest.as_ptr(), STICKY.as_ptr(), 0),
        }
    };
    if rc == 0 {
        return NO_ERR;
    }
    // Not excluded already is what was asked for.
    if exclude == 0 && darwin::xattr::is_absent(darwin::errno::get()) {
        return NO_ERR;
    }
    status_of_errno()
}

exports::exports! {
    functions {
        "CSBackupIsItemExcluded" => CSBackupIsItemExcluded,
        "CSBackupSetItemExcluded" => CSBackupSetItemExcluded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(path: &std::path::Path) -> CFTypeRef {
        corefoundation::url::new_file_url(path.to_str().unwrap(), path.is_dir())
    }

    #[test]
    fn ancestors_run_from_the_item_to_the_root() {
        assert_eq!(
            ancestors("/a/b/c").collect::<Vec<_>>(),
            ["/a/b/c", "/a/b", "/a", "/"]
        );
        assert_eq!(ancestors("/").collect::<Vec<_>>(), ["/"]);
    }

    #[test]
    fn the_sticky_value_is_a_property_list_of_the_daemon_name() {
        assert_eq!(
            plist::parse(STICKY_VALUE).unwrap(),
            Value::String("com.apple.backupd".to_string())
        );
    }

    /// A sticky exclusion is on the item and covers what is inside it; taking
    /// it away twice is not an error.
    #[test]
    fn a_sticky_exclusion_covers_the_item_and_its_contents() {
        let dir = std::env::temp_dir().join(format!("rosemary-backup-{}", std::process::id()));
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let (outer_url, inner_url) = (url(&dir), url(&inner));
        let mut by_path = 9u8;
        // SAFETY: URLs made here, and a writable flag.
        unsafe {
            assert_eq!(CSBackupIsItemExcluded(inner_url, &mut by_path), 0);
            assert_eq!(by_path, 0);
            let status = CSBackupSetItemExcluded(outer_url, 1, 0);
            if status == IO_ERR {
                // A file system without user attributes, such as some tmpfs.
                eprintln!("skipped: no extended attributes in {}", dir.display());
                std::fs::remove_dir_all(&dir).unwrap();
                return;
            }
            assert_eq!(status, NO_ERR);
            assert_eq!(CSBackupIsItemExcluded(outer_url, std::ptr::null_mut()), 1);
            by_path = 9;
            assert_eq!(CSBackupIsItemExcluded(inner_url, &mut by_path), 1);
            assert_eq!(by_path, 0, "sticky, not by path");
            assert_eq!(CSBackupSetItemExcluded(outer_url, 0, 0), NO_ERR);
            assert_eq!(CSBackupSetItemExcluded(outer_url, 0, 0), NO_ERR);
            assert_eq!(CSBackupIsItemExcluded(inner_url, std::ptr::null_mut()), 0);
            let missing = url(&dir.join("missing"));
            assert_eq!(CSBackupSetItemExcluded(missing, 1, 0), FNF_ERR);
            for object in [outer_url, inner_url, missing] {
                corefoundation::api::CFRelease(object);
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
