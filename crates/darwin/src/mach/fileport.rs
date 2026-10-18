//! Fileports: an open file wrapped in a Mach send right, which is how Darwin
//! hands a descriptor to another process in a message.
//!
//! The right holds a duplicate of the descriptor, as XNU's port holds a
//! reference on the file, so the caller may close its own as soon as the port
//! exists. A message carries the file over `SCM_RIGHTS` beside the datagram
//! (see [`super::msg`]).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::space::{self, Name};

/// `int fileport_makeport(int fd, fileport_t *port)`
///
/// # Safety
///
/// `port` is a writable `fileport_t`, or null.
pub unsafe extern "C" fn fileport_makeport(fd: i32, port: *mut Name) -> i32 {
    if port.is_null() {
        crate::errno::set(libc::EFAULT);
        return -1;
    }
    crate::guarded::enforce(
        fd,
        crate::guarded::GUARD_FILEPORT,
        crate::guarded::Flavor::Fileport,
    );
    // SAFETY: an integer descriptor; the call touches no caller memory.
    let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if copied < 0 {
        return -1;
    }
    // SAFETY: a descriptor just made and owned by nothing else.
    let file = unsafe { OwnedFd::from_raw_fd(copied) };
    let nosigpipe = crate::net::sockopt::suppresses_sigpipe(fd);
    let name = space::insert_fileport(file, nosigpipe);
    // SAFETY: the caller's `fileport_t`, checked above.
    unsafe { port.write_unaligned(name) };
    0
}

/// `int fileport_makefd(fileport_t port)`
///
/// A new descriptor for the file, close-on-exec as `sys_fileport_makefd`
/// makes it; the right itself stays with the caller.
pub extern "C" fn fileport_makefd(port: Name) -> i32 {
    let Some((file, nosigpipe)) = space::fileport_of(port) else {
        crate::errno::set(libc::EINVAL);
        return -1;
    };
    // SAFETY: the right's own descriptor, kept open by the `Arc` held here.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd >= 0 && nosigpipe {
        crate::net::sockopt::suppress_sigpipe(fd);
    }
    fd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mach::kern::KERN_SUCCESS;

    fn pipe() -> (i32, i32) {
        let mut ends = [0i32; 2];
        // SAFETY: a writable two-element descriptor array.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        (ends[0], ends[1])
    }

    #[test]
    fn a_fileport_outlives_the_descriptor_it_was_made_from() {
        let (read, write) = pipe();
        let mut port = 0;
        // SAFETY: a live local for the out-parameter.
        assert_eq!(unsafe { fileport_makeport(write, &mut port) }, 0);
        // SAFETY: this test's own descriptor.
        unsafe { libc::close(write) };

        let fd = fileport_makefd(port);
        assert!(fd >= 0);
        // SAFETY: a descriptor just made.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "made close-on-exec");
        // SAFETY: one byte from a live local.
        assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
        let mut byte = 0u8;
        // SAFETY: one writable byte.
        assert_eq!(unsafe { libc::read(read, (&raw mut byte).cast(), 1) }, 1);
        assert_eq!(byte, b'x');

        assert_eq!(
            space::mach_port_deallocate(space::TASK_SELF, port),
            KERN_SUCCESS
        );
        assert_eq!(fileport_makefd(port), -1, "the right is gone");
        // SAFETY: this test's own descriptors.
        unsafe {
            libc::close(fd);
            libc::close(read);
        }
    }

    #[test]
    fn a_name_that_is_not_a_fileport_makes_no_descriptor() {
        assert_eq!(fileport_makefd(space::TASK_SELF), -1);
        assert_eq!(crate::errno::get(), libc::EINVAL);
    }
}
