//! Dead-name notifications.
//!
//! A send right holds a claim on its port: a stream connection to the port's
//! listener (see [`super::senders`]). Nothing is ever written on one, so it
//! reads end-of-file exactly when the receive right is gone from every process
//! that could hold it - which is what makes the send right a dead name. A
//! thread per process watches the claims of the rights a dead-name
//! notification was asked for, and turns that end-of-file into the dead name
//! and the `MACH_NOTIFY_DEAD_NAME` XNU would send.

use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::space::Name;
use super::wire::Address;

struct Watch {
    name: Name,
    /// The right's claim, which the space owns: this registry only polls it,
    /// and stops before the right lets go of it (see [`retain`]).
    fd: c_int,
    notify: Address,
}

struct Registry {
    watches: Vec<Watch>,
    owner: u32,
    wake: Option<(c_int, c_int)>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    watches: Vec::new(),
    owner: 0,
    wake: None,
});

/// How many watches there are, so the space can skip [`retain`] when none.
static WATCHING: AtomicUsize = AtomicUsize::new(0);

fn lock() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Start the watching thread in this process, as `senders` does: a fork
/// child gets its own, and none of its parent's watches.
fn prepare(registry: &mut Registry) -> bool {
    let me = std::process::id();
    if registry.owner == me && registry.wake.is_some() {
        return true;
    }
    registry.watches.clear();
    let mut pipe = [0 as c_int; 2];
    // SAFETY: a two-element array, as `pipe` requires.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } < 0 {
        return false;
    }
    for fd in pipe {
        // SAFETY: descriptors just opened.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let read = pipe[0];
    let started = std::thread::Builder::new()
        .name("mach-dead-names".into())
        .spawn(move || run(read, me))
        .is_ok();
    if !started {
        for fd in pipe {
            // SAFETY: the descriptors opened above, never shared.
            unsafe { libc::close(fd) };
        }
        return false;
    }
    registry.owner = me;
    registry.wake = Some((pipe[0], pipe[1]));
    true
}

fn wake(registry: &Registry) {
    if let Some((_, write)) = registry.wake {
        // SAFETY: one byte from a live local to the registry's own pipe.
        unsafe { libc::write(write, [0u8].as_ptr().cast(), 1) };
    }
}

/// Watch `name`, a send right whose claim is `fd`, and tell `notify` when its
/// port dies. A second request for the same name replaces the first.
pub fn watch(name: Name, fd: c_int, notify: Address) -> bool {
    let mut registry = lock();
    if !prepare(&mut registry) {
        return false;
    }
    registry.watches.retain(|w| w.name != name);
    registry.watches.push(Watch { name, fd, notify });
    WATCHING.store(registry.watches.len(), Ordering::Relaxed);
    wake(&registry);
    true
}

/// Keep only the watches `live` still vouches for, which the space calls
/// after every change: a right that went away closed its claim, and the
/// descriptor number must not be polled after it is reused.
pub fn retain(live: impl Fn(Name, c_int) -> bool) {
    if WATCHING.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut registry = lock();
    let before = registry.watches.len();
    registry.watches.retain(|w| live(w.name, w.fd));
    if registry.watches.len() != before {
        WATCHING.store(registry.watches.len(), Ordering::Relaxed);
        // The thread may be inside `poll` on the descriptor that went, which
        // keeps the connection open until it returns.
        wake(&registry);
    }
}

fn run(wake_read: c_int, owner: u32) {
    loop {
        let mut watched = Vec::new();
        let mut polled = vec![libc::pollfd {
            fd: wake_read,
            events: libc::POLLIN,
            revents: 0,
        }];
        {
            let registry = lock();
            if registry.owner != owner {
                return;
            }
            for w in &registry.watches {
                watched.push((w.name, w.fd));
                polled.push(libc::pollfd {
                    fd: w.fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
        }
        // SAFETY: `polled` is exactly the live `pollfd`s the count names.
        let rc = unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, -1) };
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
        if polled[0].revents != 0 {
            let mut drain = [0u8; 64];
            // SAFETY: a live buffer of the length given.
            while unsafe { libc::read(wake_read, drain.as_mut_ptr().cast(), 64) } > 0 {}
        }
        let mut dead = Vec::new();
        {
            let mut registry = lock();
            if registry.owner != owner {
                return;
            }
            for ((name, fd), poll) in watched.iter().zip(&polled[1..]) {
                if poll.revents == 0 {
                    continue;
                }
                // Looked up again: the watch may have been replaced or
                // dropped, and its number reused, while the poll waited.
                let Some(at) = registry
                    .watches
                    .iter()
                    .position(|w| w.name == *name && w.fd == *fd)
                else {
                    continue;
                };
                if super::senders::closed(*fd) {
                    let w = registry.watches.swap_remove(at);
                    dead.push(w);
                }
            }
            WATCHING.store(registry.watches.len(), Ordering::Relaxed);
        }
        for w in dead {
            if super::space::kill_send(w.name, w.fd, true) {
                super::msg::deliver_dead_name(w.notify, w.name);
            }
        }
    }
}
