//! T    let sessions = sessions().lock().unwrap_or_else(|e|
//! e.into_inner());lling neighbors to drop our routes when herald panics.
//!
//! With Graceful Restart a neighbor keeps our routes when the session ends
//! without a NOTIFICATION, which is also what a crash looks like. So the
//! panic hook writes a final Cease (a Hard Reset with the N bit) on every
//! Established session before the process aborts (release builds use
//! `panic = "abort"`). kill -9, the OOM killer or a dead host cannot be
//! handled: those look like a restart to the neighbor.
//!
//! The Cease must not land in the middle of a message: the peer would see
//! garbage, answer with its own NOTIFICATION, and with the N bit that keeps
//! our routes. The writer task therefore writes under the session's
//! [`WriteState`] lock and records the unsent rest of the message it is in;
//! the hook takes the lock for good, finishes that message, then writes the
//! Cease.

use std::{
    collections::HashMap,
    os::fd::RawFd,
    sync::{
        Arc, Mutex, MutexGuard, Once,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};

/// Time for all final writes together; the process is dying.
const DEADLINE: Duration = Duration::from_secs(1);

/// What the writer has written of the current message.
#[derive(Debug, Default)]
pub struct WriteState {
    /// The unsent rest of the message the writer is in; empty between
    /// messages.
    rest: Bytes,
}

pub type SharedWriteState = Arc<Mutex<WriteState>>;

pub fn lock(state: &Mutex<WriteState>) -> MutexGuard<'_, WriteState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// Tracks message boundaries in a buffer of whole BGP messages as it is
/// written.
#[derive(Debug, Default)]
pub struct Boundaries {
    /// Bytes until the next message starts; 0: at a message start.
    to_next: usize,
}

impl Boundaries {
    /// `n` bytes of `buf` were written: advances `buf` and returns the
    /// unsent rest of the current message (empty at a boundary).
    pub fn advance(&mut self, buf: &mut Bytes, mut n: usize) -> Bytes {
        while n > 0 && !buf.is_empty() {
            if self.to_next == 0 {
                self.to_next = message_len(buf);
            }
            let step = n.min(self.to_next);
            buf.advance(step);
            self.to_next -= step;
            n -= step;
        }
        buf.slice(..self.to_next.min(buf.len()))
    }
}

/// Length of the message at the start of `buf` (header bytes 16..18). A
/// broken length counts as one message to the end of the buffer.
fn message_len(buf: &[u8]) -> usize {
    match buf.get(16..18) {
        Some(len) => {
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            if len < herald_bgp::wire::HEADER_LEN {
                buf.len()
            } else {
                len.min(buf.len())
            }
        }
        None => buf.len(),
    }
}

impl WriteState {
    pub fn set_rest(&mut self, rest: Bytes) {
        self.rest = rest;
    }
}

struct Session {
    fd: RawFd,
    state: SharedWriteState,
    /// The encoded Cease.
    cease: Bytes,
}

fn sessions() -> &'static Mutex<HashMap<u64, Session>> {
    static SESSIONS: std::sync::OnceLock<Mutex<HashMap<u64, Session>>> = std::sync::OnceLock::new();
    SESSIONS.get_or_init(Mutex::default)
}

/// An Established session the hook would write to; removed on drop. Must
/// be dropped before the socket can close (the fd number could be reused).
#[derive(Debug)]
pub struct Registration(u64);

impl Drop for Registration {
    fn drop(&mut self) {
        sessions()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Registers a session: on a panic `cease` (a whole encoded NOTIFICATION)
/// goes out on `fd` after the message the writer is in.
pub fn register(fd: RawFd, state: SharedWriteState, cease: Bytes) -> Registration {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    sessions()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, Session { fd, state, cease });
    Registration(id)
}

/// Installs the panic hook, only where a panic ends the process: with
/// unwinding a panicking task leaves herald running, and the sessions must
/// stay as they are.
pub fn install() {
    if !cfg!(panic = "abort") {
        return;
    }
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            previous(info);
            let sent = notify_all();
            eprintln!("herald: panic, sent the final Cease on {sent} sessions");
        }));
    });
}

/// Writes the Cease on every registered session; returns how many got it
/// completely. The sessions stay locked afterwards, so the writers send
/// nothing more.
pub fn notify_all() -> usize {
    let deadline = Instant::now() + DEADLINE;
    let sessions = sessions().lock().unwrap_or_else(|e| e.into_inner());
    let mut sent = 0;
    for session in sessions.values() {
        // A writer holds the lock only for one non-blocking write.
        let guard = loop {
            match session.state.try_lock() {
                Ok(guard) => break Some(guard),
                Err(std::sync::TryLockError::Poisoned(e)) => break Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(std::sync::TryLockError::WouldBlock) => break None,
            }
        };
        let Some(guard) = guard else { continue };
        let ok = write_all(session.fd, &guard.rest, deadline)
            && write_all(session.fd, &session.cease, deadline);
        std::mem::forget(guard);
        sent += usize::from(ok);
    }
    sent
}

/// Writes `buf` on the (non-blocking) socket, waiting for room until
/// `deadline`.
fn write_all(fd: RawFd, mut buf: &[u8], deadline: Instant) -> bool {
    while !buf.is_empty() {
        // SAFETY: `buf` is valid for its length; `fd` is open while it is
        // registered.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return false;
                }
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as i32) };
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::fd::AsRawFd};

    fn message(len: u16, fill: u8) -> Vec<u8> {
        let mut m = vec![0xff; 16];
        m.extend(len.to_be_bytes());
        m.resize(usize::from(len), fill);
        m
    }

    #[test]
    fn boundaries_follow_partial_writes() {
        let mut buf: Vec<u8> = message(23, 1);
        buf.extend(message(30, 2));
        let mut buf = Bytes::from(buf);
        let mut b = Boundaries::default();
        // Into the first message.
        let rest = b.advance(&mut buf, 10);
        assert_eq!(rest.len(), 13);
        // Exactly to its end: at a boundary.
        assert!(b.advance(&mut buf, 13).is_empty());
        // Across nothing: 5 into the second.
        let rest = b.advance(&mut buf, 5);
        assert_eq!(rest.len(), 25);
        assert!(b.advance(&mut buf, 25).is_empty());
        assert!(buf.is_empty());

        // One write over a boundary.
        let mut buf: Vec<u8> = message(19, 1);
        buf.extend(message(20, 2));
        let mut buf = Bytes::from(buf);
        let mut b = Boundaries::default();
        assert_eq!(b.advance(&mut buf, 21).len(), 18);

        // A broken length: the rest of the buffer is one message.
        let mut buf = Bytes::from(vec![0u8; 40]);
        let mut b = Boundaries::default();
        assert_eq!(b.advance(&mut buf, 4).len(), 36);
    }

    #[test]
    fn notify_finishes_the_message_then_sends_the_cease() {
        let (ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let state = SharedWriteState::default();
        lock(&state).set_rest(Bytes::from_static(b"rest-of-update"));
        let reg = register(
            ours.as_raw_fd(),
            state.clone(),
            Bytes::from_static(b"CEASE"),
        );
        // Another session that went away is not written to.
        drop(register(
            -1,
            SharedWriteState::default(),
            Bytes::from_static(b"x"),
        ));

        assert_eq!(notify_all(), 1);
        drop(ours);
        let mut got = Vec::new();
        theirs.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"rest-of-updateCEASE");
        // The writer is locked out for good.
        assert!(state.try_lock().is_err());
        drop(reg);
    }
}
