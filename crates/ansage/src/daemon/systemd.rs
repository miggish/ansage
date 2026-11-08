//! systemd readiness notification (sd_notify protocol) without libsystemd:
//! one datagram to `$NOTIFY_SOCKET`. A no-op when not run by systemd with
//! `Type=notify` / `Type=notify-reload`.

use std::{io, os::unix::net::UnixDatagram};

use crate::config::Config;
use tracing::warn;

/// Sends `state` (newline-separated `KEY=VALUE` lines) to systemd. Errors
/// are returned but are usually only worth a debug log: ansage runs the same
/// without systemd.
pub fn notify(state: &str) -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    let bytes = path.as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        // Abstract socket namespace.
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        socket.send_to_addr(state.as_bytes(), &addr)?;
    } else {
        socket.send_to(state.as_bytes(), &path)?;
    }
    Ok(())
}

/// `RELOADING=1` with the timestamp `Type=notify-reload` requires.
pub fn reloading() -> String {
    // SAFETY: clock_gettime only writes the timespec we pass.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let usec = ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000;
    format!("RELOADING=1\nMONOTONIC_USEC={usec}")
}

/// Tells systemd we are up (again).
pub(super) fn ready(config: &Config) {
    sd_notify(&format!(
        "READY=1\nSTATUS=AS {}, {} neighbors, {} own prefixes",
        config.asn,
        config.neighbors.len(),
        config.announce.len()
    ));
}

pub(super) fn sd_notify(state: &str) {
    if let Err(err) = notify(state) {
        warn!(%err, "cannot notify systemd");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_the_notify_socket() {
        let dir = std::env::temp_dir().join(format!("ansage-notify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        // SAFETY: no other test reads or writes NOTIFY_SOCKET.
        unsafe { std::env::set_var("NOTIFY_SOCKET", &path) };
        notify("READY=1").unwrap();
        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        notify("READY=1").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(reloading().starts_with("RELOADING=1\nMONOTONIC_USEC="));
    }
}
