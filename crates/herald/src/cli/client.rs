//! Client side of the control socket, for `herald show`. Blocking: one
//! request, one reply, no runtime needed.

use std::{
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use thiserror::Error;

use crate::control::proto::{Envelope, Reply, Request, VERSION};

/// Longer than the server's RIB and reload timeouts, so its error message wins.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cannot connect to {}: {source} (is herald running, and is this its control_socket?)", path.display())]
    Connect { path: PathBuf, source: io::Error },
    #[error("talking to herald: {0}")]
    Io(#[from] io::Error),
    #[error("herald closed the connection without a reply")]
    NoReply,
    #[error("unexpected reply: {0}")]
    BadReply(serde_json::Error),
    /// herald answered with an error.
    #[error("{0}")]
    Herald(String),
}

/// Sends `request` to the herald listening on `path` and returns the `ok`
/// value.
pub fn request(path: &Path, request: Request) -> Result<serde_json::Value, ClientError> {
    let stream = UnixStream::connect(path).map_err(|source| ClientError::Connect {
        path: path.to_owned(),
        source,
    })?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    stream.set_write_timeout(Some(REPLY_TIMEOUT))?;
    let mut line = serde_json::to_vec(&Envelope {
        v: VERSION,
        request,
    })
    .expect("requests always serialize");
    line.push(b'\n');
    (&stream).write_all(&line)?;

    let mut reply = String::new();
    if BufReader::new(&stream).read_line(&mut reply)? == 0 {
        return Err(ClientError::NoReply);
    }
    match serde_json::from_str(&reply).map_err(ClientError::BadReply)? {
        Reply::Ok(value) => Ok(value),
        Reply::Error(message) => Err(ClientError::Herald(message)),
    }
}
