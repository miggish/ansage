//! Scripted BGP peer for the e2e tests (malformed input, odd peers).
//!
//! ```text
//! rogue [--listen 0.0.0.0:179] SCRIPT      # SCRIPT is a file or - for stdin
//! ```
//!
//! The rogue listens for herald's connection; `connect` also dials herald's
//! listener (collisions). It plays a script of one step per line, logs
//! everything it sends and receives (one line each, seconds since start
//! first) and exits 0 when the script completed, 1 with a `FAIL` line when
//! an `expect` was not met.
//!
//! Hex arguments are whitespace-separated tokens of hex digits; `XX*N` repeats
//! the byte XX N times (e.g. `ff*16` for the marker).
//!
//! Steps:
//! ```text
//! accept [SECS]                  wait for the next connection (default 60 s); drops the current one
//! open [KEY=VALUE...]            send an OPEN. Keys: as (64520) id (10.201.0.20) hold (9)
//!                                version (4) caps (mp4,mp6,rr,as4; also ext, none)
//!                                cap=CODE:HEX (extra capability) param=TYPE:HEX (extra
//!                                optional parameter); as > 65535 puts 23456 in My AS
//! handshake [KEY=VALUE...]       open + expect open + keepalive + expect keepalive
//! keepalive
//! msg TYPE HEX...                message with a correct header; TYPE open|update|
//!                                notification|keepalive|refresh or a number
//! raw HEX...                     bytes as they are
//! notification CODE/SUB [HEX...]
//! announce PREFIX... [nh4=A] [nh6=A] [path=AS,AS] [attr=FLAGS:CODE:HEX] [size=N]
//!                                one UPDATE per family (AS_PATH width as negotiated);
//!                                size pads the UPDATE to N bytes with an optional
//!                                transitive attribute (type 250)
//! withdraw PREFIX...
//! pace MS                        later sends go out one byte every MS ms (0: off)
//! sleep SECS
//! expect WHAT [ARG] [timeout=S]  WHAT: open, keepalive, update, refresh, notification
//!                                [CODE/SUB], close. KEEPALIVEs and UPDATEs are skipped
//!                                while waiting for something else; anything else fails
//! run SECS                       stay up: KEEPALIVE every 3 s, fail on NOTIFICATION or close
//! close                          FIN (after reading what the peer still sends for 0.2 s)
//! connect ADDR:PORT [SECS]       open a connection to ADDR (default 10 s); the current one
//!                                is kept aside (not read) for `swap`
//! swap                           exchange the current connection and the one kept aside
//! replay DIR [max=N] [KEY=VALUE...]  for each file in DIR (sorted): be Established
//!                                (accept + handshake with KEY=VALUE as needed), send the
//!                                file, then a KEEPALIVE; prints a summary
//! print TEXT
//! ```

use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use clap::Parser;

const MARKER: [u8; 16] = [0xff; 16];
const OPEN: u8 = 1;
const UPDATE: u8 = 2;
const NOTIFICATION: u8 = 3;
const KEEPALIVE: u8 = 4;
const REFRESH: u8 = 5;
const DEFAULT_TIMEOUT: f64 = 15.0;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:179")]
    listen: SocketAddr,
    /// Script file, or - for stdin.
    script: PathBuf,
}

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args = Args::parse();
    let text = if args.script.as_os_str() == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s).map(|_| s)
    } else {
        fs::read_to_string(&args.script)
    };
    let text = match text {
        Ok(t) => t,
        Err(err) => {
            eprintln!("FAIL: reading {}: {err}", args.script.display());
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(args.listen) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("FAIL: listen on {}: {err}", args.listen);
            return ExitCode::from(2);
        }
    };
    let mut rogue = Rogue::new(listener);
    rogue.log(format_args!("listening on {}", args.listen));
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        rogue.log(format_args!("> {line}"));
        if let Err(err) = rogue.step(line) {
            rogue.log(format_args!("FAIL line {}: {err}", n + 1));
            return ExitCode::FAILURE;
        }
    }
    rogue.log(format_args!("done"));
    ExitCode::SUCCESS
}

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    /// What we offered in our OPEN.
    sent_as4: bool,
    sent_ext: bool,
    /// Negotiated once the peer's OPEN arrived.
    as4: bool,
    ext: bool,
}

/// One received message.
enum Recv {
    Msg(u8, Vec<u8>),
    Closed(String),
}

struct Rogue {
    listener: TcpListener,
    conn: Option<Conn>,
    /// A second connection, kept aside by `connect` (collisions).
    aside: Option<Conn>,
    start: Instant,
    pace: Duration,
    our_as: u32,
}

impl Rogue {
    fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            conn: None,
            aside: None,
            start: Instant::now(),
            pace: Duration::ZERO,
            our_as: 64520,
        }
    }

    fn log(&self, args: std::fmt::Arguments) {
        println!("{:8.3} {args}", self.start.elapsed().as_secs_f64());
        let _ = io::stdout().flush();
    }

    fn conn(&mut self) -> Result<&mut Conn> {
        self.conn
            .as_mut()
            .ok_or_else(|| "no connection".to_string())
    }

    fn step(&mut self, line: &str) -> Result<()> {
        let mut words = line.split_whitespace();
        let cmd = words.next().unwrap_or("");
        let rest: Vec<&str> = words.collect();
        match cmd {
            "accept" => self.accept(secs(rest.first().copied().unwrap_or("60"))?),
            "open" => self.open(&rest),
            "handshake" => {
                self.open(&rest)?;
                self.expect(&["open"])?;
                self.send_msg(KEEPALIVE, &[])?;
                self.expect(&["keepalive"])
            }
            "keepalive" => self.send_msg(KEEPALIVE, &[]),
            "msg" => {
                let (kind, hex) = rest.split_first().ok_or("msg needs a type")?;
                self.send_msg(msg_type(kind)?, &parse_hex(hex)?)
            }
            "raw" => self.send(&parse_hex(&rest)?),
            "notification" => {
                let (cs, hex) = rest.split_first().ok_or("notification needs CODE/SUB")?;
                let (code, sub) = code_sub(cs)?;
                let mut body = vec![code, sub];
                body.extend(parse_hex(hex)?);
                self.send_msg(NOTIFICATION, &body)
            }
            "announce" => self.announce(&rest, true),
            "withdraw" => self.announce(&rest, false),
            "pace" => {
                let ms: u64 = num(rest.first().copied().unwrap_or("0"))?;
                self.pace = Duration::from_millis(ms);
                Ok(())
            }
            "sleep" => {
                thread::sleep(secs(rest.first().copied().unwrap_or("1"))?);
                Ok(())
            }
            "expect" => self.expect(&rest),
            "run" => self.run(secs(rest.first().copied().unwrap_or("10"))?),
            "close" => self.close(),
            "connect" => {
                let addr: SocketAddr = rest
                    .first()
                    .ok_or("connect needs ADDR:PORT")?
                    .parse()
                    .map_err(|e| format!("connect: {e}"))?;
                self.connect(addr, secs(rest.get(1).copied().unwrap_or("10"))?)
            }
            "swap" => {
                std::mem::swap(&mut self.conn, &mut self.aside);
                Ok(())
            }
            "replay" => self.replay(&rest),
            "print" => {
                self.log(format_args!("{}", rest.join(" ")));
                Ok(())
            }
            _ => Err(format!("unknown step '{cmd}'")),
        }
    }

    fn connect(&mut self, addr: SocketAddr, timeout: Duration) -> Result<()> {
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("connect to {addr}: {e}"))?;
        let _ = stream.set_nodelay(true);
        self.log(format_args!("connected to {addr}"));
        self.aside = self.conn.take();
        self.conn = Some(Conn {
            stream,
            buf: Vec::new(),
            sent_as4: false,
            sent_ext: false,
            as4: false,
            ext: false,
        });
        Ok(())
    }

    fn accept(&mut self, timeout: Duration) -> Result<()> {
        self.conn = None;
        self.listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                    let _ = stream.set_nodelay(true);
                    self.log(format_args!("accepted {peer}"));
                    self.conn = Some(Conn {
                        stream,
                        buf: Vec::new(),
                        sent_as4: false,
                        sent_ext: false,
                        as4: false,
                        ext: false,
                    });
                    return Ok(());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        return Err(format!("no connection within {timeout:?}"));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("accept: {e}")),
            }
        }
    }

    fn open(&mut self, args: &[&str]) -> Result<()> {
        let mut asn: u32 = 64520;
        let mut id = Ipv4Addr::new(10, 201, 0, 20);
        let mut hold: u16 = 9;
        let mut version: u8 = 4;
        let mut caps = vec!["mp4", "mp6", "rr", "as4"];
        let mut extra_caps = Vec::new();
        let mut params = Vec::new();
        for arg in args {
            let (k, v) = arg.split_once('=').ok_or(format!("bad argument '{arg}'"))?;
            match k {
                "as" => asn = num(v)?,
                "id" => id = num(v)?,
                "hold" => hold = num(v)?,
                "version" => version = num(v)?,
                "caps" => caps = v.split(',').filter(|c| *c != "none").collect(),
                "cap" => {
                    let (code, hex) = v.split_once(':').ok_or("cap=CODE:HEX")?;
                    extra_caps.push((num::<u8>(code)?, parse_hex(&[hex])?));
                }
                "param" => {
                    let (kind, hex) = v.split_once(':').ok_or("param=TYPE:HEX")?;
                    params.push((num::<u8>(kind)?, parse_hex(&[hex])?));
                }
                _ => return Err(format!("unknown open key '{k}'")),
            }
        }
        self.our_as = asn;
        let mut cap_bytes = Vec::new();
        for cap in &caps {
            match *cap {
                "mp4" => cap_bytes.extend([1, 4, 0, 1, 0, 1]),
                "mp6" => cap_bytes.extend([1, 4, 0, 2, 0, 1]),
                "rr" => cap_bytes.extend([2, 0]),
                "ext" => cap_bytes.extend([6, 0]),
                "as4" => {
                    cap_bytes.extend([65, 4]);
                    cap_bytes.extend(asn.to_be_bytes());
                }
                _ => return Err(format!("unknown capability '{cap}'")),
            }
        }
        for (code, value) in &extra_caps {
            cap_bytes.push(*code);
            cap_bytes.push(u8::try_from(value.len()).map_err(|_| "capability too long")?);
            cap_bytes.extend(value);
        }
        let mut opt = Vec::new();
        if !cap_bytes.is_empty() {
            opt.push(2);
            opt.push(u8::try_from(cap_bytes.len()).map_err(|_| "capabilities too long")?);
            opt.extend(&cap_bytes);
        }
        for (kind, value) in &params {
            opt.push(*kind);
            opt.push(u8::try_from(value.len()).map_err(|_| "parameter too long")?);
            opt.extend(value);
        }
        let my_as = u16::try_from(asn).unwrap_or(23456);
        let mut body = vec![version];
        body.extend(my_as.to_be_bytes());
        body.extend(hold.to_be_bytes());
        body.extend(id.octets());
        body.push(u8::try_from(opt.len()).map_err(|_| "optional parameters too long")?);
        body.extend(opt);
        let c = self.conn()?;
        c.sent_as4 = caps.contains(&"as4");
        c.sent_ext = caps.contains(&"ext");
        self.send_msg(OPEN, &body)
    }

    fn announce(&mut self, args: &[&str], announce: bool) -> Result<()> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut nh4 = Ipv4Addr::new(10, 201, 0, 20);
        let mut nh6: Ipv6Addr = "2001:db8:201::20".parse().expect("valid");
        let mut path = vec![self.our_as];
        let mut extra = Vec::new();
        let mut size = None;
        for arg in args {
            if let Some((k, v)) = arg.split_once('=') {
                match k {
                    "nh4" => nh4 = num(v)?,
                    "nh6" => nh6 = num(v)?,
                    "path" if v.is_empty() => path.clear(),
                    "path" => path = v.split(',').map(num).collect::<Result<_>>()?,
                    "attr" => {
                        let mut it = v.splitn(3, ':');
                        let (Some(f), Some(c), Some(hex)) = (it.next(), it.next(), it.next())
                        else {
                            return Err("attr=FLAGS:CODE:HEX".into());
                        };
                        let flags = u8::from_str_radix(f, 16).map_err(|e| e.to_string())?;
                        extra.push(attr(flags, num(c)?, &parse_hex(&[hex])?));
                    }
                    "size" => size = Some(num::<usize>(v)?),
                    _ => return Err(format!("unknown announce key '{k}'")),
                }
                continue;
            }
            let (addr, len) = arg.split_once('/').ok_or(format!("bad prefix '{arg}'"))?;
            let len: u8 = num(len)?;
            if let Ok(a) = addr.parse::<Ipv4Addr>() {
                v4.push(prefix_bytes(&a.octets(), len));
            } else {
                v6.push(prefix_bytes(&num::<Ipv6Addr>(addr)?.octets(), len));
            }
        }
        let as4 = self.conn()?.as4;
        let mut base = Vec::new();
        if announce {
            base.push(attr(0x40, 1, &[0])); // ORIGIN IGP
            let mut segs = Vec::new();
            if !path.is_empty() {
                segs.extend([2, u8::try_from(path.len()).map_err(|_| "path too long")?]);
                for asn in &path {
                    if as4 {
                        segs.extend(asn.to_be_bytes());
                    } else {
                        segs.extend(u16::try_from(*asn).unwrap_or(23456).to_be_bytes());
                    }
                }
            }
            base.push(attr(0x40, 2, &segs));
        }
        base.extend(extra);
        if !v4.is_empty() {
            let mut attrs = base.clone();
            let nlri: Vec<u8> = v4.concat();
            let body = if announce {
                attrs.push(attr(0x40, 3, &nh4.octets()));
                update_body(&[], &attrs.concat(), &nlri)
            } else {
                update_body(&nlri, &attrs.concat(), &[])
            };
            self.send_update(body, size)?;
        }
        if !v6.is_empty() {
            let mut attrs = base;
            let nlri: Vec<u8> = v6.concat();
            if announce {
                let mut mp = vec![0, 2, 1, 16];
                mp.extend(nh6.octets());
                mp.push(0);
                mp.extend(&nlri);
                attrs.push(attr(0x80, 14, &mp));
            } else {
                let mut mp = vec![0, 2, 1];
                mp.extend(&nlri);
                attrs.push(attr(0x80, 15, &mp));
            }
            self.send_update(update_body(&[], &attrs.concat(), &[]), size)?;
        }
        Ok(())
    }

    /// Sends an UPDATE body, padded to `size` bytes on the wire if given.
    fn send_update(&mut self, body: Vec<u8>, size: Option<usize>) -> Result<()> {
        let Some(size) = size else {
            return self.send_msg(UPDATE, &body);
        };
        // Padding attribute: flags, type, 2-octet length = 4 bytes of overhead.
        let pad = size
            .checked_sub(19 + body.len() + 4)
            .ok_or(format!("size {size} is below the unpadded UPDATE"))?;
        let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        let attrs_at = 2 + withdrawn_len;
        let attrs_len = usize::from(u16::from_be_bytes([body[attrs_at], body[attrs_at + 1]]));
        let mut padded = body[..attrs_at].to_vec();
        let new_len = u16::try_from(attrs_len + 4 + pad).map_err(|_| "attributes too long")?;
        padded.extend(new_len.to_be_bytes());
        padded.extend(&body[attrs_at + 2..attrs_at + 2 + attrs_len]);
        // Always the extended length form, so the overhead is 4 bytes.
        padded.extend([0xd0, 250]);
        padded.extend((pad as u16).to_be_bytes());
        padded.extend(std::iter::repeat_n(0, pad));
        padded.extend(&body[attrs_at + 2 + attrs_len..]);
        self.send_msg(UPDATE, &padded)
    }

    fn send_msg(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let mut msg = MARKER.to_vec();
        // Lengths above 65535 wrap; use `raw` for deliberately wrong lengths.
        msg.extend(((19 + body.len()) as u16).to_be_bytes());
        msg.push(kind);
        msg.extend(body);
        self.log(format_args!("send {} len={}", type_name(kind), msg.len()));
        self.write(&msg)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.log(format_args!(
            "send raw len={} {}",
            bytes.len(),
            hex(&bytes[..bytes.len().min(64)])
        ));
        self.write(bytes)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let pace = self.pace;
        let c = self.conn()?;
        if pace.is_zero() {
            return c.stream.write_all(bytes).map_err(|e| format!("write: {e}"));
        }
        for b in bytes {
            c.stream
                .write_all(&[*b])
                .map_err(|e| format!("write: {e}"))?;
            thread::sleep(pace);
        }
        Ok(())
    }

    /// Next message, or the connection end; `None` on timeout.
    fn recv(&mut self, deadline: Instant) -> Result<Option<Recv>> {
        loop {
            let c = self.conn()?;
            if c.buf.len() >= 19 {
                let len = usize::from(u16::from_be_bytes([c.buf[16], c.buf[17]]));
                if len < 19 {
                    return Err(format!("peer sent a bad length {len}"));
                }
                if c.buf.len() >= len {
                    let msg: Vec<u8> = c.buf.drain(..len).collect();
                    let kind = msg[18];
                    let body = msg[19..].to_vec();
                    self.show(kind, &body);
                    if kind == OPEN {
                        let (as4, ext) = open_caps(&body);
                        let c = self.conn()?;
                        c.as4 = c.sent_as4 && as4;
                        c.ext = c.sent_ext && ext;
                    }
                    return Ok(Some(Recv::Msg(kind, body)));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let c = self.conn()?;
            c.stream
                .set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))))
                .map_err(|e| e.to_string())?;
            let mut chunk = [0u8; 65536];
            match c.stream.read(&mut chunk) {
                Ok(0) => return Ok(Some(Recv::Closed("closed".into()))),
                Ok(n) => c.buf.extend(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => return Ok(Some(Recv::Closed(e.to_string()))),
            }
        }
    }

    fn expect(&mut self, args: &[&str]) -> Result<()> {
        let mut timeout = DEFAULT_TIMEOUT;
        let mut want = None;
        let mut what = "";
        for arg in args {
            if let Some(t) = arg.strip_prefix("timeout=") {
                timeout = num(t)?;
            } else if what.is_empty() {
                what = arg;
            } else {
                want = Some(code_sub(arg)?);
            }
        }
        let kind = match what {
            "close" => None,
            w => Some(msg_type(w)?),
        };
        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        loop {
            match self.recv(deadline)? {
                None => return Err(format!("timeout after {timeout} s waiting for {what}")),
                Some(Recv::Closed(why)) => {
                    self.log(format_args!("recv end of connection ({why})"));
                    self.conn = None;
                    return if kind.is_none() {
                        Ok(())
                    } else {
                        Err(format!("connection ended while waiting for {what}"))
                    };
                }
                Some(Recv::Msg(k, body)) => {
                    if Some(k) == kind {
                        if let Some((code, sub)) = want
                            && body.get(..2) != Some(&[code, sub][..])
                        {
                            return Err(format!(
                                "expected NOTIFICATION {code}/{sub}, got {}",
                                notification_text(&body)
                            ));
                        }
                        return Ok(());
                    }
                    // KEEPALIVEs and herald's own UPDATEs come at any time.
                    if k != KEEPALIVE && k != UPDATE {
                        return Err(format!("expected {what}, got {}", type_name(k)));
                    }
                }
            }
        }
    }

    fn run(&mut self, duration: Duration) -> Result<()> {
        let end = Instant::now() + duration;
        while Instant::now() < end {
            self.send_msg(KEEPALIVE, &[])?;
            let tick = (Instant::now() + Duration::from_secs(3)).min(end);
            while let Some(r) = self.recv(tick)? {
                match r {
                    Recv::Closed(why) => {
                        self.conn = None;
                        return Err(format!("connection ended ({why})"));
                    }
                    Recv::Msg(NOTIFICATION, _) => return Err("peer sent a NOTIFICATION".into()),
                    Recv::Msg(..) => {}
                }
            }
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        let Some(c) = self.conn.as_mut() else {
            return Ok(());
        };
        let _ = c.stream.shutdown(Shutdown::Write);
        let deadline = Instant::now() + Duration::from_millis(200);
        while let Ok(Some(Recv::Msg(..))) = self.recv(deadline) {}
        self.conn = None;
        Ok(())
    }

    /// Sends every file of `dir` on an established session.
    fn replay(&mut self, args: &[&str]) -> Result<()> {
        let (dir, rest) = args.split_first().ok_or("replay needs a directory")?;
        let mut max = usize::MAX;
        let mut open_args = Vec::new();
        for arg in rest {
            match arg.strip_prefix("max=") {
                Some(m) => max = num(m)?,
                None => open_args.push(*arg),
            }
        }
        let mut files: Vec<_> = fs::read_dir(Path::new(dir))
            .map_err(|e| format!("{dir}: {e}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        files.truncate(max);
        let (mut kept, mut closed, mut notified) = (0, 0, 0);
        for (i, file) in files.iter().enumerate() {
            if self.conn.is_none() {
                self.accept(Duration::from_secs(30))?;
                self.open(&open_args)?;
                self.expect(&["open"])?;
                self.send_msg(KEEPALIVE, &[])?;
                self.expect(&["keepalive"])?;
            }
            let data = fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
            self.log(format_args!(
                "replay {}/{} {}",
                i + 1,
                files.len(),
                file.display()
            ));
            self.write(&data)?;
            // A KEEPALIVE after the input: shows whether the session survived.
            let _ = self.write(&keepalive());
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match self.recv(deadline) {
                    Ok(None) => {
                        kept += 1;
                        break;
                    }
                    Ok(Some(Recv::Msg(NOTIFICATION, _))) => {
                        notified += 1;
                        // The peer closes after its NOTIFICATION.
                        self.conn = None;
                        break;
                    }
                    Ok(Some(Recv::Msg(..))) => {}
                    Ok(Some(Recv::Closed(_))) | Err(_) => {
                        closed += 1;
                        self.conn = None;
                        break;
                    }
                }
            }
        }
        self.log(format_args!(
            "replay summary: inputs={} kept={kept} notification={notified} closed={closed}",
            files.len()
        ));
        Ok(())
    }

    /// Logs a received message.
    fn show(&self, kind: u8, body: &[u8]) {
        let detail = match kind {
            OPEN => open_text(body),
            NOTIFICATION => notification_text(body),
            UPDATE => {
                let as4 = self.conn.as_ref().is_some_and(|c| c.as4);
                update_text(body, as4)
            }
            _ => hex(body),
        };
        self.log(format_args!(
            "recv {} len={} {detail}",
            type_name(kind),
            body.len() + 19
        ));
    }
}

fn keepalive() -> Vec<u8> {
    let mut m = MARKER.to_vec();
    m.extend([0, 19, KEEPALIVE]);
    m
}

fn attr(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(value.len() + 4);
    if value.len() > 255 {
        a.extend([flags | 0x10, code]);
        a.extend((value.len() as u16).to_be_bytes());
    } else {
        a.extend([flags & !0x10, code, value.len() as u8]);
    }
    a.extend(value);
    a
}

fn update_body(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend((withdrawn.len() as u16).to_be_bytes());
    b.extend(withdrawn);
    b.extend((attrs.len() as u16).to_be_bytes());
    b.extend(attrs);
    b.extend(nlri);
    b
}

fn prefix_bytes(addr: &[u8], len: u8) -> Vec<u8> {
    let n = usize::from(len).div_ceil(8);
    let mut p = vec![len];
    p.extend(&addr[..n.min(addr.len())]);
    p
}

fn open_caps(body: &[u8]) -> (bool, bool) {
    let (mut as4, mut ext) = (false, false);
    let Some(&opt_len) = body.get(9) else {
        return (as4, ext);
    };
    let opt = body.get(10..10 + usize::from(opt_len)).unwrap_or(&[]);
    let mut i = 0;
    while i + 2 <= opt.len() {
        let (kind, len) = (opt[i], usize::from(opt[i + 1]));
        let value = opt.get(i + 2..i + 2 + len).unwrap_or(&[]);
        if kind == 2 {
            let mut j = 0;
            while j + 2 <= value.len() {
                match value[j] {
                    65 => as4 = true,
                    6 => ext = true,
                    _ => {}
                }
                j += 2 + usize::from(value[j + 1]);
            }
        }
        i += 2 + len;
    }
    (as4, ext)
}

fn open_text(body: &[u8]) -> String {
    if body.len() < 10 {
        return hex(body);
    }
    format!(
        "version={} as={} hold={} id={} params={}",
        body[0],
        u16::from_be_bytes([body[1], body[2]]),
        u16::from_be_bytes([body[3], body[4]]),
        Ipv4Addr::new(body[5], body[6], body[7], body[8]),
        hex(&body[10..])
    )
}

fn notification_text(body: &[u8]) -> String {
    match body {
        [code, sub, data @ ..] => format!("{code}/{sub} data={}", hex(data)),
        _ => hex(body),
    }
}

/// UPDATE as text: withdrawn, attributes (AS paths decoded) and NLRI.
fn update_text(body: &[u8], as4: bool) -> String {
    let get = |i: usize| body.get(i).copied().unwrap_or(0);
    let wlen = usize::from(u16::from_be_bytes([get(0), get(1)]));
    let alen_at = 2 + wlen;
    let alen = usize::from(u16::from_be_bytes([get(alen_at), get(alen_at + 1)]));
    let attrs = body.get(alen_at + 2..alen_at + 2 + alen).unwrap_or(&[]);
    let mut out = Vec::new();
    if wlen > 0 {
        out.push(format!(
            "withdrawn={}",
            hex(body.get(2..2 + wlen).unwrap_or(&[]))
        ));
    }
    let mut i = 0;
    while i + 3 <= attrs.len() {
        let (flags, code) = (attrs[i], attrs[i + 1]);
        let (len, hdr) = if flags & 0x10 != 0 && i + 4 <= attrs.len() {
            (
                usize::from(u16::from_be_bytes([attrs[i + 2], attrs[i + 3]])),
                4,
            )
        } else {
            (usize::from(attrs[i + 2]), 3)
        };
        let value = attrs.get(i + hdr..i + hdr + len).unwrap_or(&[]);
        out.push(match code {
            2 => format!("AS_PATH=[{}]", as_path(value, if as4 { 4 } else { 2 })),
            17 => format!("AS4_PATH=[{}]", as_path(value, 4)),
            _ => format!("attr{code}={}", hex(value)),
        });
        i += hdr + len;
    }
    let nlri = body.get(alen_at + 2 + alen..).unwrap_or(&[]);
    if !nlri.is_empty() {
        out.push(format!("nlri={}", hex(nlri)));
    }
    if out.is_empty() {
        "end-of-rib ipv4".into()
    } else {
        out.join(" ")
    }
}

fn as_path(value: &[u8], width: usize) -> String {
    let mut segs = Vec::new();
    let mut i = 0;
    while i + 2 <= value.len() {
        let (kind, n) = (value[i], usize::from(value[i + 1]));
        let asns: Vec<String> = (0..n)
            .filter_map(|k| value.get(i + 2 + k * width..i + 2 + (k + 1) * width))
            .map(|b| {
                b.iter()
                    .fold(0u32, |a, x| a << 8 | u32::from(*x))
                    .to_string()
            })
            .collect();
        let name = if kind == 1 { "set" } else { "seq" };
        segs.push(format!("{name} {}", asns.join(" ")));
        i += 2 + n * width;
    }
    segs.join("; ")
}

fn type_name(kind: u8) -> String {
    match kind {
        OPEN => "OPEN".into(),
        UPDATE => "UPDATE".into(),
        NOTIFICATION => "NOTIFICATION".into(),
        KEEPALIVE => "KEEPALIVE".into(),
        REFRESH => "ROUTE-REFRESH".into(),
        k => format!("TYPE{k}"),
    }
}

fn msg_type(name: &str) -> Result<u8> {
    Ok(match name {
        "open" => OPEN,
        "update" => UPDATE,
        "notification" => NOTIFICATION,
        "keepalive" => KEEPALIVE,
        "refresh" => REFRESH,
        n => num(n)?,
    })
}

fn code_sub(s: &str) -> Result<(u8, u8)> {
    let (c, s) = s
        .split_once('/')
        .ok_or(format!("expected CODE/SUB, got '{s}'"))?;
    Ok((num(c)?, num(s)?))
}

fn num<T: FromStr>(s: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    s.parse().map_err(|e| format!("'{s}': {e}"))
}

fn secs(s: &str) -> Result<Duration> {
    Ok(Duration::from_secs_f64(num(s)?))
}

fn parse_hex(tokens: &[&str]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for t in tokens {
        if let Some((byte, n)) = t.split_once('*') {
            let b = u8::from_str_radix(byte, 16).map_err(|e| format!("'{t}': {e}"))?;
            out.extend(std::iter::repeat_n(b, num(n)?));
            continue;
        }
        if t.len() % 2 != 0 {
            return Err(format!("odd number of hex digits in '{t}'"));
        }
        for i in (0..t.len()).step_by(2) {
            out.push(u8::from_str_radix(&t[i..i + 2], 16).map_err(|e| format!("'{t}': {e}"))?);
        }
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
