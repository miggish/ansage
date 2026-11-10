use std::{collections::HashMap, net::SocketAddr, time::Duration};

use crate::config::ExportPolicy;

use crate::config::ImportPolicy;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{answer::matches, *};
use crate::{
    peer::status::{self, NeighborInfo, PeerCommand},
    rib::{self, PeerSettings, Rib, RibConfig, SourceId},
};

/// A socket path no other test uses.
fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ansage-test-{}-{name}.sock", std::process::id()))
}

fn neighbor(id: SourceId, address: &str) -> NeighborInfo {
    NeighborInfo {
        id,
        address: address.parse().unwrap(),
        asn: 64500 + u32::from(id),
        description: Some(format!("router {id}")),
        import: ImportPolicy::All,
        export: ExportPolicy::Own,
        role: None,
        default_route: false,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        tcp_md5: false,
        ttl_security: None,
        graceful_restart: None,
    }
}

struct Server {
    path: PathBuf,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    /// Keeps the RIB running; the server only has a weak sender.
    rib: Option<mpsc::Sender<RibMsg>>,
    _reporters: Vec<status::Reporter>,
}

/// A context over a running RIB with neighbors 1 and 2; keep the sender
/// and the reporters alive while it is used.
fn context() -> (Arc<Context>, mpsc::Sender<RibMsg>, Vec<status::Reporter>) {
    let rib = Rib::new(RibConfig {
        local_asn: 64500,
        announce: vec!["192.0.2.0/24".parse().unwrap()],
        max_prefix_restart: Duration::from_secs(300),
        peers: HashMap::from([(1, PeerSettings::default()), (2, PeerSettings::default())]),
        install_families: [false, false],
    });
    let (rib_tx, rib_rx) = mpsc::channel(16);
    tokio::spawn(rib::run(rib, rib_rx));

    let mut reporters = Vec::new();
    let mut peers = Vec::new();
    for (id, address) in [(1, "10.0.0.1:179"), (2, "10.0.0.2:1179")] {
        let (reporter, handle) =
            status::peer_channel(neighbor(id, address), Duration::from_secs(5));
        reporters.push(reporter);
        peers.push(handle);
    }
    let ctx = Arc::new(Context {
        fib: None,
        asn: 64500,
        router_id: Ipv4Addr::new(203, 0, 113, 1),
        started: Timestamp::now(),
        peers: Arc::new(std::sync::RwLock::new(peers)),
        rib: rib_tx.downgrade(),
        reload: None,
        restart: None,
        config_path: None,
    });
    (ctx, rib_tx, reporters)
}

async fn start(name: &str) -> Server {
    let (ctx, rib_tx, reporters) = context();
    let path = socket_path(name);
    let listener = bind(&path).unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(run(listener, path.clone(), ctx, shutdown_rx));
    Server {
        path,
        shutdown,
        task,
        rib: Some(rib_tx),
        _reporters: reporters,
    }
}

impl Server {
    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.task.await.unwrap();
        assert!(!self.path.exists(), "socket removed on shutdown");
    }
}

struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    async fn connect(path: &Path) -> Self {
        let (reader, writer) = UnixStream::connect(path).await.unwrap().into_split();
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    async fn send(&mut self, line: &str) -> Value {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
        self.recv().await
    }

    async fn recv(&mut self) -> Value {
        let mut reply = String::new();
        self.reader.read_line(&mut reply).await.unwrap();
        assert!(reply.ends_with('\n'), "reply is one line: {reply:?}");
        serde_json::from_str(&reply).unwrap()
    }
}

fn error(reply: &Value) -> &str {
    reply["error"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error: {reply}"))
}

#[tokio::test]
async fn summary_peers_and_rib() {
    let server = start("answers").await;
    let mut client = Client::connect(&server.path).await;

    let summary = client.send(r#"{"cmd":"summary"}"#).await;
    let ok = &summary["ok"];
    assert_eq!(ok["asn"], 64500);
    assert_eq!(ok["router_id"], "203.0.113.1");
    assert_eq!(ok["announce"], serde_json::json!(["192.0.2.0/24"]));
    assert_eq!(ok["rib"]["prefixes_ipv4"], 1);
    assert_eq!(ok["peers"][0]["address"], "10.0.0.1:179");
    assert_eq!(ok["peers"][0]["state"], "Idle");
    assert_eq!(ok["peers"][1]["received_ipv4"], 0);

    // Several requests on one connection; filters by ID, IP and IP:port.
    let all = client.send(r#"{"v":1,"cmd":"peers"}"#).await;
    assert_eq!(all["ok"].as_array().unwrap().len(), 2);
    for filter in ["2", "10.0.0.2", "10.0.0.2:1179"] {
        let one = client
            .send(&format!(r#"{{"cmd":"peers","peer":"{filter}"}}"#))
            .await;
        let list = one["ok"].as_array().unwrap();
        assert_eq!(list.len(), 1, "{filter}");
        assert_eq!(list[0]["neighbor"]["id"], 2);
        assert_eq!(list[0]["status"]["backoff_ms"], 5000);
        assert_eq!(list[0]["counters"]["connect_attempts"], 0);
        assert!(list[0]["rib"].is_null(), "no session, no RIB state");
    }
    let none = client
        .send(r#"{"cmd":"peers","peer":"10.0.0.2:179"}"#)
        .await;
    assert!(error(&none).contains("no neighbor matches"));

    let own = client
        .send(r#"{"cmd":"rib","prefix":"192.0.2.0/24"}"#)
        .await;
    let routes = own["ok"]["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0]["source"], "local");
    assert_eq!(routes[0]["best"], true);
    assert_eq!(routes[0]["origin"], "igp");
    assert!(own["ok"]["total"].is_null());

    let list = client.send(r#"{"cmd":"rib"}"#).await;
    assert_eq!(list["ok"]["total"], 1);
    let v6 = client.send(r#"{"cmd":"rib","family":"ipv6"}"#).await;
    assert_eq!(v6["ok"]["total"], 0);

    server.stop().await;
}

#[tokio::test]
async fn bad_requests_get_errors() {
    let server = start("errors").await;
    let mut client = Client::connect(&server.path).await;

    assert!(error(&client.send("not json").await).starts_with("bad request"));
    assert!(error(&client.send(r#"{"cmd":"reboot"}"#).await).starts_with("bad request"));
    assert!(error(&client.send(r#"{"v":2,"cmd":"summary"}"#).await).contains("version 2"));
    let host_bits = client
        .send(r#"{"cmd":"rib","prefix":"192.0.2.1/24"}"#)
        .await;
    assert!(error(&host_bits).contains("192.0.2.1/24"));
    let both = client
        .send(r#"{"cmd":"rib","prefix":"192.0.2.0/24","limit":1}"#)
        .await;
    assert!(error(&both).contains("either"));
    // Still usable after errors.
    assert!(client.send(r#"{"cmd":"summary"}"#).await["ok"].is_object());

    // A line over the limit is refused and the connection closed.
    let mut long = Client::connect(&server.path).await;
    let line = format!(r#"{{"cmd":"peers","peer":"{}"}}"#, "x".repeat(MAX_LINE));
    let reply = long.send(&line).await;
    assert!(error(&reply).contains("longer than"));
    let mut rest = String::new();
    assert_eq!(long.reader.read_line(&mut rest).await.unwrap(), 0, "closed");

    server.stop().await;
}

#[tokio::test]
async fn rib_gone_is_an_error_not_a_hang() {
    let mut server = start("rib-gone").await;
    // Dropping the only strong sender stops the RIB.
    drop(server.rib.take());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = Client::connect(&server.path).await;
    let reply = client.send(r#"{"cmd":"summary"}"#).await;
    assert_eq!(error(&reply), "the RIB is not running");
    server.stop().await;
}

#[tokio::test]
async fn too_many_clients_are_refused() {
    let server = start("crowd").await;
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut client = Client::connect(&server.path).await;
        // A round trip makes sure the server took this one.
        assert!(client.send(r#"{"cmd":"summary"}"#).await["ok"].is_object());
        held.push(client);
    }
    let mut extra = Client::connect(&server.path).await;
    assert_eq!(error(&extra.recv().await), "too many clients");
    // A slot frees up when a client leaves.
    drop(held.pop());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut late = Client::connect(&server.path).await;
    assert!(late.send(r#"{"cmd":"summary"}"#).await["ok"].is_object());
    server.stop().await;
}

#[tokio::test]
async fn bind_replaces_stale_sockets_only() {
    let path = socket_path("stale");
    let _ = std::fs::remove_file(&path);
    // A socket nobody listens on (ansage crashed): replaced.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let listener = bind(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o660);

    // A live socket (another ansage): refused, and left alone.
    let err = bind(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert!(path.exists());
    drop(listener);
    std::fs::remove_file(&path).unwrap();

    // Not a socket: refused, not deleted.
    std::fs::write(&path, "data").unwrap();
    assert_eq!(
        bind(&path).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(path.exists());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn neighbor_filters() {
    let addr: SocketAddr = "[2001:db8::2]:179".parse().unwrap();
    assert!(matches("3", 3, addr));
    assert!(!matches("4", 3, addr));
    assert!(matches("2001:db8::2", 3, addr));
    assert!(matches("[2001:db8::2]:179", 3, addr));
    assert!(!matches("[2001:db8::2]:1179", 3, addr));
    assert!(!matches("router", 3, addr));
}

#[tokio::test]
async fn announce_and_withdraw_at_runtime() {
    let server = start("own").await;
    let mut client = Client::connect(&server.path).await;

    let reply = client
        .send(r#"{"cmd":"announce","prefixes":["198.51.100.0/24","192.0.2.0/24","2001:db8::/32"]}"#)
        .await;
    let ok = &reply["ok"];
    assert_eq!(
        ok["changed"],
        serde_json::json!(["198.51.100.0/24", "2001:db8::/32"])
    );
    assert_eq!(ok["unchanged"], serde_json::json!(["192.0.2.0/24"]));
    assert_eq!(ok["announce"].as_array().unwrap().len(), 3);
    let routes = client
        .send(r#"{"cmd":"rib","prefix":"2001:db8::/32"}"#)
        .await;
    assert_eq!(routes["ok"]["routes"][0]["source"], "local");

    let reply = client
        .send(r#"{"cmd":"withdraw","prefixes":["192.0.2.0/24","203.0.113.0/24"]}"#)
        .await;
    assert_eq!(reply["ok"]["changed"], serde_json::json!(["192.0.2.0/24"]));
    assert_eq!(
        reply["ok"]["unchanged"],
        serde_json::json!(["203.0.113.0/24"])
    );
    let summary = client.send(r#"{"cmd":"summary"}"#).await;
    assert_eq!(
        summary["ok"]["announce"],
        serde_json::json!(["198.51.100.0/24", "2001:db8::/32"])
    );

    // Strict parsing, like the config: nothing changes on an error.
    let reply = client
        .send(r#"{"cmd":"announce","prefixes":["192.0.2.0/24","10.0.0.1/8"]}"#)
        .await;
    assert!(error(&reply).contains("10.0.0.1/8"), "{reply}");
    let reply = client.send(r#"{"cmd":"announce","prefixes":[]}"#).await;
    assert!(error(&reply).contains("no prefixes"));
    let summary = client.send(r#"{"cmd":"summary"}"#).await;
    assert_eq!(summary["ok"]["announce"].as_array().unwrap().len(), 2);
    server.stop().await;
}

#[tokio::test]
async fn drain_and_undrain() {
    let server = start("drain").await;
    let mut client = Client::connect(&server.path).await;
    let summary = client.send(r#"{"cmd":"summary"}"#).await;
    assert!(summary["ok"]["drained"].is_null(), "{summary}");

    let reply = client.send(r#"{"cmd":"drain"}"#).await;
    assert_eq!(reply["ok"]["changed"], true, "{reply}");
    let since = reply["ok"]["drained"].as_u64().unwrap();
    let again = client.send(r#"{"cmd":"drain"}"#).await;
    assert_eq!(again["ok"]["changed"], false);
    // Same drain; the wall-clock conversion may differ by a millisecond.
    assert!(again["ok"]["drained"].as_u64().unwrap().abs_diff(since) <= 1);
    let summary = client.send(r#"{"cmd":"summary"}"#).await;
    assert!(summary["ok"]["drained"].is_u64());
    let routes = client
        .send(r#"{"cmd":"rib","prefix":"192.0.2.0/24"}"#)
        .await;
    assert!(
        routes["ok"]["routes"][0].to_string().contains("65535:0"),
        "the own route shows GRACEFUL_SHUTDOWN: {routes}"
    );

    let reply = client.send(r#"{"cmd":"undrain"}"#).await;
    assert_eq!(reply["ok"]["changed"], true);
    assert!(reply["ok"]["drained"].is_null());
    let reply = client.send(r#"{"cmd":"undrain"}"#).await;
    assert_eq!(reply["ok"]["changed"], false);
    server.stop().await;
}

#[tokio::test]
async fn peer_commands_reach_the_peer_task() {
    let mut server = start("peer-cmd").await;
    let mut client = Client::connect(&server.path).await;

    let reply = client
        .send(r#"{"cmd":"peer","peer":"10.0.0.2","action":"disable","reason":"maintenance"}"#)
        .await;
    assert_eq!(reply["ok"]["id"], 2);
    assert_eq!(reply["ok"]["action"], "disable");
    let got = server._reporters[1].commands.try_recv().unwrap();
    assert_eq!(
        got,
        PeerCommand::Disable {
            reason: "maintenance".into()
        }
    );

    let reply = client
        .send(r#"{"cmd":"peer","peer":"1","action":"reset"}"#)
        .await;
    assert_eq!(reply["ok"]["address"], "10.0.0.1:179");
    assert_eq!(
        server._reporters[0].commands.try_recv().unwrap(),
        PeerCommand::Reset
    );

    let reply = client
        .send(r#"{"cmd":"peer","peer":"10.9.9.9","action":"enable"}"#)
        .await;
    assert!(error(&reply).contains("no neighbor"));
    let reply = client
        .send(r#"{"cmd":"peer","peer":"1","action":"enable","reason":"x"}"#)
        .await;
    assert!(error(&reply).contains("only goes with disable"));
    let reply = client
        .send(r#"{"cmd":"peer","peer":"1","action":"explode"}"#)
        .await;
    assert!(error(&reply).contains("bad request"));
    server.stop().await;
}

/// One HTTP request to the metrics listener: status code and body.
async fn http(addr: std::net::SocketAddr, request: &str) -> (u16, String) {
    use tokio::io::AsyncReadExt;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    let (head, body) = reply.split_once("\r\n\r\n").unwrap();
    let code = head.split(' ').nth(1).unwrap().parse().unwrap();
    (code, body.to_string())
}

#[tokio::test]
async fn json_api_on_the_metrics_listener() {
    let (ctx, _rib, _reporters) = context();
    let listener = crate::http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(crate::http::run(listener, ctx, shutdown_rx));
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
    let json = |body: &str| serde_json::from_str::<Value>(body).unwrap();

    let (code, body) = http(addr, &get("/api/summary")).await;
    assert_eq!(code, 200, "{body}");
    let summary = json(&body);
    assert_eq!(summary["asn"], 64500);
    assert_eq!(summary["peers"].as_array().unwrap().len(), 2);

    let (code, body) = http(addr, &get("/api/peers?peer=10.0.0.2")).await;
    assert_eq!(code, 200, "{body}");
    let peers = json(&body);
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["neighbor"]["address"], "10.0.0.2:1179");

    // Percent-encoded prefix; our own route is in the RIB.
    let (code, body) = http(addr, &get("/api/rib?prefix=192.0.2.0%2F24")).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(json(&body)["routes"][0]["prefix"], "192.0.2.0/24", "{body}");
    let (code, body) = http(addr, &get("/api/rib?family=ipv4&limit=5")).await;
    assert_eq!(code, 200, "{body}");

    // Errors: JSON with the reason; unknown names 404; nothing but GET/HEAD.
    let (code, body) = http(addr, &get("/api/peers?peer=10.9.9.9")).await;
    assert_eq!(code, 400);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("no neighbor"),
        "{body}"
    );
    let (code, body) = http(addr, &get("/api/rib?family=ipx")).await;
    assert_eq!(code, 400, "{body}");
    let (code, body) = http(addr, &get("/api/summary?x=1")).await;
    assert_eq!(code, 400, "{body}");
    let (code, _) = http(addr, &get("/api/fib")).await;
    assert_eq!(code, 400, "no [kernel] here");
    for path in ["/api/reload", "/api/restart", "/api/"] {
        assert_eq!(http(addr, &get(path)).await.0, 404, "{path}");
    }
    let post = "POST /api/summary HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(http(addr, post).await.0, 405);
    let (code, body) = http(addr, &get("/metrics")).await;
    assert_eq!(code, 200);
    assert!(body.contains("ansage_"), "{body}");

    shutdown.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn event_stream_sends_the_summary_then_peer_changes() {
    let (ctx, _rib, reporters) = context();
    let listener = crate::http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(crate::http::run(listener, ctx, shutdown_rx));

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/events HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line, "HTTP/1.1 200 OK\r\n");
    // Next event: (name, data).
    async fn next(reader: &mut BufReader<tokio::net::TcpStream>) -> (String, Value) {
        let (mut name, mut data) = (String::new(), String::new());
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line));
            assert!(read.await.unwrap().unwrap() > 0, "stream ended");
            match line.trim_end().split_once(": ") {
                Some(("event", n)) => name = n.into(),
                Some(("data", d)) => data = d.into(),
                _ if line == "\n" && !name.is_empty() => {
                    return (name, serde_json::from_str(&data).unwrap());
                }
                _ => {}
            }
        }
    }
    let (name, summary) = next(&mut reader).await;
    assert_eq!(name, "summary");
    assert_eq!(summary["peers"].as_array().unwrap().len(), 2);

    reporters[1].error("connect refused");
    let (name, peer) = next(&mut reader).await;
    assert_eq!(name, "peer");
    assert_eq!(peer["neighbor"]["id"], 2);
    assert_eq!(peer["status"]["last_error"]["message"], "connect refused");

    // A shutdown ends the stream (and the listener).
    shutdown.send(true).unwrap();
    task.await.unwrap();
    let mut rest = String::new();
    let end = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut rest));
    assert_eq!(end.await.unwrap().unwrap(), 0, "stream closed: {rest:?}");
}
