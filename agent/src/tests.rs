//! Тесты ловушек: поднимаем ловушку на loopback-порту, подключаемся как
//! клиент и проверяем и ответы, и события, которые ушли бы в центр.

use crate::event::Event;
use crate::sender::EventSink;
use crate::session::Session;
use crate::traps::Trap;
use serde_json::{json, Value};
use std::sync::mpsc::Receiver;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Поднимает TCP-ловушку на свободном порту, прогоняет её через соединение и
/// возвращает (что получил клиент, список событий).
async fn run_tcp(class: &str, params: Value, send: &[u8]) -> (Vec<u8>, Vec<Event>) {
    run_tcp_script(class, params, |mut client| async move {
        if !send.is_empty() {
            client.write_all(send).await.unwrap();
        }
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(500), client.read_to_end(&mut buf)).await;
        buf
    })
    .await
}

async fn run_tcp_script<F, Fut>(class: &str, params: Value, client_fn: F) -> (Vec<u8>, Vec<Event>)
where
    F: FnOnce(TcpStream) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let trap = Trap::build(&trap_cfg(class, &params)).unwrap();
    let (sink, rx) = EventSink::test_sink();
    let class = class.to_string();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut s = Session::new(stream, addr.port(), sink, &class, "srv01".into(), 2.0);
        s.emit(s.event(crate::event::event_type::CONNECT));
        trap.handle(&mut s).await;
        s.emit(s.disconnect_event("closed"));
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let received = client_fn(client).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    (received, drain(rx))
}

fn trap_cfg(class: &str, params: &Value) -> crate::config::TrapConfig {
    let full = json!({ "class": class, "bind": "127.0.0.1", "port": 0, "params": params });
    serde_json::from_value(full).unwrap()
}

fn drain(rx: Receiver<Event>) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn has_type<'a>(evs: &'a [Event], t: &str) -> Option<&'a Event> {
    evs.iter().find(|e| e.event_type == t)
}

// ----------------------------- util -----------------------------

#[test]
fn util_render_and_escape() {
    use crate::util::{parse_hex, parse_ports, render};
    let mut ctx = std::collections::HashMap::new();
    ctx.insert("hostname".to_string(), "srv01".to_string());
    let out = render("220 {hostname} ready\\r\\n", &ctx);
    assert_eq!(out, b"220 srv01 ready\r\n");
    // неизвестная переменная остаётся как есть
    assert_eq!(render("{unknown}", &std::collections::HashMap::new()), b"{unknown}");
    assert_eq!(parse_hex("52 46 42"), vec![0x52, 0x46, 0x42]);
    assert_eq!(parse_ports("8000-8002,9200"), vec![8000, 8001, 8002, 9200]);
}

// ----------------------------- banner -----------------------------

#[tokio::test]
async fn banner_sends_and_logs_input() {
    let (recv, evs) = run_tcp(
        "banner",
        json!({ "banner": "SSH-2.0-OpenSSH_8.9\\r\\n", "close_after_input": true }),
        b"SSH-2.0-OpenSSH_9.6\r\n",
    )
    .await;
    assert_eq!(recv, b"SSH-2.0-OpenSSH_8.9\r\n");
    let data = has_type(&evs, "data").expect("нет события data");
    assert!(data.data["text"].as_str().unwrap().contains("OpenSSH_9.6"));
    assert!(has_type(&evs, "connect").is_some());
    assert!(has_type(&evs, "disconnect").is_some());
}

// ----------------------------- dialog (FTP) -----------------------------

fn ftp_params() -> Value {
    json!({
        "greeting": "220 (vsFTPd 3.0.5)\\r\\n",
        "decoder": "line",
        "default_response": "530 Please login.\\r\\n",
        "rules": [
            { "match": "^USER\\s+(.*)$", "response": "331 Password required\\r\\n", "capture": "username" },
            { "match": "^PASS\\s?(.*)$", "response": "530 Login incorrect.\\r\\n", "capture": "password" },
            { "match": "^QUIT", "response": "221 Bye\\r\\n", "close": true }
        ]
    })
}

#[tokio::test]
async fn dialog_ftp_captures_credentials() {
    let (recv, evs) = run_tcp("dialog", ftp_params(), b"USER admin\r\nPASS s3cret\r\nQUIT\r\n").await;
    let text = String::from_utf8_lossy(&recv);
    assert!(text.starts_with("220 (vsFTPd 3.0.5)"));
    assert!(text.contains("331 Password required"));
    assert!(text.contains("221 Bye"));

    let auth = has_type(&evs, "auth").expect("нет события auth");
    assert_eq!(auth.username.as_deref(), Some("admin"));
    assert_eq!(auth.password.as_deref(), Some("s3cret"));
}

#[tokio::test]
async fn dialog_smtp_sasl_plain_decoded() {
    // AUTH PLAIN base64("\0user\0pass") -> AHVzZXIAcGFzcw==
    let params = json!({
        "greeting": "220 mail ready\\r\\n",
        "rules": [
            { "match": "^AUTH PLAIN\\s+(\\S+)$", "response": "535 fail\\r\\n", "capture": "username", "decode": "sasl_plain" }
        ]
    });
    let (_recv, evs) = run_tcp("dialog", params, b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n").await;
    let auth = has_type(&evs, "auth").expect("нет auth");
    assert_eq!(auth.username.as_deref(), Some("user"));
    assert_eq!(auth.password.as_deref(), Some("pass"));
}

// ----------------------------- http -----------------------------

#[tokio::test]
async fn http_captures_form_login() {
    let params = json!({
        "routes": [
            { "path": "^/login", "method": "POST", "status": 200, "body": "<h1>ok</h1>", "capture_login": true, "tag": "wp-login" }
        ]
    });
    let req = b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\nConnection: close\r\n\r\nusername=root&password=toor";
    let (recv, evs) = run_tcp("http", params, req).await;
    assert!(String::from_utf8_lossy(&recv).contains("200 OK"));
    let auth = has_type(&evs, "auth").expect("нет auth");
    assert_eq!(auth.username.as_deref(), Some("root"));
    assert_eq!(auth.password.as_deref(), Some("toor"));
    let req_ev = has_type(&evs, "request").expect("нет request");
    assert_eq!(req_ev.data["tag"], "wp-login");
}

#[tokio::test]
async fn http_unmatched_path_returns_404() {
    let params = json!({ "routes": [], "not_found_body": "nope" });
    let req = b"GET /secret HTTP/1.0\r\nHost: x\r\n\r\n";
    let (recv, evs) = run_tcp("http", params, req).await;
    assert!(String::from_utf8_lossy(&recv).contains("404 Not Found"));
    assert!(has_type(&evs, "request").is_some());
}

// ----------------------------- port_listener (scan) -----------------------------

#[tokio::test]
async fn port_listener_detects_scan() {
    // Один экземпляр ловушки, три соединения на три разных dst_port.
    let trap = std::sync::Arc::new(Trap::build(&trap_cfg("port_listener", &json!({ "action": "close", "scan_threshold": 3 }))).unwrap());
    let (sink, rx) = EventSink::test_sink();
    for port in [9000u16, 9001, 9002] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let trap = trap.clone();
        let sink = sink.clone();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // подменяем dst_port вручную через Session (эмулируем разные порты)
            let mut s = Session::new(stream, port, sink, "port_listener", "srv01".into(), 1.0);
            trap.handle(&mut s).await;
        });
        let _c = TcpStream::connect(addr).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), srv).await;
    }
    let evs = drain(rx);
    let scan = has_type(&evs, "scan").expect("нет события scan");
    let ports = scan.data["ports"].as_array().unwrap();
    assert_eq!(ports.len(), 3);
}

// ----------------------------- tarpit -----------------------------

#[tokio::test]
async fn tarpit_http_mode_sends_status_then_headers() {
    let (recv, _evs) = run_tcp_script(
        "tarpit",
        json!({ "mode": "http_headers", "delay_ms": 20, "max_hold_s": 1 }),
        |mut client| async move {
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            buf.truncate(n);
            buf
        },
    )
    .await;
    assert!(String::from_utf8_lossy(&recv).starts_with("HTTP/1.1 200 OK"));
}

// ----------------------------- honeytoken -----------------------------

#[tokio::test]
async fn honeytoken_detects_url_hit() {
    let params = json!({ "tokens": [{ "kind": "url", "token": "abc123", "label": "share/README" }] });
    let (recv, evs) = run_tcp("honeytoken", params, b"GET /static/abc123/logo.png HTTP/1.1\r\nUser-Agent: curl/8\r\n\r\n").await;
    assert!(String::from_utf8_lossy(&recv).contains("200 OK"));
    let token = has_type(&evs, "token").expect("нет события token");
    assert_eq!(token.data["token"], "abc123");
    assert_eq!(token.data["user_agent"], "curl/8");
}

// ----------------------------- udp (DNS) -----------------------------

#[tokio::test]
async fn udp_dns_answers_a_query() {
    use tokio::net::UdpSocket;
    let trap = std::sync::Arc::new(Trap::build(&trap_cfg("udp", &json!({ "helper": "dns", "dns_answer_ip": "10.0.0.15" }))).unwrap());
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let saddr = server.local_addr().unwrap();
    let (sink, rx) = EventSink::test_sink();

    let responder = match &*trap {
        Trap::Udp(u) => u.clone(),
        _ => unreachable!(),
    };
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        let (n, addr) = server.recv_from(&mut buf).await.unwrap();
        let resp = responder.on_datagram(&buf[..n], &addr.ip().to_string(), addr.port(), saddr.port(), &sink);
        server.send_to(&resp, addr).await.unwrap();
    });

    // DNS A-запрос для example.com
    let query: Vec<u8> = {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A QCLASS=IN
        q
    };
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&query, saddr).await.unwrap();
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await.unwrap().unwrap();
    buf.truncate(n);

    // последние 4 байта ответа — IP 10.0.0.15
    assert_eq!(&buf[buf.len() - 4..], &[10, 0, 0, 15]);
    let evs = drain(rx);
    let data = has_type(&evs, "data").expect("нет события data");
    assert_eq!(data.data["qname"], "example.com");
}

// ----------------------------- ssh -----------------------------

struct AcceptAnyHostKey;

impl russh::client::Handler for AcceptAnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn ssh_logs_credentials_and_denies() {
    let params = json!({ "fail_delay_ms": "0" });
    let (_, evs) = run_tcp_script("ssh", params, |stream| async move {
        let cfg = std::sync::Arc::new(russh::client::Config::default());
        let mut h = russh::client::connect_stream(cfg, stream, AcceptAnyHostKey).await.unwrap();
        for pass in ["hunter2", "toor"] {
            let res = h.authenticate_password("root", pass).await.unwrap();
            match res {
                russh::client::AuthResult::Failure { remaining_methods, .. } => {
                    // sshd даёт повторить пароль: метод не исчезает из списка
                    assert!(remaining_methods.contains(&russh::MethodKind::Password));
                }
                russh::client::AuthResult::Success => panic!("ловушка не должна пускать"),
            }
        }
        Vec::new()
    })
    .await;

    let hs = has_type(&evs, "handshake").expect("нет события handshake");
    assert!(hs.data["client_version"].as_str().unwrap().starts_with("SSH-2.0-"));
    let auths: Vec<_> = evs.iter().filter(|e| e.event_type == "auth").collect();
    assert_eq!(auths.len(), 2, "события: {evs:?}");
    assert_eq!(auths[0].username.as_deref(), Some("root"));
    assert_eq!(auths[0].password.as_deref(), Some("hunter2"));
    assert_eq!(auths[1].password.as_deref(), Some("toor"));
    assert_eq!(auths[1].data["attempt"], 2);
    assert_eq!(auths[0].data["method"], "password");
}

#[test]
fn ssh_host_key_is_stable_per_seed() {
    let mk = |seed: &str| {
        let mut cfg = trap_cfg("ssh", &json!({}));
        cfg.key_seed = seed.to_string();
        match Trap::build(&cfg).unwrap() {
            Trap::Ssh(t) => t.host_fingerprint(),
            _ => unreachable!(),
        }
    };
    assert_eq!(mk("tok-a"), mk("tok-a"));
    assert_ne!(mk("tok-a"), mk("tok-b"));
}

#[test]
fn ssh_rejects_bad_version() {
    assert!(Trap::build(&trap_cfg("ssh", &json!({ "version": "OpenSSH_8.9" }))).is_err());
}
