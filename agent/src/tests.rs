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

// ----------------------------- e2e tests -----------------------------

#[tokio::test]
async fn e2e_iec104_trap_activation_and_interrogation() {
    let (recv, evs) = run_tcp_script("iec104", json!({}), |mut client| async move {
        // 1. Send STARTDT_ACT (0x68 0x04 0x07 0x00 0x00 0x00)
        let startdt_act = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        client.write_all(&startdt_act).await.unwrap();

        // Receive STARTDT_CON (0x68 0x04 0x0B 0x00 0x00 0x00)
        let mut con_buf = vec![0u8; 6];
        client.read_exact(&mut con_buf).await.unwrap();
        assert_eq!(&con_buf, &[0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]);

        // 2. Send C_IC_NA_1 interrogation command:
        // APCI: I frame (ns: 0, nr: 0) -> [0x00, 0x00, 0x00, 0x00]
        // ASDU: type 100 (0x64), vsq 1, cot 6, originator 0, coa 1, payload [0, 0, 0, 20]
        let interrogation = [
            0x68, 0x0e, // Start 0x68, length 14
            0x00, 0x00, 0x00, 0x00, // APCI I(0, 0)
            0x64, 0x01, 0x06, 0x00, 0x01, 0x00, // ASDU: C_IC_NA_1, COT=6, COA=1
            0x00, 0x00, 0x00, 0x14, // IOA=0, QOI=20
        ];
        client.write_all(&interrogation).await.unwrap();

        let mut resp_buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(500), client.read_to_end(&mut resp_buf)).await;

        let mut all = con_buf;
        all.extend_from_slice(&resp_buf);
        all
    })
    .await;

    // Verify response contains STARTDT_CON followed by interrogation responses
    assert!(recv.starts_with(&[0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]));
    assert!(recv.len() > 6);
    // Verifies received events
    assert!(has_type(&evs, "connect").is_some());
    assert!(has_type(&evs, "disconnect").is_some());
}

#[tokio::test]
async fn e2e_scada_modbus_read_holding_registers() {
    let req = [
        0x00, 0x01, // Transaction ID: 1
        0x00, 0x00, // Protocol ID: 0 (Modbus TCP)
        0x00, 0x06, // Length: 6 bytes following
        0x01,       // Unit ID: 1
        0x03,       // Function Code: 3 (Read Holding Registers)
        0x00, 0x00, // Starting Address: 0
        0x00, 0x02, // Quantity of Registers: 2
    ];
    let (recv, evs) = run_tcp("scada", json!({}), &req).await;

    // Verify response
    assert!(recv.len() >= 13);
    assert_eq!(&recv[0..2], &[0x00, 0x01]); // tx_id
    assert_eq!(&recv[2..4], &[0x00, 0x00]); // proto_id
    assert_eq!(&recv[4..6], &[0x00, 0x07]); // length = 7 (unit_id 1 + pdu 6)
    assert_eq!(recv[6], 1);                 // unit_id
    assert_eq!(recv[7], 0x03);              // fc
    assert_eq!(recv[8], 4);                 // byte count (2 registers * 2 bytes)
    assert_eq!(&recv[9..11], &22000u16.to_be_bytes()); // reg 0
    assert_eq!(&recv[11..13], &1500u16.to_be_bytes());  // reg 1

    // Verify events
    let req_ev = has_type(&evs, "request").expect("нет события request");
    assert_eq!(req_ev.data["protocol"], "modbus_tcp");
    assert_eq!(req_ev.data["function_code"], 3);
    assert_eq!(req_ev.data["address"], 0);
    assert_eq!(req_ev.data["quantity"], 2);
    assert_eq!(req_ev.data["unit_id"], 1);
    assert!(has_type(&evs, "connect").is_some());
    assert!(has_type(&evs, "disconnect").is_some());
}

#[tokio::test]
async fn e2e_high_interaction_vfs_and_tokens() {
    let (recv, evs) = run_tcp("high_interaction", json!({}), b"cat /root/.env\r\nexit\r\n").await;
    let text = String::from_utf8_lossy(&recv);
    assert!(text.contains("API_KEY="));

    // Verify that honeytoken alert event was captured
    let token_ev = has_type(&evs, "token").expect("нет события token");
    assert_eq!(token_ev.data["token_file"], "/root/.env");
    assert_eq!(token_ev.data["severity"], "CRITICAL");
    assert_eq!(token_ev.data["message"], "Honeytoken accessed by attacker");

    assert!(has_type(&evs, "honeytoken_hit").is_some());
    assert!(has_type(&evs, "command").is_some());
    assert!(has_type(&evs, "connect").is_some());
    assert!(has_type(&evs, "disconnect").is_some());
}

#[tokio::test]
async fn e2e_extra_traps() {
    // starts medium_extra, sends Redis PING\r\n, receives +PONG\r\n
    let (recv, evs) = run_tcp("medium_extra", json!({ "mode": "redis" }), b"PING\r\n").await;
    assert_eq!(recv, b"+PONG\r\n");

    let cmd_ev = has_type(&evs, "command").expect("нет события command");
    assert_eq!(cmd_ev.data["command"], "PING");
    assert_eq!(cmd_ev.data["proto"], "redis");

    // Also verify low_extra trap
    let (recv_low, evs_low) = run_tcp("low_extra", json!({ "mode": "echo" }), b"PING_ECHO\r\n").await;
    assert_eq!(recv_low, b"PING_ECHO\r\n");
    let scan_ev = has_type(&evs_low, "scan").expect("нет события scan");
    assert_eq!(scan_ev.data["probe_signature"], "echo_probe");
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

// ----------------------------- несколько ловушек в одном агенте -----------------------------

fn host_units(traps: Value) -> Vec<crate::runtime::Unit> {
    let cfg: crate::config::Config =
        serde_json::from_value(json!({ "center_url": "http://127.0.0.1:1", "traps": traps })).unwrap();
    crate::runtime::build_units(cfg.units().unwrap()).unwrap()
}

/// Свободный TCP-порт на loopback (сразу освобождаем — гонка в тестах приемлема).
async fn free_port() -> u16 {
    crate::plugin_tests::free_port()
}

#[tokio::test]
async fn runtime_serves_each_trap_with_its_own_sink() {
    let (p1, p2) = (free_port().await, free_port().await);
    let units = host_units(json!([
        { "token": "t-ssh", "name": "A", "class": "banner", "bind": "127.0.0.1", "port": p1,
          "params": { "banner": "AAA\\r\\n", "close_after_input": true } },
        { "token": "t-ftp", "name": "B", "class": "banner", "bind": "127.0.0.1", "port": p2,
          "params": { "banner": "BBB\\r\\n", "close_after_input": true } }
    ]));
    let bound = crate::plugin_tests::bind_all_settled(&units, 0).await.unwrap();
    assert_eq!(bound.len(), 2);
    let (s1, r1) = EventSink::test_sink();
    let (s2, r2) = EventSink::test_sink();
    let handles = crate::runtime::serve(&units, bound, &[s1, s2]);

    for (port, want) in [(p1, "AAA"), (p2, "BBB")] {
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"hello\r\n").await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut buf)).await;
        assert!(String::from_utf8_lossy(&buf).starts_with(want), "порт {port}: {buf:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for h in handles {
        h.abort();
    }

    // События каждой ловушки ушли только в её канал (а значит, в центр под её токеном).
    let (e1, e2) = (drain(r1), drain(r2));
    assert!(has_type(&e1, "connect").is_some() && has_type(&e2, "connect").is_some());
    assert!(e1.iter().all(|e| e.dst_port == p1), "{e1:?}");
    assert!(e2.iter().all(|e| e.dst_port == p2), "{e2:?}");
}

#[tokio::test]
async fn runtime_ssh_host_key_follows_trap_token() {
    let units = host_units(json!([
        { "token": "tok-1", "class": "ssh", "port": 1 },
        { "token": "tok-2", "class": "ssh", "port": 2 }
    ]));
    let fp = |i: usize| match &*units[i].trap {
        Trap::Ssh(t) => t.host_fingerprint(),
        _ => unreachable!(),
    };
    let solo = crate::traps::ssh::SshTrap::new(&json!({}), "tok-1").unwrap();
    assert_eq!(fp(0), solo.host_fingerprint(), "ключ тот же, что у ловушки с этим токеном отдельно");
    assert_ne!(fp(0), fp(1), "у разных ловушек разные ключи хоста");
}

#[test]
fn runtime_rejects_port_clash_but_allows_tcp_and_udp_on_same_number() {
    let cfg = |traps: Value| -> crate::config::Config {
        serde_json::from_value(json!({ "center_url": "x", "traps": traps })).unwrap()
    };
    let err = crate::runtime::build_units(
        cfg(json!([
            { "token": "a", "name": "SSH", "class": "ssh", "port": 2222 },
            { "token": "b", "name": "Shell", "class": "high_interaction", "port": 2222 }
        ]))
        .units()
        .unwrap(),
    )
    .err()
    .unwrap();
    assert!(err.contains("2222/tcp") && err.contains("«SSH»") && err.contains("«Shell»"), "{err}");

    // Порт внутри диапазона многопортовой ловушки — тоже конфликт.
    let err = crate::runtime::build_units(
        cfg(json!([
            { "token": "a", "class": "port_listener", "ports": "9000-9005" },
            { "token": "b", "class": "banner", "port": 9003 }
        ]))
        .units()
        .unwrap(),
    )
    .err()
    .unwrap();
    assert!(err.contains("9003/tcp"), "{err}");

    // 53/tcp и 53/udp — разные сокеты.
    let units = crate::runtime::build_units(
        cfg(json!([
            { "token": "a", "class": "udp", "port": 5353 },
            { "token": "b", "class": "banner", "port": 5353 }
        ]))
        .units()
        .unwrap(),
    )
    .unwrap();
    assert_eq!(units.len(), 2);

    // Ошибка сборки ловушки называет, какая именно сломана.
    let err = crate::runtime::build_units(
        cfg(json!([{ "token": "a", "name": "Bad", "class": "nope", "port": 1 }])).units().unwrap(),
    )
    .err()
    .unwrap();
    assert!(err.contains("«Bad»") && err.contains("неизвестный класс"), "{err}");
}

#[tokio::test]
async fn runtime_bind_reports_every_busy_port_and_starts_nothing() {
    // Свой loopback-адрес: порты на 127.0.0.1 тем временем занимают параллельные тесты.
    const IP: &str = "127.0.0.37";
    let busy = TcpListener::bind((IP, 0)).await.unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let free = free_port().await;
    let units = host_units(json!([
        { "token": "a", "name": "Free", "class": "banner", "bind": IP, "port": free },
        { "token": "b", "name": "Busy", "class": "banner", "bind": IP, "port": busy_port }
    ]));
    let errors = match crate::plugin_tests::bind_all_settled(&units, 1).await {
        Ok(_) => panic!("занятый порт должен быть ошибкой"),
        Err(e) => e,
    };
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("«Busy»") && errors[0].contains(&format!(":{busy_port}/tcp")), "{errors:?}");
    // Свободный порт тоже отпущен: агент не держит ничего, раз не стартует.
    crate::plugin_tests::rebind_settled(IP, free).await.expect("порт свободной ловушки должен освободиться");
}

#[test]
fn runtime_buffer_files_are_per_trap() {
    use crate::runtime::buffer_path_for;
    use std::path::Path;
    let base = Path::new("/var/tmp/honeyforge-agent-buffer.dat");
    assert_eq!(buffer_path_for(base, "tok-a", false), base, "одна ловушка — прежний путь");
    let a = buffer_path_for(base, "tok-a", true);
    let b = buffer_path_for(base, "tok-b", true);
    assert_ne!(a, b);
    assert_eq!(a.parent(), base.parent());
    let name = a.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("honeyforge-agent-buffer-") && name.ends_with(".dat"), "{name}");
    assert_eq!(a, buffer_path_for(base, "tok-a", true), "путь стабилен между запусками");
    let no_ext = buffer_path_for(Path::new("/tmp/buf"), "tok-a", true);
    assert!(no_ext.to_str().unwrap().starts_with("/tmp/buf-"));
}
