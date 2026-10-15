//! Тесты класса plugin: разбор вывода программы и оба режима на настоящих скриптах.

use crate::config::{Config, TrapConfig};
use crate::event::Event;
use crate::sender::EventSink;
use crate::session::Session;
use crate::traps::plugin::{parse_event_line, read_line_limited, EventDefaults, PluginTrap, RateLimiter, Verdict, MAX_LINE};
use crate::traps::Trap;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

fn defaults() -> EventDefaults {
    EventDefaults {
        class: "plugin".into(),
        proto: "tcp".into(),
        src_ip: "10.0.0.1".into(),
        src_port: 4444,
        dst_port: 2222,
        session: "sess1".into(),
        salt: "salt".into(),
    }
}

fn drain(rx: &Receiver<Event>) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Ждёт, пока в канале появится событие, подходящее под условие.
async fn wait_event(rx: &Receiver<Event>, seen: &mut Vec<Event>, what: impl Fn(&Event) -> bool) -> Event {
    for _ in 0..100 {
        seen.extend(drain(rx));
        if let Some(e) = seen.iter().find(|e| what(e)) {
            return e.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("событие не пришло, были: {:?}", seen.iter().map(|e| &e.event_type).collect::<Vec<_>>());
}

/// Каталог плагина с исполняемым скриптом.
fn plugin_dir(name: &str, script: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-plugin-test-{}-{}", name, crate::util::session_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("run.sh");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn plugin_cfg(dir: &Path, mode: &str, port: u16, params: Value, command: Value) -> TrapConfig {
    serde_json::from_value(json!({
        "class": "plugin", "bind": "127.0.0.1", "port": port, "name": "test", "params": params,
        "plugin": { "slug": "demo", "dir": dir, "command": command, "mode": mode }
    }))
    .unwrap()
}

/// bind_all для тестов: параллельные тесты запускают процессы, и дочерний
/// процесс до exec держит копии сокетов родителя — только что отпущенный порт
/// может быть занят ещё миллисекунды. Повторяем, пока ошибок больше, чем ждём.
pub(crate) async fn bind_all_settled(
    units: &[crate::runtime::Unit],
    expected_errors: usize,
) -> Result<Vec<crate::runtime::Bound>, Vec<String>> {
    let mut attempt = 0;
    loop {
        let res = crate::runtime::bind_all(units).await;
        let extra = match &res {
            Ok(_) => false,
            Err(e) => e.len() > expected_errors,
        };
        if !extra || attempt == 40 {
            return res;
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Порт освободился: та же оговорка про fork, что у bind_all_settled.
pub(crate) async fn rebind_settled(ip: &str, port: u16) -> std::io::Result<TcpListener> {
    let mut attempt = 0;
    loop {
        match TcpListener::bind((ip, port)).await {
            Err(e) if attempt < 40 => {
                attempt += 1;
                let _ = e;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            other => return other,
        }
    }
}

pub(crate) fn free_port() -> u16 {
    // Порты вне диапазона временных (32768+): из него ОС раздаёт и bind(0), и
    // исходящие соединения параллельных тестов, и только что отпущенный порт
    // успевали занять. Здесь каждый порт выдаётся один раз за прогон.
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let _ = NEXT.compare_exchange(0, 20000 + (std::process::id() % 5000) as u16, Ordering::SeqCst, Ordering::SeqCst);
    loop {
        let port = NEXT.fetch_add(1, Ordering::SeqCst);
        if port >= 30000 {
            panic!("тестам не хватило портов 20000-29999");
        }
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
}

// ----------------------------- разбор строк -----------------------------

#[test]
fn event_line_full() {
    let ev = parse_event_line(
        br#"{"type":"auth","src_ip":"1.2.3.4","src_port":5555,"username":"root","password":"toor","data":{"method":"password"}}"#,
        &defaults(),
    )
    .unwrap();
    assert_eq!(ev.event_type, "auth");
    assert_eq!(ev.src_ip, "1.2.3.4");
    assert_eq!(ev.src_port, 5555);
    assert_eq!(ev.dst_port, 2222, "dst_port по умолчанию — порт ловушки");
    assert_eq!(ev.session, "sess1");
    assert_eq!(ev.username.as_deref(), Some("root"));
    assert_eq!(ev.password.as_deref(), Some("toor"));
    assert_eq!(ev.data["method"], "password");
    assert_eq!(ev.trap_class, "plugin");
}

#[test]
fn event_line_not_events() {
    let d = defaults();
    assert!(parse_event_line(b"Listening on 0.0.0.0:2222", &d).is_none());
    assert!(parse_event_line(br#"{"msg":"no type"}"#, &d).is_none());
    assert!(parse_event_line(br#"{"type":""}"#, &d).is_none());
    assert!(parse_event_line(br#"{"type":5}"#, &d).is_none());
    assert!(parse_event_line(br#"{"type":"auth""#, &d).is_none(), "битый JSON — просто строка журнала");
    assert!(parse_event_line(b"[1,2,3]", &d).is_none());
    assert!(parse_event_line(&[0xff, 0xfe, b'{'], &d).is_none());
}

#[test]
fn event_line_sanitizes() {
    let d = defaults();
    // неизвестный тип → data с исходным типом
    let ev = parse_event_line(br#"{"type":"Exploit","data":"x"}"#, &d).unwrap();
    assert_eq!(ev.event_type, "data");
    assert_eq!(ev.data["custom_type"], "exploit");
    assert_eq!(ev.data["value"], "x", "не-объект в data заворачивается");
    // payload — как у встроенной high_interaction
    let ev = parse_event_line(br#"{"type":"payload","data":{"payload_sha256":"ab"}}"#, &d).unwrap();
    assert_eq!(ev.event_type, "payload");
    // мусор вместо адреса и портов → значения по умолчанию
    let ev = parse_event_line(br#"{"type":"connect","src_ip":"evil; rm -rf","src_port":70000,"dst_port":-1}"#, &d).unwrap();
    assert_eq!(ev.src_ip, "10.0.0.1");
    assert_eq!(ev.src_port, 4444);
    assert_eq!(ev.dst_port, 2222);
    // IPv6 принимается
    let ev = parse_event_line(br#"{"type":"connect","src_ip":"2001:db8::1"}"#, &d).unwrap();
    assert_eq!(ev.src_ip, "2001:db8::1");
    // длинные логин и сессия обрезаются
    let long = "я".repeat(1000);
    let line = json!({"type":"auth","username": long, "session": long}).to_string();
    let ev = parse_event_line(line.as_bytes(), &d).unwrap();
    assert_eq!(ev.username.unwrap().chars().count(), 256);
    assert_eq!(ev.session.chars().count(), 64);
    // огромный data заменяется усечённым
    let line = json!({"type":"data","data":{"blob":"a".repeat(100_000)}}).to_string();
    let ev = parse_event_line(line.as_bytes(), &d).unwrap();
    assert_eq!(ev.data["truncated"], true);
    assert!(ev.data.to_string().len() < 2000);
    // proto: только tcp/udp
    let ev = parse_event_line(br#"{"type":"connect","proto":"udp"}"#, &d).unwrap();
    assert_eq!(ev.proto, "udp");
    let ev = parse_event_line(br#"{"type":"connect","proto":"icmp"}"#, &d).unwrap();
    assert_eq!(ev.proto, "tcp");
}

#[tokio::test]
async fn line_reader_limits_length() {
    let mut input = vec![b'x'; MAX_LINE * 3];
    input.extend_from_slice(b"\r\nsecond\nlast-no-newline");
    let mut r = BufReader::new(&input[..]);
    let first = read_line_limited(&mut r).await.unwrap();
    assert_eq!(first.len(), MAX_LINE);
    assert_eq!(read_line_limited(&mut r).await.unwrap(), b"second");
    assert_eq!(read_line_limited(&mut r).await.unwrap(), b"last-no-newline");
    assert!(read_line_limited(&mut r).await.is_none());
    // CRLF срезается
    let mut r = BufReader::new(&b"abc\r\n"[..]);
    assert_eq!(read_line_limited(&mut r).await.unwrap(), b"abc");
}

#[test]
fn rate_limiter_burst_then_reports_once() {
    let mut l = RateLimiter::new(1.0, 3.0);
    assert_eq!(l.take(), Verdict::Allow);
    assert_eq!(l.take(), Verdict::Allow);
    assert_eq!(l.take(), Verdict::Allow);
    assert_eq!(l.take(), Verdict::DropAndReport(1));
    assert_eq!(l.take(), Verdict::Drop, "второе сообщение — не раньше чем через минуту");
    assert_eq!(l.take(), Verdict::Drop);
}

// ----------------------------- сборка -----------------------------

#[test]
fn build_errors_are_clear() {
    let dir = plugin_dir("build", "#!/bin/sh\n");
    let err = |cfg: TrapConfig| match PluginTrap::new(&cfg) {
        Ok(_) => panic!("ожидалась ошибка"),
        Err(e) => e,
    };
    let e = err(plugin_cfg(Path::new("/nonexistent/hf"), "service", 1, json!({}), json!(["./run.sh"])));
    assert!(e.contains("нет каталога"), "{e}");
    let e = err(plugin_cfg(&dir, "service", 1, json!({}), json!(["./missing.sh"])));
    assert!(e.contains("нет файла"), "{e}");
    let e = err(plugin_cfg(&dir, "daemon", 1, json!({}), json!(["./run.sh"])));
    assert!(e.contains("режим"), "{e}");
    let e = err(plugin_cfg(&dir, "service", 1, json!({}), json!([])));
    assert!(e.contains("команда"), "{e}");
    let mut cfg = plugin_cfg(&dir, "stdio", 1, json!({}), json!(["./run.sh"]));
    cfg.plugin.as_mut().unwrap().transport = "udp".into();
    assert!(err(cfg).contains("stdio"));
    let mut cfg = plugin_cfg(&dir, "service", 1, json!({}), json!(["./run.sh"]));
    cfg.plugin = None;
    assert!(err(cfg).contains("plugin"));
    // команда из PATH не проверяется на месте
    assert!(PluginTrap::new(&plugin_cfg(&dir, "service", 1, json!({}), json!(["sh", "run.sh"]))).is_ok());
}

#[test]
fn relative_plugin_dir_is_resolved_from_config_dir() {
    let mut cfg: Config = serde_json::from_value(json!({
        "center_url": "http://127.0.0.1:1",
        "traps": [{ "token": "t1", "class": "plugin", "port": 1,
                    "plugin": { "slug": "x", "dir": "plugins/x-1", "command": ["./run"] } },
                  { "token": "t2", "class": "plugin", "port": 2,
                    "plugin": { "slug": "y", "dir": "/opt/y", "command": ["./run"] } }]
    }))
    .unwrap();
    cfg.base_dir = PathBuf::from("/etc/hf");
    let units = cfg.units().unwrap();
    assert_eq!(units[0].trap.plugin.as_ref().unwrap().dir, "/etc/hf/plugins/x-1");
    assert_eq!(units[1].trap.plugin.as_ref().unwrap().dir, "/opt/y");
    assert_eq!(units[0].trap.plugin.as_ref().unwrap().mode, "service", "режим по умолчанию");
}

// ----------------------------- режим stdio -----------------------------

/// Поднимает stdio-плагин на порту и обслуживает одно соединение.
async fn serve_one(trap: Arc<Trap>, sink: EventSink) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut s = Session::new(stream, addr.port(), sink, "plugin", "srv01".into(), 3.0);
        trap.handle(&mut s).await;
    });
    (addr, h)
}

#[tokio::test]
async fn stdio_talks_to_client_and_reports_events() {
    let dir = plugin_dir(
        "stdio",
        r#"#!/bin/sh
printf 'hello %s from %s\n' "$HF_SRC_IP" "$(basename "$PWD")"
read line
printf '{"type":"command","data":{"line":"%s","greeting":%s}}\n' "$line" "$HF_PARAMS" >&2
echo "plain log line" >&2
echo "you said: $line"
"#,
    );
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 2222, json!({"greeting": "hi"}), json!(["./run.sh"]))).unwrap());
    let (sink, rx) = EventSink::test_sink();
    let (addr, server) = serve_one(trap, sink).await;

    let mut client = BufReader::new(TcpStream::connect(addr).await.unwrap());
    let mut line = String::new();
    client.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("hello 127.0.0.1 from hf-plugin-test-stdio"), "{line}");
    client.get_mut().write_all(b"uname -a\n").await.unwrap();
    let mut rest = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut rest)).await.unwrap().unwrap();
    assert_eq!(rest, "you said: uname -a\n");
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();

    let evs = drain(&rx);
    let cmd = evs.iter().find(|e| e.event_type == "command").expect("событие программы");
    assert_eq!(cmd.data["line"], "uname -a");
    assert_eq!(cmd.data["greeting"]["greeting"], "hi", "HF_PARAMS дошёл до программы");
    assert_eq!(cmd.src_ip, "127.0.0.1", "адрес клиента подставлен агентом");
    assert_eq!(cmd.dst_port, addr.port());
    assert!(!cmd.session.is_empty());
    let data = evs.iter().find(|e| e.event_type == "data").expect("начало ввода клиента");
    assert_eq!(data.data["text"], "uname -a\n");
    assert_eq!(data.session, cmd.session, "одна сессия");
    assert!(!evs.iter().any(|e| e.data.to_string().contains("plain log line")), "журнал не становится событием");
}

#[tokio::test]
async fn python_deps_from_center_are_on_pythonpath() {
    let dir = plugin_dir("pydeps", "#!/bin/sh\nexec python3 -c 'import hfdep; print(hfdep.X)'\n");
    let deps = dir.join(crate::traps::plugin::PYDEPS_DIR);
    std::fs::create_dir_all(&deps).unwrap();
    std::fs::write(deps.join("hfdep.py"), "X = 'from .hf-pydeps'\n").unwrap();
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 2222, json!({}), json!(["./run.sh"]))).unwrap());
    let (sink, _rx) = EventSink::test_sink();
    let (addr, server) = serve_one(trap, sink).await;
    let mut out = String::new();
    let mut client = TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_string(&mut out)).await.unwrap().unwrap();
    assert_eq!(out, "from .hf-pydeps\n");
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
}

#[tokio::test]
async fn stdio_program_that_ignores_client_is_cut_after_idle() {
    let dir = plugin_dir("idle", "#!/bin/sh\nsleep 30\n");
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 1, json!({}), json!(["./run.sh"]))).unwrap());
    let (sink, _rx) = EventSink::test_sink();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut s = Session::new(stream, addr.port(), sink, "plugin", "srv01".into(), 0.5);
        trap.handle(&mut s).await;
    });
    let _client = TcpStream::connect(addr).await.unwrap();
    // idle 0.5 с + 2 с на дописывание ответа; программа спит 30 с — её надо убить
    tokio::time::timeout(Duration::from_secs(5), server).await.expect("сессия не закрылась").unwrap();
}

#[tokio::test]
async fn stdio_client_disconnect_kills_program() {
    let marker = std::env::temp_dir().join(format!("hf-plugin-killed-{}", crate::util::session_id()));
    let dir = plugin_dir(
        "kill",
        &format!("#!/bin/sh\ncat > /dev/null\nsleep 5\ntouch {}\n", marker.display()),
    );
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 1, json!({}), json!(["./run.sh"]))).unwrap());
    let (sink, _rx) = EventSink::test_sink();
    let (addr, server) = serve_one(trap, sink).await;
    let client = TcpStream::connect(addr).await.unwrap();
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(!marker.exists(), "программа должна быть убита вместе с сессией");
}

#[tokio::test]
async fn stdio_spawn_failure_is_an_error_event() {
    let dir = plugin_dir("noexec", "#!/bin/sh\n");
    std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 1, json!({}), json!(["./run.sh"]))).unwrap());
    let (sink, rx) = EventSink::test_sink();
    let (addr, server) = serve_one(trap, sink).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut buf)).await;
    tokio::time::timeout(Duration::from_secs(3), server).await.unwrap().unwrap();
    let evs = drain(&rx);
    let err = evs.iter().find(|e| e.event_type == "error").expect("ошибка запуска");
    assert_eq!(err.data["reason"], "plugin start failed");
}

// ----------------------------- режим service -----------------------------

fn service_trap(dir: &Path, port: u16, params: Value, command: Value) -> Arc<PluginTrap> {
    match Trap::build(&plugin_cfg(dir, "service", port, params, command)).unwrap() {
        Trap::Plugin(p) => p,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn service_runs_real_server_and_forwards_events() {
    // Небольшой сервер на Python: слушает HF_PORT, на каждое подключение пишет событие в stdout.
    let dir = plugin_dir("svc", "");
    std::fs::write(
        dir.join("server.py"),
        r#"
import json, os, socket, sys
params = json.loads(os.environ["HF_PARAMS"])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((os.environ["HF_BIND"], int(os.environ["HF_PORT"]))); s.listen()
print("listening", file=sys.stderr)
while True:
    c, (ip, port) = s.accept()
    c.sendall(params["banner"].encode() + b"\n")
    user = c.recv(100).decode().strip()
    print(json.dumps({"type": "auth", "src_ip": ip, "src_port": port, "username": user, "password": "x",
                      "data": {"data_dir_ok": os.access(os.environ["HF_DATA_DIR"], os.W_OK)}}))
    c.close()
"#,
    )
    .unwrap();
    let port = free_port();
    let trap = service_trap(&dir, port, json!({"banner": "220 hi"}), json!(["python3", "server.py"]));
    let (sink, rx) = EventSink::test_sink();
    let (tx, ready) = tokio::sync::oneshot::channel();
    let sup = tokio::spawn(trap.run_service(sink, tx));
    assert_eq!(ready.await.unwrap(), Ok(()));

    let mut c = BufReader::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    let mut banner = String::new();
    c.read_line(&mut banner).await.unwrap();
    assert_eq!(banner, "220 hi\n");
    c.get_mut().write_all(b"admin\n").await.unwrap();

    let mut seen = Vec::new();
    let ev = wait_event(&rx, &mut seen, |e| e.event_type == "auth").await;
    assert_eq!(ev.username.as_deref(), Some("admin"));
    assert_eq!(ev.src_ip, "127.0.0.1");
    assert_eq!(ev.dst_port, port);
    assert_eq!(ev.data["data_dir_ok"], true, "программе есть куда писать");
    sup.abort();
    // программа убивается вместе с надзирателем — порт освобождается
    let mut freed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            freed = true;
            break;
        }
    }
    assert!(freed, "после остановки агента программа должна умереть");
}

#[tokio::test]
async fn service_that_dies_at_start_fails_with_its_log() {
    let dir = plugin_dir("dies", "#!/bin/sh\necho 'ModuleNotFoundError: No module named flask' >&2\nexit 3\n");
    let trap = service_trap(&dir, free_port(), json!({}), json!(["./run.sh"]));
    let (sink, _rx) = EventSink::test_sink();
    let (tx, ready) = tokio::sync::oneshot::channel();
    let sup = tokio::spawn(trap.run_service(sink, tx));
    let err = ready.await.unwrap().unwrap_err();
    assert!(err.contains("код 3"), "{err}");
    assert!(err.contains("No module named flask"), "{err}");
    tokio::time::timeout(Duration::from_secs(2), sup).await.expect("надзиратель должен выйти").unwrap();
}

#[tokio::test]
async fn service_missing_program_fails_start() {
    let dir = plugin_dir("missing", "");
    let trap = service_trap(&dir, free_port(), json!({}), json!(["no-such-binary-hf"]));
    let (sink, _rx) = EventSink::test_sink();
    let (tx, ready) = tokio::sync::oneshot::channel();
    tokio::spawn(trap.run_service(sink, tx));
    let err = ready.await.unwrap().unwrap_err();
    assert!(err.contains("не удалось запустить"), "{err}");
}

#[tokio::test]
async fn service_crash_after_start_is_reported_and_restarted() {
    let counter = std::env::temp_dir().join(format!("hf-plugin-runs-{}", crate::util::session_id()));
    let dir = plugin_dir(
        "crash",
        &format!("#!/bin/sh\necho run >> {}\necho 'about to crash' >&2\nsleep 2.5\nexit 7\n", counter.display()),
    );
    let trap = service_trap(&dir, free_port(), json!({}), json!(["./run.sh"]));
    let (sink, rx) = EventSink::test_sink();
    let (tx, ready) = tokio::sync::oneshot::channel();
    let sup = tokio::spawn(trap.run_service(sink, tx));
    assert_eq!(ready.await.unwrap(), Ok(()));
    let mut seen = Vec::new();
    let ev = wait_event(&rx, &mut seen, |e| e.event_type == "error").await;
    assert_eq!(ev.data["reason"], "plugin exited");
    assert_eq!(ev.data["exit"], "код 7");
    assert!(ev.data["log"].as_str().unwrap().contains("about to crash"));
    // через секунду после падения — второй запуск
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let runs = std::fs::read_to_string(&counter).unwrap_or_default();
    assert_eq!(runs.lines().count(), 2, "программа должна быть перезапущена");
    sup.abort();
}

#[tokio::test]
async fn start_plugins_frees_port_and_fails_whole_agent_on_bad_plugin() {
    use crate::runtime::{build_units, start_plugins};
    let good = plugin_dir("good", "#!/bin/sh\nexec sleep 30\n");
    let bad = plugin_dir("bad", "#!/bin/sh\necho 'bad config' >&2\nexit 1\n");
    let cfg: Config = serde_json::from_value(json!({
        "center_url": "http://127.0.0.1:1",
        "traps": [
            { "token": "a", "class": "plugin", "bind": "127.0.0.1", "port": free_port(), "name": "good",
              "plugin": { "slug": "good", "dir": good, "command": ["./run.sh"] } },
            { "token": "b", "class": "plugin", "bind": "127.0.0.1", "port": free_port(), "name": "bad",
              "plugin": { "slug": "bad", "dir": bad, "command": ["./run.sh"] } }
        ]
    }))
    .unwrap();
    let units = build_units(cfg.units().unwrap()).unwrap();
    let bound = bind_all_settled(&units, 0).await.unwrap();
    let sinks: Vec<EventSink> = units.iter().map(|_| EventSink::test_sink().0).collect();
    let errors = match start_plugins(&units, bound, &sinks).await {
        Ok(_) => panic!("плохой плагин должен остановить запуск"),
        Err(e) => e,
    };
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("«bad»") && errors[0].contains("bad config"), "{errors:?}");

    // порт service-плагина занимает программа, а не агент
    let port = free_port();
    let cfg: Config = serde_json::from_value(json!({
        "center_url": "http://127.0.0.1:1",
        "traps": [{ "token": "a", "class": "plugin", "bind": "127.0.0.1", "port": port,
                    "plugin": { "slug": "py", "dir": good, "command": ["python3", "-c",
                    "import os,socket,time; s=socket.socket(); s.bind(('127.0.0.1', int(os.environ['HF_PORT']))); s.listen(); time.sleep(30)"] } }]
    }))
    .unwrap();
    let units = build_units(cfg.units().unwrap()).unwrap();
    let bound = bind_all_settled(&units, 0).await.unwrap();
    let sinks: Vec<EventSink> = units.iter().map(|_| EventSink::test_sink().0).collect();
    let (rest, handles) = start_plugins(&units, bound, &sinks).await.expect("программа должна занять свой порт");
    assert!(rest.is_empty());
    assert_eq!(handles.len(), 1);
    for h in handles {
        h.abort();
    }
}

#[tokio::test]
async fn busy_port_is_caught_before_plugin_starts() {
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let dir = plugin_dir("busy", "#!/bin/sh\nexec sleep 30\n");
    let cfg: Config = serde_json::from_value(json!({
        "center_url": "http://127.0.0.1:1",
        "traps": [{ "token": "a", "class": "plugin", "bind": "127.0.0.1", "port": port,
                    "plugin": { "slug": "x", "dir": dir, "command": ["./run.sh"] } }]
    }))
    .unwrap();
    let units = crate::runtime::build_units(cfg.units().unwrap()).unwrap();
    let errors = match crate::runtime::bind_all(&units).await {
        Ok(_) => panic!("порт занят"),
        Err(e) => e,
    };
    assert!(errors[0].contains(&port.to_string()));
}

fn alive(pid: i32) -> bool {
    // SAFETY: сигнал 0 только проверяет, что процесс существует.
    unsafe { libc::kill(pid, 0) == 0 }
}

async fn read_pid(path: &Path) -> i32 {
    for _ in 0..60 {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(p) = s.trim().parse() {
                return p;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("программа не записала pid");
}

#[tokio::test]
async fn stdio_session_end_kills_background_children() {
    let pidfile = std::env::temp_dir().join(format!("hf-plugin-pid-{}", crate::util::session_id()));
    let dir = plugin_dir("bg", &format!("#!/bin/sh\nsleep 300 &\necho $! > {}\ncat > /dev/null\nwait\n", pidfile.display()));
    let trap = Arc::new(Trap::build(&plugin_cfg(&dir, "stdio", 1, json!({}), json!(["./run.sh"]))).unwrap());
    let (sink, _rx) = EventSink::test_sink();
    let (addr, server) = serve_one(trap, sink).await;
    let client = TcpStream::connect(addr).await.unwrap();
    let pid = read_pid(&pidfile).await;
    assert!(alive(pid));
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!alive(pid), "фоновый потомок программы должен умереть вместе с сессией");
}

#[tokio::test]
async fn service_stop_kills_wrapped_server() {
    // Обёртка sh запускает «сервер» и ждёт его — типичный run.sh.
    let pidfile = std::env::temp_dir().join(format!("hf-plugin-pid-{}", crate::util::session_id()));
    let dir = plugin_dir("wrap", &format!("#!/bin/sh\nsleep 300 &\necho $! > {}\nwait\n", pidfile.display()));
    let trap = service_trap(&dir, free_port(), json!({}), json!(["./run.sh"]));
    let (sink, _rx) = EventSink::test_sink();
    let (tx, ready) = tokio::sync::oneshot::channel();
    let sup = tokio::spawn(trap.run_service(sink, tx));
    assert_eq!(ready.await.unwrap(), Ok(()));
    let pid = read_pid(&pidfile).await;
    assert!(alive(pid));
    sup.abort();
    let _ = sup.await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!alive(pid), "остановка агента должна убить и потомков программы");
}

#[test]
fn service_events_of_one_connection_share_a_session() {
    let d = EventDefaults { session: String::new(), src_ip: String::new(), src_port: 0, ..defaults() };
    let a = parse_event_line(br#"{"type":"connect","src_ip":"1.2.3.4","src_port":5000}"#, &d).unwrap();
    let b = parse_event_line(br#"{"type":"auth","src_ip":"1.2.3.4","src_port":5000}"#, &d).unwrap();
    let c = parse_event_line(br#"{"type":"auth","src_ip":"1.2.3.4","src_port":5001}"#, &d).unwrap();
    assert_eq!(a.session.len(), 12);
    assert_eq!(a.session, b.session, "одно соединение — одна сессия");
    assert_ne!(a.session, c.session, "другое соединение — другая сессия");
    let named = parse_event_line(br#"{"type":"auth","src_ip":"1.2.3.4","src_port":5000,"session":"mine"}"#, &d).unwrap();
    assert_eq!(named.session, "mine", "сессия программы важнее");
    let anon = parse_event_line(br#"{"type":"scan"}"#, &d).unwrap();
    assert_eq!(anon.session, "", "без адреса сессию не выдумываем");
    let other_run = EventDefaults { salt: "other".into(), ..d.clone() };
    let a2 = parse_event_line(br#"{"type":"connect","src_ip":"1.2.3.4","src_port":5000}"#, &other_run).unwrap();
    assert_ne!(a.session, a2.session, "после перезапуска агента тот же порт — новая сессия");
}
