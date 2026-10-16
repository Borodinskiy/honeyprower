//! Класс "plugin": проект пользователя, загруженный в центр.
//!
//! Агент запускает чужую программу и превращает её вывод в события:
//! строка-JSON с полем "type" — событие, любая другая строка — запись в журнал.
//!
//! Режимы:
//! * service — программа сама слушает порт (HF_BIND/HF_PORT). Агент держит её
//!   запущенной и перезапускает при падении; события читает из stdout и stderr.
//! * stdio — порт слушает агент и на каждое соединение запускает программу:
//!   stdin/stdout — это клиент, события — из stderr. Подключение, отключение и
//!   начало ввода клиента агент записывает сам.
//!
//! Переменные окружения программы: HF_MODE, HF_BIND, HF_PORT, HF_PARAMS (JSON
//! параметров ловушки), HF_TRAP_NAME, HF_PLUGIN_DIR, HF_DATA_DIR (каталог для
//! записи), а в режиме stdio ещё HF_SRC_IP, HF_SRC_PORT, HF_DST_PORT, HF_SESSION.

use crate::config::{PluginSpec, TrapConfig};
use crate::event::{event_type, Event};
use crate::sender::EventSink;
use crate::session::Session;
use crate::util;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

/// Длиннее строка вывода — обрезается (защита памяти агента от болтливой программы).
pub const MAX_LINE: usize = 64 * 1024;
/// Сколько программа в режиме service должна проработать, чтобы старт считался удачным.
pub const STARTUP_GRACE: Duration = Duration::from_secs(2);
/// Поле data события больше этого заменяется на усечённое.
const MAX_DATA: usize = 16 * 1024;
/// Сколько последних строк журнала программы хранить для сообщения о падении.
const TAIL_LINES: usize = 20;

/// Каталог Python-зависимостей внутри каталога плагина (кладёт центр при деплое).
pub const PYDEPS_DIR: &str = ".hf-pydeps";

const EVENT_TYPES: [&str; 11] = [
    event_type::CONNECT,
    event_type::DISCONNECT,
    event_type::DATA,
    event_type::AUTH,
    event_type::COMMAND,
    event_type::REQUEST,
    event_type::HANDSHAKE,
    event_type::SCAN,
    event_type::TOKEN,
    event_type::ERROR,
    event_type::PAYLOAD,
];

pub struct PluginTrap {
    pub spec: PluginSpec,
    program: PathBuf,
    class: String,
    params_json: String,
    trap_name: String,
    bind: String,
    port: u16,
    data_dir: PathBuf,
    limiter: Arc<Mutex<RateLimiter>>,
    /// Соль для сессий, которые агент выводит сам (своя на каждый запуск агента).
    salt: String,
}

impl PluginTrap {
    pub fn new(cfg: &TrapConfig) -> Result<PluginTrap, String> {
        let spec = cfg.plugin.clone().ok_or("для класса plugin нужен блок plugin")?;
        if spec.mode != "service" && spec.mode != "stdio" {
            return Err(format!("плагин {}: неизвестный режим {:?} (service или stdio)", spec.slug, spec.mode));
        }
        if spec.transport != "tcp" && spec.transport != "udp" {
            return Err(format!("плагин {}: транспорт должен быть tcp или udp", spec.slug));
        }
        if spec.mode == "stdio" && spec.transport != "tcp" {
            return Err(format!("плагин {}: режим stdio работает только по tcp", spec.slug));
        }
        let first = spec.command.first().filter(|c| !c.trim().is_empty());
        let first = first.ok_or_else(|| format!("плагин {}: не задана команда запуска", spec.slug))?;
        let dir = Path::new(&spec.dir);
        if !dir.is_dir() {
            return Err(format!("плагин {}: нет каталога {}", spec.slug, spec.dir));
        }
        let program = resolve_program(dir, first);
        if first.contains('/') && !program.is_file() {
            return Err(format!("плагин {}: нет файла {}", spec.slug, program.display()));
        }
        let params_json = if cfg.params.is_null() { "{}".to_string() } else { cfg.params.to_string() };
        Ok(PluginTrap {
            data_dir: data_dir(&spec.slug),
            program,
            class: cfg.class.clone(),
            params_json,
            trap_name: cfg.name.clone(),
            bind: cfg.bind.clone(),
            port: cfg.port,
            limiter: Arc::new(Mutex::new(RateLimiter::new(100.0, 200.0))),
            salt: util::session_id(),
            spec,
        })
    }

    pub fn is_service(&self) -> bool {
        self.spec.mode == "service"
    }

    pub fn transport(&self) -> &'static str {
        if self.spec.transport == "udp" {
            "udp"
        } else {
            "tcp"
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.spec.command[1..])
            .current_dir(&self.spec.dir)
            .env("HF_MODE", &self.spec.mode)
            .env("HF_BIND", &self.bind)
            .env("HF_PORT", self.port.to_string())
            .env("HF_PARAMS", &self.params_json)
            .env("HF_TRAP_NAME", &self.trap_name)
            .env("HF_PLUGIN_DIR", &self.spec.dir)
            .env("HF_DATA_DIR", &self.data_dir)
            .env("HOME", &self.data_dir)
            // Python буферизует stdout в канал — события приходили бы пачками с опозданием.
            .env("PYTHONUNBUFFERED", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Своя группа процессов: при остановке убиваем и потомков (обёртка sh → python).
            .process_group(0)
            .kill_on_drop(true);
        // Python-зависимости, которые центр привёз под платформу хоста (manifest.pip).
        let deps = Path::new(&self.spec.dir).join(PYDEPS_DIR);
        if deps.is_dir() {
            let mut path = deps.into_os_string();
            if let Some(old) = std::env::var_os("PYTHONPATH").filter(|v| !v.is_empty()) {
                path.push(":");
                path.push(old);
            }
            cmd.env("PYTHONPATH", path);
        }
        cmd
    }

    fn label(&self) -> String {
        format!("плагин {}", self.spec.slug)
    }

    fn defaults(&self) -> EventDefaults {
        EventDefaults {
            class: self.class.clone(),
            proto: self.transport().to_string(),
            src_ip: String::new(),
            src_port: 0,
            dst_port: self.port,
            session: String::new(),
            salt: self.salt.clone(),
        }
    }

    /// Режим service: держит программу запущенной. В `ready` сообщает, пережила ли
    /// программа первые STARTUP_GRACE (если нет — с её последними строками журнала,
    /// и тогда возвращается: агент не стартует, деплой покажет причину).
    pub async fn run_service(self: Arc<Self>, sink: EventSink, ready: oneshot::Sender<Result<(), String>>) {
        let mut ready = Some(ready);
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            let tail = Arc::new(Mutex::new(VecDeque::new()));
            let mut child = match spawn_retrying(&mut self.command()).await {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("{}: не удалось запустить {}: {e}", self.label(), self.program.display());
                    if let Some(r) = ready.take() {
                        let _ = r.send(Err(msg));
                        return;
                    }
                    eprintln!("{msg}");
                    sink.emit(self.error_event("plugin start failed", json!({ "error": e.to_string() })));
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            };
            let _group = GroupKill::of(&child);
            let pumps = [
                child.stdout.take().map(|o| self.pump(o, sink.clone(), self.defaults(), tail.clone())),
                child.stderr.take().map(|e| self.pump(e, sink.clone(), self.defaults(), tail.clone())),
            ];

            let status = match ready.take() {
                Some(r) => match timeout(STARTUP_GRACE, child.wait()).await {
                    Ok(status) => {
                        for p in pumps.into_iter().flatten() {
                            let _ = timeout(Duration::from_secs(1), p).await;
                        }
                        let _ = r.send(Err(format!(
                            "{} завершился сразу после запуска ({}){}",
                            self.label(),
                            exit_text(&status),
                            tail_text(&tail, "\n")
                        )));
                        return;
                    }
                    Err(_) => {
                        let _ = r.send(Ok(()));
                        child.wait().await
                    }
                },
                None => child.wait().await,
            };
            for p in pumps.into_iter().flatten() {
                let _ = timeout(Duration::from_secs(1), p).await;
            }
            eprintln!(
                "{} завершился ({}), перезапуск через {} с{}",
                self.label(),
                exit_text(&status),
                backoff.as_secs(),
                tail_text(&tail, "\n")
            );
            sink.emit(self.error_event(
                "plugin exited",
                json!({ "exit": exit_text(&status), "log": tail_text(&tail, "\n").trim() }),
            ));
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    fn error_event(&self, reason: &str, extra: Value) -> Event {
        let mut data = Map::new();
        data.insert("reason".into(), json!(reason));
        data.insert("plugin".into(), json!(self.spec.slug));
        if let Value::Object(m) = extra {
            data.extend(m);
        }
        Event::new(&self.class, event_type::ERROR)
            .proto(self.transport())
            .peer("", 0, self.port)
            .data(Value::Object(data))
    }

    /// Читает поток программы построчно: события — в sink, остальное — в журнал агента.
    fn pump<R>(&self, r: R, sink: EventSink, d: EventDefaults, tail: Arc<Mutex<VecDeque<String>>>) -> tokio::task::JoinHandle<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let limiter = self.limiter.clone();
        let label = self.label();
        let class = self.class.clone();
        let port = self.port;
        tokio::spawn(async move {
            let mut r = BufReader::new(r);
            while let Some(line) = read_line_limited(&mut r).await {
                match parse_event_line(&line, &d) {
                    Some(ev) => {
                        let verdict = limiter.lock().map(|mut l| l.take()).unwrap_or(Verdict::Allow);
                        match verdict {
                            Verdict::Allow => sink.emit(ev),
                            Verdict::Drop => {}
                            Verdict::DropAndReport(n) => {
                                eprintln!("{label}: слишком много событий, отброшено {n}");
                                sink.emit(
                                    Event::new(&class, event_type::ERROR)
                                        .peer("", 0, port)
                                        .data(json!({ "reason": "plugin event rate limit", "dropped": n })),
                                );
                            }
                        }
                    }
                    None => {
                        let text = util::safe_text(&line, 2000);
                        let text = text.trim_end();
                        if text.is_empty() {
                            continue;
                        }
                        eprintln!("[{label}] {text}");
                        if let Ok(mut t) = tail.lock() {
                            if t.len() == TAIL_LINES {
                                t.pop_front();
                            }
                            t.push_back(text.to_string());
                        }
                    }
                }
            }
        })
    }

    /// Режим stdio: одно соединение — один запуск программы.
    pub async fn handle(&self, s: &mut Session) {
        let mut cmd = self.command();
        cmd.stdin(Stdio::piped())
            .env("HF_SRC_IP", &s.src_ip)
            .env("HF_SRC_PORT", s.src_port.to_string())
            .env("HF_DST_PORT", s.dst_port.to_string())
            .env("HF_SESSION", &s.id);
        let mut child = match spawn_retrying(&mut cmd).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{}: не удалось запустить {}: {e}", self.label(), self.program.display());
                s.emit_data(
                    event_type::ERROR,
                    json!({ "reason": "plugin start failed", "plugin": self.spec.slug, "error": e.to_string() }),
                );
                return;
            }
        };
        let group = GroupKill::of(&child);
        let mut stdin = child.stdin.take();
        let Some(mut stdout) = child.stdout.take() else { return };
        let d = EventDefaults {
            src_ip: s.src_ip.clone(),
            src_port: s.src_port,
            dst_port: s.dst_port,
            session: s.id.clone(),
            ..self.defaults()
        };
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let pump = child.stderr.take().map(|e| self.pump(e, s.sink(), d, tail));

        let mut preview: Vec<u8> = Vec::new();
        let mut out = vec![0u8; 16 * 1024];
        let mut client_open = true;
        // Клиент ушёл — даём программе дописать ответ, но не ждём её вечно.
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(86400);
        loop {
            tokio::select! {
                r = s.read(16 * 1024, None), if client_open => match r {
                    Ok(data) if !data.is_empty() => {
                        if preview.len() < 1024 {
                            preview.extend_from_slice(&data[..data.len().min(1024 - preview.len())]);
                        }
                        if let Some(w) = stdin.as_mut() {
                            if w.write_all(&data).await.is_err() || w.flush().await.is_err() {
                                stdin = None;
                            }
                        }
                    }
                    _ => {
                        client_open = false;
                        stdin = None; // EOF для программы
                        deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                    }
                },
                r = stdout.read(&mut out) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client_open && s.send(&out[..n]).await.is_err() {
                            client_open = false;
                            stdin = None;
                            deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                        }
                    }
                },
                _ = tokio::time::sleep_until(deadline), if !client_open => break,
            }
        }
        drop(stdin);
        drop(group);
        let _ = child.start_kill();
        let _ = timeout(Duration::from_secs(1), child.wait()).await;
        if let Some(p) = pump {
            let _ = timeout(Duration::from_secs(1), p).await;
        }
        if !preview.is_empty() {
            s.emit_data(
                event_type::DATA,
                json!({ "source": "client", "text": util::safe_text(&preview, 1024), "bytes_in": s.bytes_in }),
            );
        }
    }
}

/// Убивает группу процессов программы при выходе из области видимости: и при
/// обычном завершении (остатки вроде фоновых потомков), и при отмене задачи.
struct GroupKill(Option<i32>);

impl GroupKill {
    fn of(child: &tokio::process::Child) -> GroupKill {
        GroupKill(child.id().map(|p| p as i32))
    }
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        if let Some(pgid) = self.0.filter(|p| *p > 1) {
            // SAFETY: kill(2) с отрицательным pid — сигнал группе, которую создали мы сами.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
}

/// Команда с "/" — путь внутри каталога плагина (или абсолютный), без — ищется в PATH.
/// Запуск с повтором при ETXTBSY: если в момент запуска другой поток агента
/// порождал процесс, тот мог ненадолго унаследовать открытый на запись
/// дескриптор файла программы, и exec отказывает «Text file busy».
async fn spawn_retrying(cmd: &mut Command) -> std::io::Result<tokio::process::Child> {
    let mut attempt = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 5 => {
                attempt += 1;
                sleep(Duration::from_millis(20 * attempt)).await;
            }
            other => return other,
        }
    }
}

fn resolve_program(dir: &Path, first: &str) -> PathBuf {
    let p = Path::new(first);
    if p.is_absolute() || !first.contains('/') {
        p.to_path_buf()
    } else {
        dir.join(p)
    }
}

/// Каталог, куда программе можно писать: $HF_PLUGIN_DATA/<slug>
/// (по умолчанию /var/lib/honeyforge/plugin-data), иначе — во временном каталоге.
fn data_dir(slug: &str) -> PathBuf {
    let base = std::env::var("HF_PLUGIN_DATA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/honeyforge/plugin-data"));
    let dir = base.join(slug);
    if std::fs::create_dir_all(&dir).is_ok() {
        return dir;
    }
    let fallback = std::env::temp_dir().join("honeyforge-plugin-data").join(slug);
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

fn exit_text(status: &std::io::Result<std::process::ExitStatus>) -> String {
    match status {
        Ok(s) => match s.code() {
            Some(c) => format!("код {c}"),
            None => format!("{s}"),
        },
        Err(e) => e.to_string(),
    }
}

fn tail_text(tail: &Arc<Mutex<VecDeque<String>>>, sep: &str) -> String {
    let t = tail.lock().map(|t| t.iter().cloned().collect::<Vec<_>>()).unwrap_or_default();
    if t.is_empty() {
        String::new()
    } else {
        format!("{sep}{}", t.join(sep))
    }
}

/// Читает строку до '\n'. Слишком длинная обрезается до MAX_LINE, хвост до конца строки
/// выбрасывается. None — поток закончился.
pub async fn read_line_limited<R: AsyncBufRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut got_any = false;
    loop {
        let buf = match r.fill_buf().await {
            Ok(b) => b,
            Err(_) => return got_any.then_some(line),
        };
        if buf.is_empty() {
            return got_any.then_some(line);
        }
        got_any = true;
        let (chunk, used, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..i], i + 1, true),
            None => (buf, buf.len(), false),
        };
        let room = MAX_LINE.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        r.consume(used);
        if done {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Some(line);
        }
    }
}

/// Поля события, которые программа может не указывать.
#[derive(Clone)]
pub struct EventDefaults {
    pub class: String,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub session: String,
    /// Если программа не назвала сессию, она выводится из адреса и порта клиента
    /// с этой солью: события одного соединения получают одну сессию.
    pub salt: String,
}

/// Строка вывода → событие, если это JSON-объект с полем "type". Неизвестный тип
/// становится "data" с исходным в data.custom_type: набор типов в центре закрыт.
pub fn parse_event_line(line: &[u8], d: &EventDefaults) -> Option<Event> {
    let text = std::str::from_utf8(line).ok()?.trim();
    if !text.starts_with('{') {
        return None;
    }
    let obj: Map<String, Value> = serde_json::from_str(text).ok()?;
    let raw_type = obj.get("type")?.as_str()?.trim().to_ascii_lowercase();
    if raw_type.is_empty() {
        return None;
    }

    let mut data = match obj.get("data") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(other) => {
            let mut m = Map::new();
            m.insert("value".into(), other.clone());
            m
        }
    };
    let event_type = if EVENT_TYPES.contains(&raw_type.as_str()) {
        raw_type
    } else {
        data.insert("custom_type".into(), json!(clip(&raw_type, 64)));
        event_type::DATA.to_string()
    };
    let mut data = Value::Object(data);
    let size = data.to_string().len();
    if size > MAX_DATA {
        data = json!({ "truncated": true, "bytes": size, "preview": clip(&data.to_string(), 1024) });
    }

    let src_ip = obj
        .get("src_ip")
        .and_then(Value::as_str)
        .filter(|s| s.trim().parse::<IpAddr>().is_ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| d.src_ip.clone());
    let port = |key: &str, def: u16| -> u16 {
        obj.get(key)
            .and_then(Value::as_u64)
            .filter(|p| *p <= 65535)
            .map(|p| p as u16)
            .unwrap_or(def)
    };
    let text_field = |key: &str, limit: usize| -> Option<String> {
        obj.get(key).and_then(Value::as_str).map(|s| clip(s, limit))
    };
    let src_port = port("src_port", d.src_port);
    let session = text_field("session", 64)
        .filter(|s| !s.is_empty())
        .or_else(|| (!d.session.is_empty()).then(|| d.session.clone()))
        .or_else(|| (!src_ip.is_empty() && src_port != 0).then(|| derived_session(&d.salt, &src_ip, src_port)))
        .unwrap_or_default();
    let proto = match obj.get("proto").and_then(Value::as_str) {
        Some("tcp") => "tcp",
        Some("udp") => "udp",
        _ => d.proto.as_str(),
    };

    Some(
        Event::new(&d.class, &event_type)
            .proto(proto)
            .peer(&src_ip, src_port, port("dst_port", d.dst_port))
            .session(&session)
            .username(text_field("username", 256))
            .password(text_field("password", 256))
            .data(data),
    )
}

/// Сессия соединения по адресу клиента: 12 hex-символов, как у сессий агента.
fn derived_session(salt: &str, ip: &str, port: u16) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (salt, ip, port).hash(&mut h);
    format!("{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// Первые `limit` символов (по границе символа).
fn clip(s: &str, limit: usize) -> String {
    s.chars().take(limit).collect()
}

/// Токен-бакет на события плагина: болтливая программа не забьёт канал в центр.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
    dropped: u64,
    last_report: Option<Instant>,
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Allow,
    Drop,
    /// Отбросить и сообщить, сколько отброшено с прошлого сообщения.
    DropAndReport(u64),
}

impl RateLimiter {
    pub fn new(rate: f64, burst: f64) -> RateLimiter {
        RateLimiter { rate, burst, tokens: burst, last: Instant::now(), dropped: 0, last_report: None }
    }

    pub fn take(&mut self) -> Verdict {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Verdict::Allow;
        }
        self.dropped += 1;
        let due = self.last_report.map_or(true, |t| now.duration_since(t) >= Duration::from_secs(60));
        if due {
            self.last_report = Some(now);
            let n = std::mem::take(&mut self.dropped);
            return Verdict::DropAndReport(n);
        }
        Verdict::Drop
    }
}
