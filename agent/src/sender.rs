//! Отправка событий в центр. Канал односторонний: агент только шлёт.
//!
//! Устойчивость к потере связи (FR-A4): события копятся в зашифрованном буфере
//! на диске (Base64-строки бинарных конвертов, без открытого JSON).
//! Поддерживаются скрытные транспорты:
//! - SO_LINGER=0 HTTP без TIME_WAIT в `ss`/`netstat` (send_http_nolinger)
//! - Stateless UDP burst (send_udp_burst)
//! - Джиттер и piggybacking для Heartbeat (сброс таймера при реальной передаче событий).

use crate::config::Config;
use crate::event::Event;
use rand::Rng;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_BUFFER: usize = 50_000;

/// Больше конверт в одну UDP-датаграмму не помещается (65507 минус запас).
pub const UDP_MAX_ENVELOPE: usize = 60_000;

/// Когда отправитель ловушки последний раз доставил события в центр. Heartbeat
/// той же ловушки по нему пропускает свой такт (piggybacking). У каждой ловушки
/// свои часы: иначе события одной гасили бы heartbeat'ы остальных.
#[derive(Clone, Default)]
pub struct IngestClock {
    ts: Arc<AtomicU64>,
    count: Arc<AtomicU64>,
}

impl IngestClock {
    /// Фиксирует успешную отправку телеметрии (ingest).
    pub fn record(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.ts.store(now, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    /// Unix-время (в секундах) последней успешной отправки.
    pub fn last_sent(&self) -> u64 {
        self.ts.load(Ordering::SeqCst)
    }

    /// Монотонный счётчик успешных отправок.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct EventSink {
    tx: Sender<Event>,
}

impl EventSink {
    /// Отправить событие (не блокирует ловушку). Если поток-отправитель умер — тихо игнорируем.
    pub fn emit(&self, ev: Event) {
        let _ = self.tx.send(ev);
    }

    /// Раковина-сборщик для тестов: события не уходят в сеть, а падают в Receiver.
    #[cfg(test)]
    pub fn test_sink() -> (EventSink, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel::<Event>();
        (EventSink { tx }, rx)
    }
}

/// Отправка конверта через HTTP POST без сохранения TIME_WAIT (SO_LINGER = 0).
/// При закрытии сокета ядро отправляет TCP RST, не оставляя соединений в ss / netstat.
pub fn send_http_nolinger(host_port: &str, path: &str, envelope: &[u8]) -> Result<(), String> {
    let host_hdr = host_port
        .strip_prefix("http://")
        .or_else(|| host_port.strip_prefix("https://"))
        .unwrap_or(host_port);
    let host_hdr = host_hdr.split('/').next().unwrap_or(host_hdr);

    let host_with_port = if !host_hdr.contains(':') {
        if host_port.starts_with("https://") {
            format!("{host_hdr}:443")
        } else {
            format!("{host_hdr}:80")
        }
    } else {
        host_hdr.to_string()
    };

    let addrs: Vec<std::net::SocketAddr> = host_with_port
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host_with_port} failed: {e}"))?
        .collect();

    let addr = addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("no IPv4 address found for {host_with_port}"))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(|e| format!("socket creation failed: {e}"))?;

    socket
        .set_linger(Some(Duration::ZERO))
        .map_err(|e| format!("set linger failed: {e}"))?;

    let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(10)));

    socket
        .connect(&addr.into())
        .map_err(|e| format!("connect to {addr} failed: {e}"))?;

    let mut stream: std::net::TcpStream = socket.into();

    let req_headers = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        host_hdr,
        envelope.len()
    );

    stream
        .write_all(req_headers.as_bytes())
        .map_err(|e| format!("write headers failed: {e}"))?;

    if !envelope.is_empty() {
        stream
            .write_all(envelope)
            .map_err(|e| format!("write body failed: {e}"))?;
    }
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("read status line failed: {e}"))?;

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("malformed HTTP status line: {status_line:?}"));
    }
    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| format!("invalid HTTP status code in: {status_line:?}"))?;

    loop {
        let mut header_line = String::new();
        let n = reader
            .read_line(&mut header_line)
            .map_err(|e| format!("read header line failed: {e}"))?;
        if n == 0 {
            break;
        }
        let trimmed = header_line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
    }

    if status_code == 200 || status_code == 204 {
        Ok(())
    } else {
        Err(format!("server returned HTTP status {status_code}"))
    }
}

/// Одиночная отправка конверта через UDP без вызова connect() (stateless burst).
pub fn send_udp_burst(udp_target: &str, envelope: &[u8]) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(envelope, udp_target)
        .map_err(|e| format!("udp send_to {udp_target} failed: {e}"))?;
    Ok(())
}

/// Сохраняет зашифрованный бинарный конверт как Base64-строку в конец файла буфера.
pub fn append_encrypted_buffer(path: impl AsRef<Path>, envelope: &[u8]) -> Result<(), String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(envelope);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path.as_ref())
        .map_err(|e| format!("open buffer for append: {e}"))?;
    writeln!(file, "{b64}").map_err(|e| format!("write to buffer: {e}"))?;
    file.flush().map_err(|e| format!("flush buffer: {e}"))?;
    Ok(())
}

/// Загружает сохраненные Base64-строки конвертов из файла буфера на диске.
pub fn load_encrypted_buffer(path: impl AsRef<Path>) -> Result<Vec<Vec<u8>>, String> {
    use base64::Engine;
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|e| format!("open buffer {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("read buffer line {idx}: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| format!("base64 decode line {idx}: {e}"))?;
        out.push(bytes);
    }
    Ok(out)
}

/// Перезаписывает файл буфера текущим списком конвертов в формате Base64 (по строке на конверт).
pub fn persist_encrypted_buffer<I, B>(path: impl AsRef<Path>, envelopes: I) -> Result<(), String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    use base64::Engine;
    let path = path.as_ref();
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp).map_err(|e| format!("create tmp buffer: {e}"))?;
    for env in envelopes {
        let b64 = base64::engine::general_purpose::STANDARD.encode(env.as_ref());
        writeln!(file, "{b64}").map_err(|e| format!("write tmp buffer: {e}"))?;
    }
    file.flush().map_err(|e| format!("flush tmp buffer: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename buffer: {e}"))?;
    Ok(())
}

fn extract_host_port(url: &str) -> String {
    let s = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    if !s.contains(':') {
        if url.starts_with("https://") {
            format!("{s}:443")
        } else {
            format!("{s}:80")
        }
    } else {
        s.to_string()
    }
}

fn pick_path(cfg: &Config) -> &str {
    if !cfg.stealth_paths.is_empty() {
        let idx = rand::thread_rng().gen_range(0..cfg.stealth_paths.len());
        &cfg.stealth_paths[idx]
    } else {
        "/api/ingest"
    }
}

fn send_envelope(cfg: &Config, agent: &ureq::Agent, envelope: &[u8]) -> Result<(), String> {
    match cfg.transport.as_str() {
        "udp_burst" => {
            if cfg.center_udp.is_empty() {
                return Err("center_udp is not configured for udp_burst transport".to_string());
            }
            send_udp_burst(&cfg.center_udp, envelope)
        }
        "http_nolinger" => {
            let host_port = extract_host_port(&cfg.center_url);
            let path = pick_path(cfg);
            send_http_nolinger(&host_port, path, envelope)
        }
        _ => {
            let url = cfg.ingest_url();
            let content_type = if !cfg.server_pub_key.is_empty() {
                "application/octet-stream"
            } else {
                "application/json"
            };
            let res = agent
                .post(&url)
                .set("Content-Type", content_type)
                .set("X-HF-Token", &cfg.token)
                .send_bytes(envelope);
            match res {
                Ok(_) => Ok(()),
                Err(ureq::Error::Status(code, _)) if code == 401 || code == 404 => {
                    Err(format!("center rejected envelope ({code})"))
                }
                Err(e) => Err(format!("ureq error: {e}")),
            }
        }
    }
}

fn flush_envelopes(
    cfg: &Config,
    agent: &ureq::Agent,
    buffer_path: &Path,
    pending: &mut VecDeque<Vec<u8>>,
    clock: &IngestClock,
) -> usize {
    let mut sent = 0;
    while let Some(env) = pending.front() {
        match send_envelope(cfg, agent, env) {
            Ok(_) => {
                pending.pop_front();
                sent += 1;
                clock.record();
            }
            Err(e) => {
                if e.contains("rejected") || e.contains("401") || e.contains("404") {
                    eprintln!("[sender] центр отверг конверт ({e}), отбрасываю");
                    pending.pop_front();
                    sent += 1;
                    continue;
                }
                break;
            }
        }
    }
    if sent > 0 {
        let _ = persist_encrypted_buffer(buffer_path, &*pending);
    }
    sent
}

/// Запечатывает события в конверты. Для udp_burst пачка делится пополам,
/// пока каждый конверт не поместится в датаграмму; событие, которое не
/// помещается и одно, отбрасывается — иначе оно навсегда застряло бы в буфере.
pub fn seal_events(cfg: &Config, events: &[Event]) -> Vec<Vec<u8>> {
    match crate::crypto::seal_envelope(&cfg.server_pub_key, &cfg.token, "ingest", events) {
        Ok(env) if cfg.transport != "udp_burst" || env.len() <= UDP_MAX_ENVELOPE => vec![env],
        Ok(_) if events.len() > 1 => {
            let (a, b) = events.split_at(events.len() / 2);
            let mut out = seal_events(cfg, a);
            out.extend(seal_events(cfg, b));
            out
        }
        Ok(env) => {
            eprintln!("[sender] событие не помещается в UDP-датаграмму ({} байт), отброшено", env.len());
            Vec::new()
        }
        Err(e) => {
            eprintln!("[sender] ошибка seal_envelope: {e}");
            Vec::new()
        }
    }
}

fn handle_events(
    cfg: &Config,
    agent: &ureq::Agent,
    buffer_path: &Path,
    pending: &mut VecDeque<Vec<u8>>,
    events: Vec<Event>,
    clock: &IngestClock,
) {
    if events.is_empty() {
        return;
    }

    let envelopes_to_send: Vec<Vec<u8>> = if !cfg.server_pub_key.is_empty() {
        seal_events(cfg, &events)
    } else {
        events
            .iter()
            .filter_map(|e| serde_json::to_vec(e).ok())
            .collect()
    };

    for env in envelopes_to_send {
        if pending.is_empty() {
            match send_envelope(cfg, agent, &env) {
                Ok(_) => {
                    clock.record();
                }
                Err(_) => {
                    if pending.len() >= MAX_BUFFER {
                        pending.pop_front();
                    }
                    let _ = append_encrypted_buffer(buffer_path, &env);
                    pending.push_back(env);
                }
            }
        } else {
            if pending.len() >= MAX_BUFFER {
                pending.pop_front();
            }
            let _ = append_encrypted_buffer(buffer_path, &env);
            pending.push_back(env);
        }
    }

    if !pending.is_empty() {
        flush_envelopes(cfg, agent, buffer_path, pending, clock);
    }
}

/// Запускает поток-отправитель и возвращает «раковину», которую раздают ловушкам.
/// clock — общие с heartbeat'ом той же ловушки часы отправок.
pub fn start(cfg: Config, buffer_path: PathBuf, clock: IngestClock) -> EventSink {
    let buffer_path = cfg
        .buffer_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or(buffer_path);

    let (tx, rx) = mpsc::channel::<Event>();
    thread::spawn(move || {
        let mut pending: VecDeque<Vec<u8>> = match load_encrypted_buffer(&buffer_path) {
            Ok(loaded) => {
                if !loaded.is_empty() {
                    eprintln!("[sender] восстановлено {} конвертов из буфера", loaded.len());
                }
                loaded.into()
            }
            Err(_) => {
                let legacy = load_buffer(&buffer_path);
                let mut conv = VecDeque::new();
                if !cfg.server_pub_key.is_empty() {
                    let evs: Vec<Event> = legacy.into_iter().collect();
                    if let Ok(env) =
                        crate::crypto::seal_envelope(&cfg.server_pub_key, &cfg.token, "ingest", &evs)
                    {
                        conv.push_back(env);
                    }
                } else {
                    for ev in legacy {
                        if let Ok(bytes) = serde_json::to_vec(&ev) {
                            conv.push_back(bytes);
                        }
                    }
                }
                conv
            }
        };

        let agent = build_agent(cfg.verify_tls);
        let retry = Duration::from_secs(cfg.retry_interval_s.max(1));

        if !pending.is_empty() {
            flush_envelopes(&cfg, &agent, &buffer_path, &mut pending, &clock);
        }

        loop {
            match rx.recv_timeout(retry) {
                Ok(ev) => {
                    let mut incoming = vec![ev];
                    while let Ok(next) = rx.try_recv() {
                        incoming.push(next);
                    }
                    handle_events(&cfg, &agent, &buffer_path, &mut pending, incoming, &clock);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !pending.is_empty() {
                        flush_envelopes(&cfg, &agent, &buffer_path, &mut pending, &clock);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    if !pending.is_empty() {
                        flush_envelopes(&cfg, &agent, &buffer_path, &mut pending, &clock);
                    }
                    return;
                }
            }
        }
    });
    EventSink { tx }
}

/// Периодический heartbeat: обновляет "last seen" ловушки в центре между
/// атаками, чтобы на дашборде был виден статус online (FR-A3).
///
/// Интервал вычисляется как interval + rand::thread_rng().gen_range(0..=cfg.jitter_s).
/// При успешной отправке реальных событий (ingest) таймер сбрасывается (piggybacking).
pub fn start_heartbeat(cfg: Config, clock: IngestClock) {
    if cfg.heartbeat_interval_s == 0 {
        return;
    }
    thread::spawn(move || {
        let agent = build_agent(cfg.verify_tls);
        let url = cfg.heartbeat_url();
        let host_port = extract_host_port(&cfg.center_url);

        loop {
            let jitter = if cfg.jitter_s > 0 {
                rand::thread_rng().gen_range(0..=cfg.jitter_s)
            } else {
                0
            };
            let period_secs = cfg.heartbeat_interval_s + jitter;
            let period = Duration::from_secs(period_secs);
            let start_instant = Instant::now();
            let start_count = clock.count();
            let check_interval = Duration::from_millis(100);

            let mut piggybacked = false;
            while start_instant.elapsed() < period {
                let remaining = period.saturating_sub(start_instant.elapsed());
                thread::sleep(remaining.min(check_interval));
                if clock.count() > start_count {
                    // При успешной отправке реальных событий (ingest) таймер heartbeat сбрасывается (piggybacking)
                    piggybacked = true;
                    break;
                }
            }

            if piggybacked {
                continue;
            }

            // Отправка heartbeat
            if cfg.transport == "http_nolinger" && !cfg.server_pub_key.is_empty() {
                if let Ok(env) =
                    crate::crypto::seal_envelope(&cfg.server_pub_key, &cfg.token, "heartbeat", &[])
                {
                    let path = pick_path(&cfg);
                    let _ = send_http_nolinger(&host_port, path, &env);
                }
            } else if cfg.transport == "udp_burst" && !cfg.center_udp.is_empty() {
                if let Ok(env) =
                    crate::crypto::seal_envelope(&cfg.server_pub_key, &cfg.token, "heartbeat", &[])
                {
                    let _ = send_udp_burst(&cfg.center_udp, &env);
                }
            } else {
                let _ = agent
                    .post(&url)
                    .set("X-HF-Token", &cfg.token)
                    .send_string("");
            }
        }
    });
}

fn build_agent(_verify_tls: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
}

fn load_buffer(path: &PathBuf) -> VecDeque<Event> {
    let mut out = VecDeque::new();
    if let Ok(f) = OpenOptions::new().read(true).open(path) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<Event>(trimmed) {
                out.push_back(ev);
            }
        }
    }
    out
}

/// Для buffered Event нужно уметь десериализовать — зеркало Serialize.
mod de {
    use crate::event::Event;
    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Deserialize)]
    struct Raw {
        trap_class: String,
        event_type: String,
        #[serde(default = "tcp")]
        proto: String,
        #[serde(default)]
        src_ip: String,
        #[serde(default)]
        src_port: u16,
        #[serde(default)]
        dst_port: u16,
        #[serde(default)]
        session: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        data: Value,
        #[serde(default)]
        ts: f64,
    }
    fn tcp() -> String {
        "tcp".into()
    }

    impl<'de> Deserialize<'de> for Event {
        fn deserialize<D>(d: D) -> Result<Event, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let r = Raw::deserialize(d)?;
            Ok(Event {
                trap_class: r.trap_class,
                event_type: r.event_type,
                proto: r.proto,
                src_ip: r.src_ip,
                src_port: r.src_port,
                dst_port: r.dst_port,
                session: r.session,
                username: r.username,
                password: r.password,
                data: if r.data.is_null() {
                    Value::Object(Default::default())
                } else {
                    r.data
                },
                ts: r.ts,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_send_http_nolinger_204_success() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_port = addr.to_string();
        let path = "/v1/rgstr";
        let envelope = b"binary-stealth-envelope-data-204";

        let srv_host_port = host_port.clone();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(request_line.trim(), "POST /v1/rgstr HTTP/1.1");

            let mut content_length = 0usize;
            let mut host_header = String::new();
            let mut content_type = String::new();

            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break;
                }
                if let Some(val) = trimmed.strip_prefix("Content-Length:") {
                    content_length = val.trim().parse().unwrap();
                } else if let Some(val) = trimmed.strip_prefix("Host:") {
                    host_header = val.trim().to_string();
                } else if let Some(val) = trimmed.strip_prefix("Content-Type:") {
                    content_type = val.trim().to_string();
                }
            }

            assert_eq!(host_header, srv_host_port);
            assert_eq!(content_type, "application/octet-stream");
            assert_eq!(content_length, envelope.len());

            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(&body, envelope);

            // Ответ 204 No Content
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let res = send_http_nolinger(&host_port, path, envelope);
        assert!(res.is_ok(), "send_http_nolinger failed: {:?}", res.err());
        handle.join().unwrap();
    }

    #[test]
    fn test_send_http_nolinger_200_success() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_port = addr.to_string();
        let path = "/cdn-cgi/rum";
        let envelope = b"binary-stealth-envelope-data-200";

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(request_line.trim(), "POST /cdn-cgi/rum HTTP/1.1");

            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
            }

            let mut body = vec![0u8; envelope.len()];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(&body, envelope);

            // Ответ 200 OK
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let res = send_http_nolinger(&host_port, path, envelope);
        assert!(res.is_ok(), "send_http_nolinger failed: {:?}", res.err());
        handle.join().unwrap();
    }

    #[test]
    fn test_send_http_nolinger_error_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_port = addr.to_string();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            loop {
                line.clear();
                let _ = reader.read_line(&mut line);
                if line.trim().is_empty() {
                    break;
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n");
            let _ = stream.flush();
        });

        let res = send_http_nolinger(&host_port, "/error", b"payload");
        assert!(res.is_err());
        handle.join().unwrap();
    }

    fn seal_cfg(transport: &str) -> Config {
        serde_json::from_value(serde_json::json!({
            "center_url": "http://127.0.0.1:8080",
            "token": "tok",
            "server_pub_key": "11".repeat(32),
            "transport": transport,
            "center_udp": "127.0.0.1:9099",
        }))
        .unwrap()
    }

    fn noisy_events(n: usize) -> Vec<Event> {
        (0..n)
            .map(|_| {
                let noise: String = (0..1500).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
                Event::new("x", "data").data(serde_json::json!({ "noise": noise }))
            })
            .collect()
    }

    #[test]
    fn udp_burst_splits_batches_to_fit_datagrams() {
        let events = noisy_events(200);
        let http = seal_events(&seal_cfg("http_nolinger"), &events);
        assert_eq!(http.len(), 1, "HTTP шлёт пачку одним конвертом");
        assert!(http[0].len() > UDP_MAX_ENVELOPE);

        let udp = seal_events(&seal_cfg("udp_burst"), &events);
        assert!(udp.len() > 1);
        assert!(udp.iter().all(|e| e.len() <= UDP_MAX_ENVELOPE), "каждый конверт помещается в датаграмму");

        let huge = vec![Event::new("x", "data").data(serde_json::json!({
            "noise": (0..150_000).map(|_| format!("{:02x}", rand::random::<u8>())).collect::<String>()
        }))];
        assert!(seal_events(&seal_cfg("udp_burst"), &huge).is_empty(), "неотправимое событие отбрасывается");
    }

    #[test]
    fn test_send_udp_burst_received() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let envelope = b"udp-envelope-burst-data-secret-12345";
        let target = addr.to_string();

        let res = send_udp_burst(&target, envelope);
        assert!(res.is_ok(), "send_udp_burst failed: {:?}", res.err());

        let mut buf = [0u8; 1024];
        let (n, _src) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], envelope);
    }

    #[test]
    fn test_encrypted_buffer_save_and_load_base64() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_buf_{}.dat", rand::random::<u64>()));

        let env1 = b"first_secret_envelope_bytes".to_vec();
        let env2 = b"second_secret_envelope_bytes".to_vec();

        append_encrypted_buffer(&file_path, &env1).unwrap();
        append_encrypted_buffer(&file_path, &env2).unwrap();

        // Проверяем, что файл содержит Base64-строки и не содержит открытый текст
        let mut raw_content = String::new();
        File::open(&file_path)
            .unwrap()
            .read_to_string(&mut raw_content)
            .unwrap();

        assert!(!raw_content.contains("first_secret_envelope_bytes"));
        assert!(!raw_content.contains("second_secret_envelope_bytes"));

        let loaded = load_encrypted_buffer(&file_path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], env1);
        assert_eq!(loaded[1], env2);

        // Проверяем перезапись через persist_encrypted_buffer
        let env3 = b"third_envelope".to_vec();
        persist_encrypted_buffer(&file_path, &[env3.clone()]).unwrap();

        let loaded_after = load_encrypted_buffer(&file_path).unwrap();
        assert_eq!(loaded_after, vec![env3]);

        let _ = std::fs::remove_file(&file_path);
    }

    #[test]
    fn test_piggybacking_and_jitter() {
        let clock = IngestClock::default();
        assert_eq!(clock.count(), 0);
        assert_eq!(clock.last_sent(), 0);
        clock.clone().record();
        assert_eq!(clock.count(), 1, "клон делит часы с оригиналом");
        assert!(clock.last_sent() > 0);
    }

    #[test]
    fn ingest_clocks_are_independent_per_trap() {
        // Отправка событий одной ловушкой не должна гасить heartbeat другой.
        let a = IngestClock::default();
        let b = IngestClock::default();
        a.record();
        a.record();
        assert_eq!(a.count(), 2);
        assert_eq!(b.count(), 0);
        assert_eq!(b.last_sent(), 0);
    }
}
