//! Отправка событий в центр. Канал односторонний: агент только шлёт.
//!
//! Устойчивость к потере связи (FR-A4): события копятся в буфере и в файле на
//! диске; пока центр недоступен, агент их держит и досылает при восстановлении.
//! HTTP-клиент живёт в отдельном потоке, чтобы блокирующая сеть не трогала
//! асинхронные ловушки.

use crate::config::Config;
use crate::event::Event;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

const MAX_BUFFER: usize = 50_000;

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

/// Запускает поток-отправитель и возвращает «раковину», которую раздают ловушкам.
pub fn start(cfg: Config, buffer_path: PathBuf) -> EventSink {
    let (tx, rx) = mpsc::channel::<Event>();
    thread::spawn(move || {
        let mut buf: VecDeque<Event> = load_buffer(&buffer_path);
        if !buf.is_empty() {
            eprintln!("[sender] восстановлено {} событий из буфера", buf.len());
        }
        let url = cfg.ingest_url();
        let agent = build_agent(cfg.verify_tls);
        let retry = Duration::from_secs(cfg.retry_interval_s.max(1));
        let mut dirty = false;

        loop {
            match rx.recv_timeout(retry) {
                Ok(ev) => {
                    if buf.len() >= MAX_BUFFER {
                        buf.pop_front(); // при переполнении теряем самые старые
                    }
                    buf.push_back(ev);
                    dirty = true;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    flush(&agent, &url, &cfg.token, &mut buf);
                    persist(&buffer_path, &buf);
                    return;
                }
            }
            // Подбираем всё, что уже скопилось, одним заходом.
            while let Ok(ev) = rx.try_recv() {
                if buf.len() >= MAX_BUFFER {
                    buf.pop_front();
                }
                buf.push_back(ev);
                dirty = true;
            }
            let sent = flush(&agent, &url, &cfg.token, &mut buf);
            if sent > 0 || dirty {
                persist(&buffer_path, &buf);
                dirty = false;
            }
        }
    });
    EventSink { tx }
}

/// Периодический heartbeat: обновляет "last seen" ловушки в центре между
/// атаками, чтобы на дашборде был виден статус online (FR-A3).
pub fn start_heartbeat(cfg: Config) {
    if cfg.heartbeat_interval_s == 0 {
        return;
    }
    thread::spawn(move || {
        let agent = build_agent(cfg.verify_tls);
        let url = cfg.heartbeat_url();
        let period = Duration::from_secs(cfg.heartbeat_interval_s);
        loop {
            let _ = agent
                .post(&url)
                .set("X-HF-Token", &cfg.token)
                .send_string("");
            thread::sleep(period);
        }
    });
}

fn build_agent(_verify_tls: bool) -> ureq::Agent {
    // http и https с доверенным сертификатом. Самоподписанный TLS центра —
    // отдельный шаг (маскировка канала), пока его не трогаем.
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
}

/// Отправляет события из начала буфера, пока центр отвечает. Возвращает число отправленных.
fn flush(agent: &ureq::Agent, url: &str, token: &str, buf: &mut VecDeque<Event>) -> usize {
    let mut sent = 0;
    while let Some(ev) = buf.front() {
        let body = match serde_json::to_string(ev) {
            Ok(b) => b,
            Err(_) => {
                buf.pop_front(); // кривое событие не должно застревать навсегда
                continue;
            }
        };
        let res = agent
            .post(url)
            .set("Content-Type", "application/json")
            .set("X-HF-Token", token)
            .send_string(&body);
        match res {
            Ok(_) => {
                buf.pop_front();
                sent += 1;
            }
            Err(ureq::Error::Status(code, _)) if code == 401 || code == 404 => {
                // Токен не признан: событие центру не нужно, отбрасываем, иначе встанет очередь.
                eprintln!("[sender] центр отверг событие ({code}), отбрасываю");
                buf.pop_front();
            }
            Err(_) => break, // центр недоступен — ждём следующего цикла
        }
    }
    sent
}

fn persist(path: &PathBuf, buf: &VecDeque<Event>) {
    let tmp = path.with_extension("tmp");
    let mut f = match File::create(&tmp) {
        Ok(f) => f,
        Err(_) => return,
    };
    for ev in buf {
        if let Ok(line) = serde_json::to_string(ev) {
            let _ = writeln!(f, "{line}");
        }
    }
    let _ = f.flush();
    let _ = std::fs::rename(&tmp, path);
}

fn load_buffer(path: &PathBuf) -> VecDeque<Event> {
    let mut out = VecDeque::new();
    if let Ok(f) = OpenOptions::new().read(true).open(path) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<Event>(&line) {
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

