//! Состояние одного TCP-соединения: чтение/запись с таймаутом, счётчики,
//! контекст для шаблонов и отправка событий через общую «раковину».

use crate::event::{event_type, now_ts, Event};
use crate::sender::EventSink;
use crate::util;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct Session {
    stream: TcpStream,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub id: String,
    pub started: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub vars: HashMap<String, String>,
    pub hostname: String,
    pub idle_timeout: f64,
    sink: EventSink,
    class: String,
    rbuf: Vec<u8>,
}

impl Session {
    pub fn new(
        stream: TcpStream,
        dst_port: u16,
        sink: EventSink,
        class: &str,
        hostname: String,
        idle_timeout: f64,
    ) -> Session {
        let (ip, port) = match stream.peer_addr() {
            Ok(a) => (a.ip().to_string(), a.port()),
            Err(_) => (String::new(), 0),
        };
        Session {
            stream,
            src_ip: ip,
            src_port: port,
            dst_port,
            id: util::session_id(),
            started: now_ts(),
            bytes_in: 0,
            bytes_out: 0,
            vars: HashMap::new(),
            hostname,
            idle_timeout,
            sink,
            class: class.to_string(),
            rbuf: Vec::new(),
        }
    }

    pub fn ctx(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("src_ip".into(), self.src_ip.clone());
        m.insert("src_port".into(), self.src_port.to_string());
        m.insert("dst_port".into(), self.dst_port.to_string());
        m.insert("session".into(), self.id.clone());
        m.insert("hostname".into(), self.hostname.clone());
        m.insert("date".into(), util::http_date());
        m.insert("time".into(), util::clock_time());
        for (k, v) in &self.vars {
            m.insert(k.clone(), v.clone());
        }
        m
    }

    /// Готовое событие с заполненными полями соединения.
    pub fn event(&self, event_type: &str) -> Event {
        Event::new(&self.class, event_type)
            .peer(&self.src_ip, self.src_port, self.dst_port)
            .session(&self.id)
    }

    /// Канал событий — для обработчиков, которые живут в отдельной задаче (SSH).
    pub fn sink(&self) -> EventSink {
        self.sink.clone()
    }

    pub fn emit(&self, ev: Event) {
        self.sink.emit(ev);
    }

    /// Короткая форма: событие с data.
    pub fn emit_data(&self, event_type: &str, data: Value) {
        self.emit(self.event(event_type).data(data));
    }

    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        self.bytes_out += data.len() as u64;
        Ok(())
    }

    /// Читает до `n` байт с таймаутом (по умолчанию — idle_timeout).
    pub async fn read(&mut self, n: usize, timeout_s: Option<f64>) -> std::io::Result<Vec<u8>> {
        if !self.rbuf.is_empty() {
            let take = self.rbuf.len().min(n);
            let out: Vec<u8> = self.rbuf.drain(..take).collect();
            return Ok(out);
        }
        let dur = Duration::from_secs_f64(timeout_s.unwrap_or(self.idle_timeout).max(0.001));
        let mut buf = vec![0u8; n.min(65536)];
        let read = timeout(dur, self.stream.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))??;
        buf.truncate(read);
        self.bytes_in += read as u64;
        Ok(buf)
    }

    pub fn disconnect_event(&self, reason: &str) -> Event {
        self.event(event_type::DISCONNECT).data(serde_json::json!({
            "reason": reason,
            "duration": (now_ts() - self.started * 1.0).max(0.0),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }))
    }
}
