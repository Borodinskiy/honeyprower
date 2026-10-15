//! Единая модель события. Формат одинаков для всех классов ловушек, поэтому
//! коллектор центра принимает их одним endpoint'ом. Центр сам проставляет
//! trap_id/trap_name по токену — агент его не знает и не должен.

use serde::Serialize;
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Закрытый набор типов событий — чтобы фильтрация в центре была предсказуемой.
#[allow(dead_code)]
pub mod event_type {
    pub const CONNECT: &str = "connect";
    pub const DISCONNECT: &str = "disconnect";
    pub const DATA: &str = "data";
    pub const AUTH: &str = "auth";
    pub const COMMAND: &str = "command";
    pub const REQUEST: &str = "request";
    pub const HANDSHAKE: &str = "handshake";
    pub const SCAN: &str = "scan";
    pub const TOKEN: &str = "token";
    pub const ERROR: &str = "error";
    pub const PAYLOAD: &str = "payload";
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub trap_class: String,
    pub event_type: String,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub data: Value,
    /// Unix-время с дробной частью (секунды).
    pub ts: f64,
}

pub type IngestEvent = Event;

impl Event {
    pub fn new(trap_class: &str, event_type: &str) -> Event {
        Event {
            trap_class: trap_class.to_string(),
            event_type: event_type.to_string(),
            proto: "tcp".to_string(),
            src_ip: String::new(),
            src_port: 0,
            dst_port: 0,
            session: String::new(),
            username: None,
            password: None,
            data: Value::Object(Map::new()),
            ts: now_ts(),
        }
    }

    pub fn proto(mut self, p: &str) -> Event {
        self.proto = p.to_string();
        self
    }
    pub fn peer(mut self, ip: &str, port: u16, dst_port: u16) -> Event {
        self.src_ip = ip.to_string();
        self.src_port = port;
        self.dst_port = dst_port;
        self
    }
    pub fn session(mut self, id: &str) -> Event {
        self.session = id.to_string();
        self
    }
    pub fn username(mut self, u: Option<String>) -> Event {
        self.username = u;
        self
    }
    pub fn password(mut self, p: Option<String>) -> Event {
        self.password = p;
        self
    }
    pub fn data(mut self, d: Value) -> Event {
        self.data = d;
        self
    }
}

pub fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
