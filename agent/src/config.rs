//! Конфиг ловушки. Едет вместе с бинарником (файл рядом), из центра ничего
//! не приходит. Чтобы поменять ловушку — правят конфиг и запускают заново.

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Базовый адрес центра, например http://127.0.0.1:8080. События уходят на {center_url}/api/ingest.
    pub center_url: String,
    /// Токен ловушки: по нему центр узнаёт, чья это телеметрия.
    pub token: String,
    /// Проверять ли TLS-сертификат центра (по умолчанию да).
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    /// Описание самой ловушки.
    pub trap: TrapConfig,
    /// Через сколько секунд повторять отправку, если центр недоступен.
    #[serde(default = "default_retry")]
    pub retry_interval_s: u64,
    /// Период heartbeat'а (обновляет "last seen" в центре). 0 — выключить.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrapConfig {
    pub class: String,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub port: u16,
    /// Для многопортовых классов: "8000-8005,9200".
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub name: String,
    #[serde(default)]
    pub params: Value,
}

fn default_true() -> bool {
    true
}
fn default_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_retry() -> u64 {
    10
}
fn default_heartbeat() -> u64 {
    30
}

impl Config {
    pub fn ingest_url(&self) -> String {
        format!("{}/api/ingest", self.center_url.trim_end_matches('/'))
    }
    pub fn heartbeat_url(&self) -> String {
        format!("{}/api/heartbeat", self.center_url.trim_end_matches('/'))
    }
}

/// Доступ к полям params с значениями по умолчанию.
pub struct Params<'a>(pub &'a Value);

impl<'a> Params<'a> {
    pub fn str(&self, key: &str, default: &str) -> String {
        self.0
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| default.to_string())
    }
    pub fn int(&self, key: &str, default: i64) -> i64 {
        let v = self.0.get(key);
        v.and_then(Value::as_i64)
            .or_else(|| v.and_then(Value::as_str).and_then(|s| s.parse().ok()))
            .unwrap_or(default)
    }
    pub fn float(&self, key: &str, default: f64) -> f64 {
        let v = self.0.get(key);
        v.and_then(Value::as_f64)
            .or_else(|| v.and_then(Value::as_str).and_then(|s| s.parse().ok()))
            .unwrap_or(default)
    }
    pub fn bool(&self, key: &str, default: bool) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(default)
    }
    pub fn array(&self, key: &str) -> Vec<Value> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}
