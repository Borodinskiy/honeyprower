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
    /// Открытый ключ сервера (X25519 в hex) для шифрования конвертов.
    #[serde(default)]
    pub server_pub_key: String,
    /// Транспорт передачи телеметрии ("http_nolinger", "udp_burst", "http").
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Адрес центра для stateless UDP burst ("host:port").
    #[serde(default)]
    pub center_udp: String,
    /// Маскировочные пути для HTTP-запросов.
    #[serde(default = "default_stealth_paths")]
    pub stealth_paths: Vec<String>,
    /// Пользовательский путь к файлу буфера на диске.
    #[serde(default)]
    pub buffer_path: Option<String>,
    /// Джиттер в секундах для рандомизации периодических задач.
    #[serde(default = "default_jitter")]
    pub jitter_s: u64,
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
    /// Секрет для ключей, которые должны переживать перезапуск (ключ хоста SSH).
    /// В конфиге его нет: main подставляет токен ловушки.
    #[serde(skip)]
    pub key_seed: String,
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
fn default_transport() -> String {
    "http_nolinger".to_string()
}
fn default_stealth_paths() -> Vec<String> {
    vec![
        "/cdn-cgi/rum".to_string(),
        "/v1/rgstr".to_string(),
        "/api/v2/metrics".to_string(),
    ]
}
fn default_jitter() -> u64 {
    10
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let json_str = r#"{
            "center_url": "http://127.0.0.1:8080",
            "token": "tok123",
            "trap": {
                "class": "banner"
            }
        }"#;

        let cfg: Config = serde_json::from_str(json_str).unwrap();
        assert_eq!(cfg.server_pub_key, "");
        assert_eq!(cfg.transport, "http_nolinger");
        assert_eq!(cfg.center_udp, "");
        assert_eq!(
            cfg.stealth_paths,
            vec![
                "/cdn-cgi/rum".to_string(),
                "/v1/rgstr".to_string(),
                "/api/v2/metrics".to_string()
            ]
        );
        assert_eq!(cfg.buffer_path, None);
        assert_eq!(cfg.jitter_s, 10);
        assert_eq!(cfg.heartbeat_interval_s, 30);
        assert_eq!(cfg.retry_interval_s, 10);
        assert!(cfg.verify_tls);
    }

    #[test]
    fn test_config_overrides() {
        let json_str = r#"{
            "center_url": "http://127.0.0.1:8080",
            "token": "tok123",
            "server_pub_key": "aabbcc1122",
            "transport": "udp_burst",
            "center_udp": "127.0.0.1:9099",
            "stealth_paths": ["/custom/path"],
            "buffer_path": "/var/log/custom.dat",
            "jitter_s": 5,
            "trap": {
                "class": "banner"
            }
        }"#;

        let cfg: Config = serde_json::from_str(json_str).unwrap();
        assert_eq!(cfg.server_pub_key, "aabbcc1122");
        assert_eq!(cfg.transport, "udp_burst");
        assert_eq!(cfg.center_udp, "127.0.0.1:9099");
        assert_eq!(cfg.stealth_paths, vec!["/custom/path".to_string()]);
        assert_eq!(cfg.buffer_path, Some("/var/log/custom.dat".to_string()));
        assert_eq!(cfg.jitter_s, 5);
    }
}
