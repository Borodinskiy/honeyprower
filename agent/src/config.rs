//! Конфиг агента. Едет вместе с бинарником (файл рядом), из центра ничего
//! не приходит. Чтобы поменять ловушки — правят конфиг и запускают заново.
//!
//! Один агент обслуживает все ловушки своего хоста: они перечислены в `traps`,
//! у каждой свой токен и ключ, поэтому центр различает их телеметрию. Старый
//! формат с одной ловушкой (`token` + `trap`) по-прежнему читается.

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Базовый адрес центра, например http://127.0.0.1:8080. События уходят на {center_url}/api/ingest.
    pub center_url: String,
    /// Токен ловушки (старый формат с одной `trap`): по нему центр узнаёт, чья это телеметрия.
    #[serde(default)]
    pub token: String,
    /// Проверять ли TLS-сертификат центра (по умолчанию да).
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    /// Одна ловушка (старый формат).
    #[serde(default)]
    pub trap: Option<TrapConfig>,
    /// Ловушки хоста, у каждой свои token и server_pub_key.
    #[serde(default)]
    pub traps: Vec<TrapConfig>,
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
    /// Каталог файла конфига: относительные пути плагинов считаются от него. Ставит main.
    #[serde(skip)]
    pub base_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrapConfig {
    /// Токен этой ловушки (в `traps`); в старом формате берётся из корня конфига.
    #[serde(default)]
    pub token: String,
    /// Открытый ключ центра для конвертов этой ловушки; пусто — из корня конфига.
    #[serde(default)]
    pub server_pub_key: String,
    pub class: String,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub port: u16,
    /// Для многопортовых классов: "8000-8005,9200".
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub params: Value,
    /// Секрет для ключей, которые должны переживать перезапуск (ключ хоста SSH).
    /// В конфиге его нет: Config::units подставляет токен ловушки.
    #[serde(skip)]
    pub key_seed: String,
    /// Для класса "plugin": чужая программа, которую агент запускает и слушает.
    #[serde(default)]
    pub plugin: Option<PluginSpec>,
}

/// Плагин — проект пользователя, загруженный в центр. Центр кладёт его файлы
/// в `dir` и описывает, как его запустить.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginSpec {
    /// Имя плагина (как в центре): для журнала и trap_class событий.
    pub slug: String,
    /// Каталог с файлами плагина. Относительный — от каталога конфига.
    pub dir: String,
    /// Команда запуска: argv. Первый элемент с "/" — путь внутри dir, иначе ищется в PATH.
    pub command: Vec<String>,
    /// "service" — программа сама слушает порт; "stdio" — агент слушает порт
    /// и на каждое соединение запускает программу с stdin/stdout = соединение.
    #[serde(default = "default_plugin_mode")]
    pub mode: String,
    /// Транспорт порта для режима service: tcp | udp.
    #[serde(default = "default_plugin_transport")]
    pub transport: String,
}

fn default_plugin_mode() -> String {
    "service".to_string()
}
fn default_plugin_transport() -> String {
    "tcp".to_string()
}

impl TrapConfig {
    /// Рекомендуемый порт по умолчанию для каждого класса ловушек.
    pub fn default_port_for_class(class: &str) -> u16 {
        match class {
            "banner" => 22,
            "dialog" => 21,
            "http" => 80,
            "tarpit" => 80,
            "honeytoken" => 80,
            "udp" => 53,
            "iec104" => 2404,
            "scada" => 502,
            "high_interaction" => 22,
            "low_extra" => 1900,
            "medium_extra" => 6379,
            _ => 0,
        }
    }

    /// Рекомендуемый порт ловушки с учётом конфигурации параметров.
    pub fn default_port(&self) -> u16 {
        if self.class == "medium_extra" {
            let mode = Params(&self.params).str("mode", "auto");
            if mode == "mqtt" {
                return 1883;
            } else if mode == "redis" {
                return 6379;
            }
        }
        Self::default_port_for_class(&self.class)
    }

    /// Фактический порт: если задан явно (ненулевой), возвращается он,
    /// иначе используется рекомендованный порт по умолчанию.
    pub fn effective_port(&self) -> u16 {
        if self.port != 0 {
            self.port
        } else {
            self.default_port()
        }
    }
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

/// Ловушка, готовая к запуску: её описание и настройки отправки событий
/// (корневой конфиг с токеном и ключом именно этой ловушки).
#[derive(Debug, Clone)]
pub struct TrapUnit {
    pub trap: TrapConfig,
    pub sender: Config,
}

impl TrapConfig {
    /// Как называть ловушку в сообщениях: имя из центра или номер и класс.
    pub fn label(&self, idx: usize) -> String {
        if self.name.trim().is_empty() {
            format!("#{} ({})", idx + 1, self.class)
        } else {
            format!("«{}»", self.name.trim())
        }
    }
}

impl Config {
    /// Раскладывает конфиг на ловушки. Проверяет то, без чего агент не сможет
    /// отправить телеметрию: у каждой ловушки есть токен и токены не повторяются.
    pub fn units(&self) -> Result<Vec<TrapUnit>, String> {
        let list: Vec<TrapConfig> = match (&self.trap, self.traps.is_empty()) {
            (Some(_), false) => return Err("в конфиге одновременно trap и traps — оставьте что-то одно".into()),
            (None, true) => return Err("в конфиге нет ловушек (traps пуст)".into()),
            (Some(t), true) => {
                let mut t = t.clone();
                if t.token.is_empty() {
                    t.token = self.token.clone();
                }
                vec![t]
            }
            (None, false) => self.traps.clone(),
        };

        let mut seen = std::collections::HashMap::new();
        let mut out = Vec::with_capacity(list.len());
        for (i, mut trap) in list.into_iter().enumerate() {
            let label = trap.label(i);
            trap.token = trap.token.trim().to_string();
            if trap.token.is_empty() {
                return Err(format!("ловушка {label}: не задан token"));
            }
            if let Some(prev) = seen.insert(trap.token.clone(), label.clone()) {
                return Err(format!("ловушки {prev} и {label}: одинаковый token"));
            }
            if trap.server_pub_key.is_empty() {
                trap.server_pub_key = self.server_pub_key.clone();
            }
            // Ключ хоста SSH должен переживать перезапуск: выводим его из токена ловушки.
            trap.key_seed = trap.token.clone();
            if let Some(p) = trap.plugin.as_mut() {
                let dir = std::path::Path::new(&p.dir);
                if dir.is_relative() {
                    p.dir = self.base_dir.join(dir).to_string_lossy().into_owned();
                }
            }

            let mut sender = self.clone();
            sender.token = trap.token.clone();
            sender.server_pub_key = trap.server_pub_key.clone();
            sender.trap = None;
            sender.traps = Vec::new();
            out.push(TrapUnit { trap, sender });
        }
        Ok(out)
    }

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

    fn parse(v: serde_json::Value) -> Config {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn units_legacy_single_trap_takes_root_token_and_key() {
        let cfg = parse(serde_json::json!({
            "center_url": "http://c:8080",
            "token": "tok-legacy",
            "server_pub_key": "aa",
            "trap": { "class": "banner", "port": 2222 }
        }));
        let units = cfg.units().unwrap();
        assert_eq!(units.len(), 1);
        let u = &units[0];
        assert_eq!(u.trap.token, "tok-legacy");
        assert_eq!(u.trap.server_pub_key, "aa");
        assert_eq!(u.trap.key_seed, "tok-legacy", "ключ хоста SSH выводится из токена");
        assert_eq!(u.sender.token, "tok-legacy");
        assert_eq!(u.sender.server_pub_key, "aa");
        assert_eq!(u.sender.center_url, "http://c:8080");
    }

    #[test]
    fn units_multi_each_trap_sends_with_own_token_and_key() {
        let cfg = parse(serde_json::json!({
            "center_url": "http://c:8080",
            "transport": "udp_burst",
            "jitter_s": 3,
            "server_pub_key": "root-key",
            "traps": [
                { "token": "t1", "server_pub_key": "k1", "name": "SSH", "class": "ssh", "port": 2222 },
                { "token": " t2 ", "class": "banner", "port": 21 }
            ]
        }));
        let units = cfg.units().unwrap();
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].sender.token, "t1");
        assert_eq!(units[0].sender.server_pub_key, "k1");
        assert_eq!(units[0].trap.key_seed, "t1");
        // пробелы вокруг токена отбрасываются; пустой ключ — из корня конфига
        assert_eq!(units[1].sender.token, "t2");
        assert_eq!(units[1].sender.server_pub_key, "root-key");
        // общие настройки доставки наследуются
        for u in &units {
            assert_eq!(u.sender.transport, "udp_burst");
            assert_eq!(u.sender.jitter_s, 3);
            assert!(u.sender.traps.is_empty() && u.sender.trap.is_none());
        }
    }

    #[test]
    fn units_rejects_bad_configs() {
        let cases = [
            (serde_json::json!({ "center_url": "x" }), "нет ловушек"),
            (serde_json::json!({ "center_url": "x", "traps": [] }), "нет ловушек"),
            (
                serde_json::json!({ "center_url": "x", "token": "a",
                    "trap": { "class": "banner" }, "traps": [{ "token": "b", "class": "banner" }] }),
                "одновременно",
            ),
            (serde_json::json!({ "center_url": "x", "trap": { "class": "banner" } }), "не задан token"),
            (
                serde_json::json!({ "center_url": "x", "traps": [{ "name": "FTP", "token": "  ", "class": "dialog" }] }),
                "«FTP»: не задан token",
            ),
            (
                serde_json::json!({ "center_url": "x", "traps": [
                    { "token": "same", "class": "banner" }, { "token": "same", "class": "dialog" }] }),
                "одинаковый token",
            ),
        ];
        for (v, want) in cases {
            let err = parse(v.clone()).units().unwrap_err();
            assert!(err.contains(want), "{v}: ждали «{want}», получили «{err}»");
        }
    }

    #[test]
    fn test_trap_config_default_ports() {
        assert_eq!(TrapConfig::default_port_for_class("banner"), 22);
        assert_eq!(TrapConfig::default_port_for_class("dialog"), 21);
        assert_eq!(TrapConfig::default_port_for_class("http"), 80);
        assert_eq!(TrapConfig::default_port_for_class("iec104"), 2404);
        assert_eq!(TrapConfig::default_port_for_class("scada"), 502);
        assert_eq!(TrapConfig::default_port_for_class("high_interaction"), 22);
        assert_eq!(TrapConfig::default_port_for_class("low_extra"), 1900);
        assert_eq!(TrapConfig::default_port_for_class("medium_extra"), 6379);

        let cfg_mqtt: TrapConfig = serde_json::from_value(serde_json::json!({
            "class": "medium_extra",
            "params": { "mode": "mqtt" }
        })).unwrap();
        assert_eq!(cfg_mqtt.default_port(), 1883);
        assert_eq!(cfg_mqtt.effective_port(), 1883);

        let cfg_custom: TrapConfig = serde_json::from_value(serde_json::json!({
            "class": "iec104",
            "port": 12404
        })).unwrap();
        assert_eq!(cfg_custom.effective_port(), 12404);
    }
}
