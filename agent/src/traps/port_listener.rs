//! Слушатель портов: фиксирует подключение и первые байты. Встроен детектор
//! сканирования: один источник коснулся N разных портов за окно -> событие scan.

use crate::config::Params;
use crate::event::{event_type, now_ts};
use crate::session::Session;
use crate::util::{hex_prefix, safe_text};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct PortListener {
    params: Value,
    // src_ip -> список (время, порт); reported: src_ip -> время последнего scan-события.
    hits: Mutex<HashMap<String, Vec<(f64, u16)>>>,
    reported: Mutex<HashMap<String, f64>>,
}

impl PortListener {
    pub fn new(params: &Value) -> PortListener {
        PortListener {
            params: params.clone(),
            hits: Mutex::new(HashMap::new()),
            reported: Mutex::new(HashMap::new()),
        }
    }

    fn scan_check(&self, s: &Session) {
        let p = Params(&self.params);
        let now = now_ts();
        let win = p.float("scan_window_s", 60.0);
        let threshold = p.int("scan_threshold", 3) as usize;

        let mut hits = self.hits.lock().unwrap();
        let entry = hits.entry(s.src_ip.clone()).or_default();
        entry.retain(|(t, _)| now - t < win);
        entry.push((now, s.dst_port));
        let mut ports: Vec<u16> = entry.iter().map(|(_, p)| *p).collect();
        ports.sort_unstable();
        ports.dedup();

        if ports.len() >= threshold {
            let mut reported = self.reported.lock().unwrap();
            let last = reported.get(&s.src_ip).copied().unwrap_or(0.0);
            if now - last > win {
                reported.insert(s.src_ip.clone(), now);
                s.emit_data(event_type::SCAN, json!({ "ports": ports, "window_s": win }));
            }
        }
    }

    pub async fn handle(&self, s: &mut Session) {
        self.scan_check(s);
        let p = Params(&self.params);
        match p.str("action", "read_then_close").as_str() {
            "close" => {}
            "hold" => {
                // держим до таймаута простоя, молча читая
                while let Ok(d) = s.read(4096, None).await {
                    if d.is_empty() {
                        break;
                    }
                }
            }
            _ => {
                let win = p.float("read_window_s", 3.0);
                if let Ok(data) = s.read(4096, Some(win)).await {
                    if !data.is_empty() {
                        s.emit_data(
                            "data",
                            json!({
                                "text": safe_text(&data, 2048),
                                "hex": hex_prefix(&data, 256),
                                "len": data.len(),
                            }),
                        );
                    }
                }
            }
        }
    }
}
