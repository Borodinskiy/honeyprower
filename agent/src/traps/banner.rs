//! Баннерная ловушка: сервер говорит первым (баннер), затем логирует ввод.
//! Для любого протокола, где сервер шлёт приветствие (SSH, FTP, SMTP, POP3).

use crate::config::Params;
use crate::session::Session;
use crate::util::{hex_prefix, parse_hex, render, safe_text};
use serde_json::{json, Value};

pub struct Banner {
    params: Value,
}

impl Banner {
    pub fn new(params: &Value) -> Banner {
        Banner {
            params: params.clone(),
        }
    }

    pub async fn handle(&self, s: &mut Session) {
        let p = Params(&self.params);
        super::delay(&self.params).await;

        let banner_hex = p.str("banner_hex", "");
        let out = if !banner_hex.is_empty() {
            parse_hex(&banner_hex)
        } else {
            render(&p.str("banner", "220 {hostname} ready\\r\\n"), &s.ctx())
        };
        if s.send(&out).await.is_err() {
            return;
        }

        let limit = p.int("max_session_bytes", 65536) as u64;
        let after = p.str("after_input", "");
        let close_after = p.bool("close_after_input", false);
        while s.bytes_in < limit {
            let data = match s.read(4096, None).await {
                Ok(d) if !d.is_empty() => d,
                _ => return,
            };
            s.emit_data(
                "data",
                json!({
                    "text": safe_text(&data, 2048),
                    "hex": hex_prefix(&data, 256),
                    "len": data.len(),
                }),
            );
            if !after.is_empty() {
                super::delay(&self.params).await;
                let resp = render(&after, &s.ctx());
                let _ = s.send(&resp).await;
            }
            if close_after {
                return;
            }
        }
    }
}
