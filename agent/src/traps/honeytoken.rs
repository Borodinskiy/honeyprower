//! Honeytoken: встроенный HTTP-приёмник ссылок-приманок. Переход по
//! уникальной ссылке = событие token.
//!
//! Корреляция учёток-приманок (вход с подставной учёткой в другой ловушке)
//! делается в центре: он видит auth-события всех ловушек, а агент — только
//! свою. Поэтому здесь — только URL-приёмник.

use crate::config::Params;
use crate::event::event_type;
use crate::session::Session;
use serde_json::{json, Value};

pub struct Honeytoken {
    params: Value,
}

impl Honeytoken {
    pub fn new(params: &Value) -> Honeytoken {
        Honeytoken {
            params: params.clone(),
        }
    }

    pub async fn handle(&self, s: &mut Session) {
        let data = match s.read(8192, None).await {
            Ok(d) if !d.is_empty() => d,
            _ => return,
        };
        let text = String::from_utf8_lossy(&data);
        let first_line = text.lines().next().unwrap_or("").to_string();
        let ua = text
            .lines()
            .find(|l| l.to_lowercase().starts_with("user-agent:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();

        let p = Params(&self.params);
        let mut hit: Option<(String, String)> = None; // (token, label)
        for t in p.array("tokens") {
            let kind = t.get("kind").and_then(Value::as_str).unwrap_or("url");
            let token = t.get("token").and_then(Value::as_str).unwrap_or("");
            if kind == "url" && !token.is_empty() && first_line.contains(token) {
                let label = t.get("label").and_then(Value::as_str).unwrap_or("").to_string();
                hit = Some((token.to_string(), label));
            }
        }

        if let Some((token, label)) = hit {
            s.emit_data(
                event_type::TOKEN,
                json!({
                    "token": token,
                    "label": label,
                    "kind": "url",
                    "request": truncate(&first_line, 300),
                    "user_agent": ua,
                }),
            );
        } else {
            s.emit_data(
                event_type::REQUEST,
                json!({ "request": truncate(&first_line, 300), "user_agent": ua }),
            );
        }

        let body = p.str("response_body", "<html><body></body></html>");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = s.send(resp.as_bytes()).await;
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
