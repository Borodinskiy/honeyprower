//! Tarpit: удерживает клиента, отдавая байты по капле. Почти ничего не стоит
//! серверу (одна задача на клиента), но тратит время сканера/брутфорсера.

use crate::config::Params;
use crate::event::now_ts;
use crate::session::Session;
use crate::util::rand_range;
use serde_json::Value;
use tokio::time::{sleep, Duration};

pub struct Tarpit {
    params: Value,
}

impl Tarpit {
    pub fn new(params: &Value) -> Tarpit {
        Tarpit {
            params: params.clone(),
        }
    }

    fn line(&self) -> Vec<u8> {
        let p = Params(&self.params);
        let max_len = p.int("max_line_length", 32).max(3) as u64;
        let n = rand_range(3, max_len) as usize;
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let s: String = (0..n)
            .map(|_| ALPHABET[(rand_range(0, ALPHABET.len() as u64 - 1)) as usize] as char)
            .collect();
        if p.str("mode", "ssh_banner") == "http_headers" {
            format!("X-{}: {}\r\n", &s[..s.len().min(8)], s).into_bytes()
        } else {
            // строки не начинаются с "SSH-", клиент ждёт продолжения (RFC 4253 §4.2)
            format!("{s}\r\n").into_bytes()
        }
    }

    pub async fn handle(&self, s: &mut Session) {
        let p = Params(&self.params);
        let mode = p.str("mode", "ssh_banner");
        let delay = Duration::from_millis(p.int("delay_ms", 10000).max(1) as u64);
        let max_hold = p.float("max_hold_s", 3600.0);
        let end = now_ts() + max_hold;

        if mode == "http_headers" {
            if s.send(b"HTTP/1.1 200 OK\r\n").await.is_err() {
                return;
            }
        }
        while now_ts() < end {
            sleep(delay).await;
            if mode == "silent" {
                continue;
            }
            if s.send(&self.line()).await.is_err() {
                return;
            }
        }
    }
}
