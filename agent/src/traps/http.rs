//! HTTP-приманка: мини-сервер на правилах-маршрутах (regex пути + метод).
//! Ловит логины из форм, JSON и HTTP Basic, пишет каждый запрос.

use crate::config::Params;
use crate::event::event_type;
use crate::session::Session;
use crate::util::render;
use base64::Engine;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;

struct Route {
    re: Regex,
    method: String,
    status: u16,
    content_type: String,
    headers: String,
    body: String,
    capture_login: bool,
    tag: String,
}

pub struct HttpDecoy {
    params: Value,
    routes: Vec<Route>,
}

struct Request {
    method: String,
    path: String,
    query: String,
    version: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

impl HttpDecoy {
    pub fn new(params: &Value) -> Result<HttpDecoy, String> {
        let p = Params(params);
        let mut routes = Vec::new();
        for r in p.array("routes") {
            let path = r.get("path").and_then(Value::as_str).unwrap_or("^/$");
            let re = match Regex::new(path) {
                Ok(re) => re,
                Err(_) => continue,
            };
            routes.push(Route {
                re,
                method: r.get("method").and_then(Value::as_str).unwrap_or("*").to_string(),
                status: r.get("status").and_then(Value::as_u64).unwrap_or(200) as u16,
                content_type: r
                    .get("content_type")
                    .and_then(Value::as_str)
                    .unwrap_or("text/html; charset=UTF-8")
                    .to_string(),
                headers: r.get("headers").and_then(Value::as_str).unwrap_or("").to_string(),
                body: r.get("body").and_then(Value::as_str).unwrap_or("").to_string(),
                capture_login: r.get("capture_login").and_then(Value::as_bool).unwrap_or(false),
                tag: r.get("tag").and_then(Value::as_str).unwrap_or("").to_string(),
            });
        }
        Ok(HttpDecoy {
            params: params.clone(),
            routes,
        })
    }

    pub async fn handle(&self, s: &mut Session) {
        for _ in 0..50 {
            let req = match self.read_request(s).await {
                Some(r) => r,
                None => return,
            };
            self.serve(s, &req).await;
            let conn = req.headers.get("connection").map(String::as_str).unwrap_or("");
            if conn.eq_ignore_ascii_case("close") || req.version == "HTTP/1.0" {
                return;
            }
        }
    }

    async fn read_request(&self, s: &mut Session) -> Option<Request> {
        let max_bytes = Params(&self.params).int("max_session_bytes", 65536) as usize;
        let mut head = Vec::new();
        loop {
            if find(&head, b"\r\n\r\n").is_some() || find(&head, b"\n\n").is_some() {
                break;
            }
            let chunk = s.read(4096, None).await.ok()?;
            if chunk.is_empty() {
                return None;
            }
            head.extend_from_slice(&chunk);
            if head.len() > 32768 {
                break;
            }
        }
        let sep_len = if let Some(pos) = find(&head, b"\r\n\r\n") {
            (pos, 4)
        } else {
            (find(&head, b"\n\n")?, 2)
        };
        let (raw_head, _) = head.split_at(sep_len.0);
        let mut body = head[sep_len.0 + sep_len.1..].to_vec();

        let head_str = String::from_utf8_lossy(raw_head);
        let mut lines = head_str.split('\n');
        let first = lines.next()?.trim_end_matches('\r');
        let parts: Vec<&str> = first.split(' ').collect();
        if parts.len() < 2 {
            s.emit_data(event_type::DATA, json!({ "text": truncate(first, 300) }));
            return None;
        }
        let method = parts[0].to_string();
        let target = parts[1].to_string();
        let version = parts.get(2).copied().unwrap_or("HTTP/0.9").to_string();
        let mut headers = HashMap::new();
        for ln in lines {
            let ln = ln.trim_end_matches('\r');
            if let Some((k, v)) = ln.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        let clen: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let clen = clen.min(max_bytes);
        while body.len() < clen {
            let chunk = s.read(65536.min(clen - body.len()), None).await.ok()?;
            if chunk.is_empty() {
                break;
            }
            body.extend_from_slice(&chunk);
        }
        body.truncate(clen);

        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };
        Some(Request {
            method,
            path: if path.is_empty() { "/".into() } else { path },
            query,
            version,
            headers,
            body,
        })
    }

    async fn serve(&self, s: &mut Session, req: &Request) {
        let body_text = String::from_utf8_lossy(&req.body[..req.body.len().min(4096)]).into_owned();
        let mut info = json!({
            "method": req.method,
            "path": req.path,
            "query": req.query,
            "version": req.version,
            "host": req.headers.get("host").cloned().unwrap_or_default(),
            "user_agent": req.headers.get("user-agent").cloned().unwrap_or_default(),
            "body": body_text,
        });

        let mut ctx = s.ctx();
        ctx.insert("path".into(), req.path.clone());
        ctx.insert("method".into(), req.method.clone());

        // HTTP Basic: если включён — любой путь требует авторизации, учётки логируются.
        let realm = Params(&self.params).str("basic_auth_realm", "");
        if !realm.is_empty() {
            if let Some(auth) = req.headers.get("authorization") {
                if let Some(rest) = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic ")) {
                    if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                        let txt = String::from_utf8_lossy(&dec);
                        let (u, pw) = txt.split_once(':').unwrap_or((txt.as_ref(), ""));
                        s.emit(
                            s.event(event_type::AUTH)
                                .username(Some(u.to_string()))
                                .password(Some(pw.to_string()))
                                .data(json!({ "kind": "http_basic", "path": req.path })),
                        );
                    }
                }
            }
            s.emit_data(event_type::REQUEST, info);
            super::delay(&self.params).await;
            let resp = self.response(
                401,
                "<h1>401 Unauthorized</h1>",
                "text/html",
                &format!("WWW-Authenticate: Basic realm=\"{realm}\""),
                s,
            );
            let _ = s.send(&resp).await;
            return;
        }

        for route in &self.routes {
            if route.method != "*" && !route.method.is_empty() && route.method != req.method {
                continue;
            }
            if !route.re.is_match(&req.path) {
                continue;
            }
            if !route.tag.is_empty() {
                info["tag"] = json!(route.tag);
            }
            s.emit_data(event_type::REQUEST, info.clone());
            if route.capture_login && (!req.body.is_empty() || !req.query.is_empty()) {
                let (user, pw) = self.creds_from_body(req);
                if user.is_some() || pw.is_some() {
                    s.emit(
                        s.event(event_type::AUTH)
                            .username(user.clone())
                            .password(pw)
                            .data(json!({ "kind": "http_form", "path": req.path })),
                    );
                    let u = user.unwrap_or_default();
                    s.vars.insert("username".into(), u.clone());
                    ctx.insert("username".into(), u);
                }
            }
            super::delay(&self.params).await;
            let body = render(&route.body, &ctx);
            let resp = self.response_bytes(route.status, &body, &route.content_type, &route.headers, s);
            let _ = s.send(&resp).await;
            return;
        }

        s.emit_data(event_type::REQUEST, info);
        super::delay(&self.params).await;
        let not_found = Params(&self.params).str("not_found_body", "<h1>Not Found</h1>");
        let body = render(&not_found, &ctx);
        let resp = self.response_bytes(404, &body, "text/html; charset=iso-8859-1", "", s);
        let _ = s.send(&resp).await;
    }

    fn creds_from_body(&self, req: &Request) -> (Option<String>, Option<String>) {
        let p = Params(&self.params);
        let ufields: Vec<String> = p
            .str("user_fields", "username,user,login,email,log,uname,name")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect();
        let pfields: Vec<String> = p
            .str("pass_fields", "password,pass,pwd,passwd,secret")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect();
        let mut data: HashMap<String, String> = HashMap::new();
        let ctype = req.headers.get("content-type").cloned().unwrap_or_default();
        let body = String::from_utf8_lossy(&req.body);
        if ctype.contains("json") {
            if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&body) {
                for (k, v) in obj {
                    let val = match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    data.insert(k.to_lowercase(), val);
                }
            }
        } else {
            for (k, v) in parse_form(&body) {
                data.insert(k.to_lowercase(), v);
            }
        }
        for (k, v) in parse_form(&req.query) {
            data.entry(k.to_lowercase()).or_insert(v);
        }
        let user = ufields.iter().find_map(|f| data.get(f).cloned());
        let pw = pfields.iter().find_map(|f| data.get(f).cloned());
        (user, pw)
    }

    fn response(&self, status: u16, body: &str, ctype: &str, extra: &str, s: &Session) -> Vec<u8> {
        self.response_bytes(status, body.as_bytes(), ctype, extra, s)
    }

    fn response_bytes(&self, status: u16, body: &[u8], ctype: &str, headers_txt: &str, s: &Session) -> Vec<u8> {
        let p = Params(&self.params);
        let mut hdr = vec![
            format!("HTTP/1.1 {status} {}", reason(status)),
            format!("Date: {}", s.ctx().get("date").cloned().unwrap_or_default()),
        ];
        let server = p.str("server_header", "Apache/2.4.58 (Ubuntu)");
        if !server.is_empty() {
            hdr.push(format!("Server: {server}"));
        }
        for block in [p.str("extra_headers", ""), headers_txt.to_string()] {
            for ln in block.replace("\\n", "\n").lines() {
                if ln.contains(':') {
                    let rendered = render(ln.trim(), &s.ctx());
                    hdr.push(String::from_utf8_lossy(&rendered).into_owned());
                }
            }
        }
        hdr.push(format!("Content-Length: {}", body.len()));
        hdr.push(format!("Content-Type: {ctype}"));
        hdr.push("Connection: keep-alive".to_string());
        let mut out = (hdr.join("\r\n") + "\r\n\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Разбор application/x-www-form-urlencoded и query-строки.
fn parse_form(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((url_decode(k), url_decode(v)));
    }
    out
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
