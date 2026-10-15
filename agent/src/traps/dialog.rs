//! Диалоговый автомат: приветствие + правила «состояние + regex -> ответ,
//! захват полей, переход». Собирает FTP, SMTP, POP3, IMAP, Telnet, Redis,
//! Memcached и другие построчные протоколы без кода.

use crate::config::Params;
use crate::event::event_type;
use crate::session::Session;
use crate::util::render;
use base64::Engine;
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use std::collections::HashMap;

struct Rule {
    re: Regex,
    response: String,
    state: String,
    capture: String,
    decode: String,
    next_state: String,
    log: bool,
    close: bool,
}

pub struct Dialog {
    params: Value,
    rules: Vec<Rule>,
}

#[derive(PartialEq)]
enum Decoder {
    Line,
    Telnet,
    Resp,
}

const IAC: u8 = 0xFF;

impl Dialog {
    pub fn new(params: &Value) -> Result<Dialog, String> {
        let p = Params(params);
        let mut rules = Vec::new();
        for r in p.array("rules") {
            let pat = r.get("match").and_then(Value::as_str).unwrap_or(".*");
            let re = match RegexBuilder::new(pat)
                .case_insensitive(true)
                .dot_matches_new_line(true)
                .build()
            {
                Ok(re) => re,
                Err(_) => continue, // кривое правило пропускаем, ловушка живёт
            };
            rules.push(Rule {
                re,
                response: r.get("response").and_then(Value::as_str).unwrap_or("").to_string(),
                state: r.get("state").and_then(Value::as_str).unwrap_or("*").to_string(),
                capture: r.get("capture").and_then(Value::as_str).unwrap_or("").to_string(),
                decode: r.get("decode").and_then(Value::as_str).unwrap_or("").to_string(),
                next_state: r.get("next_state").and_then(Value::as_str).unwrap_or("").to_string(),
                log: r.get("log").and_then(Value::as_bool).unwrap_or(true),
                close: r.get("close").and_then(Value::as_bool).unwrap_or(false),
            });
        }
        Ok(Dialog {
            params: params.clone(),
            rules,
        })
    }

    fn decoder(&self) -> Decoder {
        match Params(&self.params).str("decoder", "line").as_str() {
            "telnet" => Decoder::Telnet,
            "resp" => Decoder::Resp,
            _ => Decoder::Line,
        }
    }

    /// (значение, пароль-если-есть) с учётом base64 / SASL PLAIN.
    fn decode_capture(value: &str, how: &str) -> (String, Option<String>) {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let padded = value.trim_end_matches('=');
        match how {
            "base64" => b64
                .decode(padded)
                .ok()
                .map(|b| (String::from_utf8_lossy(&b).into_owned(), None))
                .unwrap_or_else(|| (value.to_string(), None)),
            "sasl_plain" => {
                if let Ok(b) = b64.decode(padded) {
                    let txt = String::from_utf8_lossy(&b);
                    let parts: Vec<&str> = txt.split('\0').collect();
                    if parts.len() >= 3 {
                        return (parts[1].to_string(), Some(parts[2].to_string()));
                    }
                }
                (value.to_string(), None)
            }
            _ => (value.to_string(), None),
        }
    }

    pub async fn handle(&self, s: &mut Session) {
        let p = Params(&self.params);
        let mut state = p.str("initial_state", "start");
        let max_commands = p.int("max_commands", 100);
        let max_bytes = p.int("max_session_bytes", 65536) as u64;
        let default_response = p.str("default_response", "");
        let decoder = self.decoder();

        let greeting = p.str("greeting", "");
        if !greeting.is_empty() {
            super::delay(&self.params).await;
            if s.send(&render(&greeting, &s.ctx())).await.is_err() {
                return;
            }
        }

        let mut buf: Vec<u8> = Vec::new();
        let mut count = 0i64;
        loop {
            if s.bytes_in >= max_bytes {
                return;
            }
            let chunk = match s.read(4096, None).await {
                Ok(c) if !c.is_empty() => c,
                _ => return,
            };
            buf.extend_from_slice(&chunk);

            if decoder == Decoder::Telnet {
                let (clean, opts) = strip_telnet(&buf);
                buf = clean;
                if !opts.is_empty() {
                    s.emit_data(event_type::HANDSHAKE, json!({ "telnet_options": opts }));
                }
            }

            let lines = extract_lines(&mut buf, &decoder);
            for line in lines {
                count += 1;
                if count > max_commands {
                    return;
                }
                if self.process_line(s, &line, &mut state, &default_response).await {
                    return; // правило закрыло соединение
                }
            }
        }
    }

    /// Возвращает true, если нужно закрыть соединение.
    async fn process_line(
        &self,
        s: &mut Session,
        line: &str,
        state: &mut String,
        default_response: &str,
    ) -> bool {
        let mut matched: Option<&Rule> = None;
        let mut caps_groups: Vec<String> = Vec::new();
        let mut caps_named: HashMap<String, String> = HashMap::new();

        for rule in &self.rules {
            if rule.state != "*" && !rule.state.is_empty() && rule.state != *state {
                continue;
            }
            if let Some(c) = rule.re.captures(line) {
                caps_groups = c.iter().map(|m| m.map(|x| x.as_str().to_string()).unwrap_or_default()).collect();
                for name in rule.re.capture_names().flatten() {
                    if let Some(m) = c.name(name) {
                        caps_named.insert(name.to_string(), m.as_str().to_string());
                    }
                }
                matched = Some(rule);
                break;
            }
        }

        let ctx_extra = |groups: &[String], named: &HashMap<String, String>| {
            let mut m = HashMap::new();
            for (i, g) in groups.iter().enumerate() {
                m.insert(i.to_string(), g.clone());
            }
            for (k, v) in named {
                m.insert(k.clone(), v.clone());
            }
            m
        };

        let rule = match matched {
            None => {
                if !line.trim().is_empty() {
                    s.emit_data(
                        event_type::COMMAND,
                        json!({ "line": truncate(line, 1000), "state": state.clone(), "matched": false }),
                    );
                }
                super::delay(&self.params).await;
                let _ = s.send(&render(default_response, &s.ctx())).await;
                return false;
            }
            Some(r) => r,
        };

        let group = |i: usize| caps_groups.get(i).cloned().unwrap_or_default();
        let u_raw = caps_named.get("user").cloned().unwrap_or_else(|| group(1));
        let p_raw = caps_named.get("pass").cloned().unwrap_or_else(|| {
            group(if rule.capture == "username_password" { 2 } else { 1 })
        });

        match rule.capture.as_str() {
            "username" => {
                let (user, pw) = Self::decode_capture(&u_raw, &rule.decode);
                s.vars.insert("username".into(), user.clone());
                if let Some(pw) = pw {
                    s.emit(
                        s.event(event_type::AUTH)
                            .username(Some(user))
                            .password(Some(pw))
                            .data(json!({ "state": state.clone() })),
                    );
                }
            }
            "password" => {
                let (pw, _) = Self::decode_capture(&p_raw, &rule.decode);
                let user = s.vars.get("username").cloned();
                s.emit(
                    s.event(event_type::AUTH)
                        .username(user)
                        .password(Some(pw))
                        .data(json!({ "state": state.clone() })),
                );
            }
            "username_password" => {
                let user = Self::decode_capture(&u_raw, &rule.decode).0;
                let pw = Self::decode_capture(&p_raw, &rule.decode).0;
                s.vars.insert("username".into(), user.clone());
                s.emit(
                    s.event(event_type::AUTH)
                        .username(Some(user))
                        .password(Some(pw))
                        .data(json!({ "state": state.clone() })),
                );
            }
            _ => {}
        }

        if rule.log && rule.capture != "password" && rule.capture != "username_password" {
            s.emit_data(
                event_type::COMMAND,
                json!({ "line": truncate(line, 1000), "state": state.clone(), "matched": true }),
            );
        }

        let mut ctx = s.ctx();
        ctx.extend(ctx_extra(&caps_groups, &caps_named));
        super::delay(&self.params).await;
        let _ = s.send(&render(&rule.response, &ctx)).await;

        if !rule.next_state.is_empty() {
            *state = rule.next_state.clone();
        }
        rule.close
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Убирает telnet-согласование (IAC ...) из потока. Возвращает чистые байты и опции.
fn strip_telnet(buf: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::with_capacity(buf.len());
    let mut opts = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let b = buf[i];
        if b == IAC && i + 1 < buf.len() {
            let cmd = buf[i + 1];
            match cmd {
                0xFB | 0xFC | 0xFD | 0xFE if i + 2 < buf.len() => {
                    let name = match cmd {
                        0xFB => "WILL",
                        0xFC => "WONT",
                        0xFD => "DO",
                        _ => "DONT",
                    };
                    opts.push(format!("{name} {}", buf[i + 2]));
                    i += 3;
                    continue;
                }
                0xFA => {
                    // SB ... IAC SE
                    if let Some(pos) = find_subslice(&buf[i..], &[IAC, 0xF0]) {
                        i += pos + 2;
                    } else {
                        i = buf.len();
                    }
                    continue;
                }
                IAC => {
                    out.push(IAC);
                    i += 2;
                    continue;
                }
                _ => {
                    i += 2;
                    continue;
                }
            }
        }
        out.push(b);
        i += 1;
    }
    (out, opts)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Достаёт готовые «строки» из буфера согласно декодеру; потреблённое удаляет из buf.
fn extract_lines(buf: &mut Vec<u8>, decoder: &Decoder) -> Vec<String> {
    let mut lines = Vec::new();
    if *decoder == Decoder::Resp {
        loop {
            match parse_resp(buf) {
                Some((args, used)) => {
                    buf.drain(..used);
                    if !args.is_empty() {
                        lines.push(args.join(" "));
                    }
                }
                None => break,
            }
        }
        return lines;
    }
    // line / telnet: режем по \r\n, \n, \r
    loop {
        let pos = buf
            .iter()
            .position(|&b| b == b'\n' || b == b'\r');
        let Some(p) = pos else { break };
        let line: Vec<u8> = buf[..p].to_vec();
        // съесть разделитель (\r\n считается одним)
        let mut end = p + 1;
        if buf[p] == b'\r' && end < buf.len() && buf[end] == b'\n' {
            end += 1;
        }
        buf.drain(..end);
        lines.push(String::from_utf8_lossy(&line).into_owned());
    }
    lines
}

/// Разбор одной команды Redis RESP (*N $len ...). Возвращает (аргументы, длина) или None.
fn parse_resp(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] != b'*' {
        // инлайн-команда до \n
        let nl = buf.iter().position(|&b| b == b'\n')?;
        let line = String::from_utf8_lossy(&buf[..nl]);
        let args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        return Some((args, nl + 1));
    }
    let crlf = find_subslice(buf, b"\r\n")?;
    let n: usize = std::str::from_utf8(&buf[1..crlf]).ok()?.parse().ok()?;
    let mut pos = crlf + 2;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        if pos >= buf.len() || buf[pos] != b'$' {
            return None;
        }
        let crlf = find_subslice(&buf[pos..], b"\r\n")? + pos;
        let len: usize = std::str::from_utf8(&buf[pos + 1..crlf]).ok()?.parse().ok()?;
        let start = crlf + 2;
        if buf.len() < start + len + 2 {
            return None;
        }
        args.push(String::from_utf8_lossy(&buf[start..start + len]).into_owned());
        pos = start + len + 2;
    }
    Some((args, pos))
}
