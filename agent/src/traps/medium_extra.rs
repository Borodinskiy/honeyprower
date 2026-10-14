//! Extended Medium-Interaction Traps (Database handshakes, industrial telemetry, network services).

use crate::config::Params;
use crate::event::{event_type, Event};
use crate::session::Session;
use serde_json::{json, Value};

/// Extended Medium-Interaction Honeypot Trap.
/// Supports Database Wire Protocol Handshake (Redis) and Industrial MQTT Telemetry (port 1883).
pub struct MediumExtraTrap {
    params: Value,
    mode: String,
    redis_version: String,
}

impl MediumExtraTrap {
    pub fn new(params: &Value) -> Result<Self, String> {
        let p = Params(params);
        let mode = p.str("mode", "auto");
        let redis_version = p.str("redis_version", "7.0.12");
        Ok(Self {
            params: params.clone(),
            mode,
            redis_version,
        })
    }

    // -------------------------------------------------------------------------
    // Redis Wire Protocol Support
    // -------------------------------------------------------------------------

    /// Parses incoming Redis commands (both RESP arrays and inline text format).
    pub fn parse_redis_commands(data: &[u8]) -> Vec<Vec<String>> {
        let mut commands = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            while pos < data.len()
                && (data[pos] == b' ' || data[pos] == b'\r' || data[pos] == b'\n' || data[pos] == b'\t')
            {
                pos += 1;
            }
            if pos >= data.len() {
                break;
            }
            if data[pos] == b'*' {
                if let Some((cmd, advanced)) = Self::parse_resp_command(&data[pos..]) {
                    commands.push(cmd);
                    pos += advanced;
                    continue;
                }
            }
            // Fallback to inline command (line-based)
            let end = data[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| pos + p)
                .unwrap_or(data.len());
            let line_slice = &data[pos..end];
            let line = String::from_utf8_lossy(line_slice);
            let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
            if !parts.is_empty() {
                commands.push(parts);
            }
            pos = end + 1;
        }
        commands
    }

    fn parse_resp_command(data: &[u8]) -> Option<(Vec<String>, usize)> {
        if data.is_empty() || data[0] != b'*' {
            return None;
        }
        let mut pos = 1;
        let nl = data[pos..].iter().position(|&b| b == b'\n')?;
        let count_str = std::str::from_utf8(&data[pos..pos + nl]).ok()?.trim();
        let count: usize = count_str.parse().ok()?;
        pos += nl + 1;

        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            if pos >= data.len() || data[pos] != b'$' {
                return None;
            }
            pos += 1;
            let arg_nl = data[pos..].iter().position(|&b| b == b'\n')?;
            let len_str = std::str::from_utf8(&data[pos..pos + arg_nl]).ok()?.trim();
            let arg_len: usize = len_str.parse().ok()?;
            pos += arg_nl + 1;

            if pos + arg_len > data.len() {
                return None;
            }
            let arg = String::from_utf8_lossy(&data[pos..pos + arg_len]).to_string();
            args.push(arg);
            pos += arg_len;
            if pos < data.len() && data[pos] == b'\r' {
                pos += 1;
            }
            if pos < data.len() && data[pos] == b'\n' {
                pos += 1;
            }
        }
        Some((args, pos))
    }

    /// Evaluates a single Redis command, generating the protocol response and event.
    pub fn eval_redis_command(
        &self,
        args: &[String],
        src_ip: &str,
        src_port: u16,
        dst_port: u16,
        session_id: &str,
    ) -> (String, Event) {
        let cmd = args[0].to_uppercase();
        match cmd.as_str() {
            "PING" => {
                let resp = "+PONG\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "PING",
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            "AUTH" => {
                let expected_pass = Params(&self.params).str("requirepass", "");
                let (user, pass) = if args.len() >= 3 {
                    (Some(args[1].clone()), args[2].clone())
                } else if args.len() >= 2 {
                    (None, args[1].clone())
                } else {
                    (None, String::new())
                };

                let mut ev = Event::new("medium_extra", event_type::AUTH)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .password(Some(pass.clone()));
                if let Some(ref u) = user {
                    ev = ev.username(Some(u.clone()));
                }
                ev = ev.data(json!({
                    "proto": "redis",
                    "command": "AUTH",
                    "username": user,
                    "password": pass,
                }));
                let resp = if !expected_pass.is_empty() && pass != expected_pass {
                    "-ERR invalid password\r\n".to_string()
                } else {
                    "+OK\r\n".to_string()
                };
                (resp, ev)
            }
            "INFO" => {
                let info_body = format!(
                    "# Server\r\nredis_version:{}\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:9f977d0cf0c41d5d\r\nredis_mode:standalone\r\nos:Linux 5.15.0-76-generic x86_64\r\narch_bits:64\r\nmultiplexing_api:epoll\r\nprocess_id:1024\r\nrun_id:d8f787b409db89a9e2d3bb421a1bc3ef4190cb61\r\ntcp_port:6379\r\nuptime_in_seconds:86400\r\nuptime_in_days:1\r\n# Clients\r\nconnected_clients:1\r\n# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\n# Persistence\r\nrdb_last_bgsave_status:ok\r\n# Stats\r\ntotal_connections_received:10\r\ntotal_commands_processed:42\r\n# Replication\r\nrole:master\r\nconnected_slaves:0\r\n",
                    self.redis_version
                );
                let resp = format!("${}\r\n{}\r\n", info_body.len(), info_body);
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "INFO",
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            "CONFIG" => {
                let subcmd = args.get(1).map(|s| s.to_uppercase()).unwrap_or_default();
                let param = args.get(2).map(|s| s.as_str()).unwrap_or("*");
                let resp = if subcmd == "GET" {
                    if param == "*" {
                        let items = [
                            ("maxclients", "10000"),
                            ("save", "3600 1 300 100 60 10000"),
                            ("appendonly", "no"),
                            ("dir", "/var/lib/redis"),
                            ("dbfilename", "dump.rdb"),
                            ("requirepass", ""),
                        ];
                        let mut out = format!("*{}\r\n", items.len() * 2);
                        for (k, v) in items {
                            out.push_str(&format!(
                                "${}\r\n{}\r\n${}\r\n{}\r\n",
                                k.len(),
                                k,
                                v.len(),
                                v
                            ));
                        }
                        out
                    } else {
                        format!("*2\r\n${}\r\n{}\r\n$5\r\n10000\r\n", param.len(), param)
                    }
                } else {
                    "+OK\r\n".to_string()
                };
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "CONFIG",
                        "subcommand": subcmd,
                        "args": &args[1..],
                        "raw": args.join(" "),
                    }));
                (resp, ev)
            }
            "SET" => {
                let key = args.get(1).cloned().unwrap_or_default();
                let val = args.get(2).cloned().unwrap_or_default();
                let resp = "+OK\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "SET",
                        "key": key,
                        "value": val,
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            "GET" => {
                let key = args.get(1).cloned().unwrap_or_default();
                let resp = "$-1\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "GET",
                        "key": key,
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            "SLAVEOF" | "REPLICAOF" => {
                let host = args.get(1).cloned().unwrap_or_default();
                let port = args.get(2).cloned().unwrap_or_default();
                let resp = "+OK\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": cmd,
                        "host": host,
                        "port": port,
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            "QUIT" => {
                let resp = "+OK\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": "QUIT",
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
            _ => {
                let resp = "+OK\r\n".to_string();
                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "redis",
                        "command": cmd,
                        "args": &args[1..],
                    }));
                (resp, ev)
            }
        }
    }

    async fn handle_redis_loop(&self, s: &mut Session, mut buffer: Vec<u8>) {
        loop {
            if buffer.is_empty() {
                buffer = match s.read(4096, None).await {
                    Ok(b) if !b.is_empty() => b,
                    _ => break,
                };
            }
            let commands = Self::parse_redis_commands(&buffer);
            buffer.clear();
            if commands.is_empty() {
                break;
            }
            let mut should_quit = false;
            for cmd_args in commands {
                if cmd_args.is_empty() {
                    continue;
                }
                let is_quit = cmd_args[0].eq_ignore_ascii_case("QUIT");
                let (resp, ev) =
                    self.eval_redis_command(&cmd_args, &s.src_ip, s.src_port, s.dst_port, &s.id);
                let _ = s.send(resp.as_bytes()).await;
                s.emit(ev);
                if is_quit {
                    should_quit = true;
                    break;
                }
            }
            if should_quit {
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Industrial MQTT Telemetry Support (Port 1883)
    // -------------------------------------------------------------------------

    pub fn decode_var_int(data: &[u8]) -> Option<(usize, usize)> {
        let mut multiplier: usize = 1;
        let mut value: usize = 0;
        let mut bytes_read = 0;
        for &b in data {
            value += ((b & 0x7F) as usize) * multiplier;
            multiplier *= 128;
            bytes_read += 1;
            if (b & 0x80) == 0 {
                return Some((value, bytes_read));
            }
            if bytes_read >= 4 {
                return None;
            }
        }
        None
    }

    pub fn encode_var_int(mut len: usize, out: &mut Vec<u8>) {
        loop {
            let mut byte = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if len == 0 {
                break;
            }
        }
    }

    /// Reads one full MQTT packet from the buffer: returns (header_byte, payload, total_packet_bytes).
    pub fn read_mqtt_packet(data: &[u8]) -> Option<(u8, &[u8], usize)> {
        if data.is_empty() {
            return None;
        }
        let header_byte = data[0];
        let (rem_len, bytes_read) = Self::decode_var_int(&data[1..])?;
        let total_len = 1 + bytes_read + rem_len;
        if data.len() < total_len {
            return None;
        }
        let payload = &data[1 + bytes_read..total_len];
        Some((header_byte, payload, total_len))
    }

    /// Evaluates an MQTT packet, returning optional (response_bytes, event, should_disconnect).
    pub fn eval_mqtt_packet(
        &self,
        header_byte: u8,
        payload: &[u8],
        src_ip: &str,
        src_port: u16,
        dst_port: u16,
        session_id: &str,
    ) -> (Option<Vec<u8>>, Option<Event>, bool) {
        let packet_type = header_byte >> 4;
        match packet_type {
            1 => {
                // CONNECT (0x10)
                if payload.len() < 4 {
                    return (Some(vec![0x20, 0x02, 0x00, 0x00]), None, false);
                }
                let proto_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                let mut pos = 2;
                let proto_name = if pos + proto_len <= payload.len() {
                    let name = String::from_utf8_lossy(&payload[pos..pos + proto_len]).to_string();
                    pos += proto_len;
                    name
                } else {
                    "MQTT".to_string()
                };

                let proto_level = if pos < payload.len() {
                    let lvl = payload[pos];
                    pos += 1;
                    lvl
                } else {
                    4
                };

                let flags = if pos < payload.len() {
                    let fl = payload[pos];
                    pos += 1;
                    fl
                } else {
                    0
                };

                let has_user = (flags & 0x80) != 0;
                let has_pass = (flags & 0x40) != 0;
                let will_flag = (flags & 0x04) != 0;
                let clean_session = (flags & 0x02) != 0;

                // Keepalive: 2 bytes
                pos += 2;

                // If MQTT 5 (level 5), parse properties length and skip
                if proto_level == 5 && pos < payload.len() {
                    if let Some((prop_len, read_b)) = Self::decode_var_int(&payload[pos..]) {
                        pos += read_b + prop_len;
                    }
                }

                // Payload: client_id
                let client_id = if pos + 2 <= payload.len() {
                    let cid_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2;
                    if pos + cid_len <= payload.len() {
                        let cid =
                            String::from_utf8_lossy(&payload[pos..pos + cid_len]).to_string();
                        pos += cid_len;
                        cid
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                // Will topic and payload
                if will_flag && pos + 2 <= payload.len() {
                    let wt_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2 + wt_len;
                    if pos + 2 <= payload.len() {
                        let wp_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                        pos += 2 + wp_len;
                    }
                }

                // Username
                let username = if has_user && pos + 2 <= payload.len() {
                    let ulen = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2;
                    if pos + ulen <= payload.len() {
                        let u = String::from_utf8_lossy(&payload[pos..pos + ulen]).to_string();
                        pos += ulen;
                        Some(u)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Password
                let password = if has_pass && pos + 2 <= payload.len() {
                    let plen = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2;
                    if pos + plen <= payload.len() {
                        let p = String::from_utf8_lossy(&payload[pos..pos + plen]).to_string();
                        Some(p)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut ev = Event::new("medium_extra", event_type::AUTH)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id);
                if let Some(ref u) = username {
                    ev = ev.username(Some(u.clone()));
                }
                if let Some(ref p) = password {
                    ev = ev.password(Some(p.clone()));
                }
                ev = ev.data(json!({
                    "proto": "mqtt",
                    "action": "connect",
                    "client_id": client_id,
                    "protocol_name": proto_name,
                    "protocol_level": proto_level,
                    "clean_session": clean_session,
                    "username": username,
                    "password": password,
                }));

                // Response: CONNACK (0x20 0x02 0x00 0x00)
                let connack = vec![0x20, 0x02, 0x00, 0x00];
                (Some(connack), Some(ev), false)
            }
            3 => {
                // PUBLISH (0x30..0x3F)
                let qos = (header_byte & 0x06) >> 1;
                let retain = (header_byte & 0x01) != 0;
                let dup = (header_byte & 0x08) != 0;

                if payload.len() < 2 {
                    return (None, None, false);
                }
                let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                let mut pos = 2;
                let topic = if pos + topic_len <= payload.len() {
                    let t = String::from_utf8_lossy(&payload[pos..pos + topic_len]).to_string();
                    pos += topic_len;
                    t
                } else {
                    "scada/unknown".to_string()
                };

                let packet_id = if qos > 0 && pos + 2 <= payload.len() {
                    let pid = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
                    pos += 2;
                    Some(pid)
                } else {
                    None
                };

                let msg_payload = if pos <= payload.len() {
                    &payload[pos..]
                } else {
                    &[]
                };
                let payload_str = String::from_utf8_lossy(msg_payload).to_string();

                let ev = Event::new("medium_extra", event_type::DATA)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "mqtt",
                        "action": "publish",
                        "topic": topic,
                        "payload": payload_str,
                        "payload_hex": hex::encode(msg_payload),
                        "qos": qos,
                        "retain": retain,
                        "dup": dup,
                        "packet_id": packet_id,
                    }));

                let resp = match qos {
                    1 => {
                        packet_id.map(|pid| vec![0x40, 0x02, (pid >> 8) as u8, (pid & 0xFF) as u8])
                    }
                    2 => {
                        packet_id.map(|pid| vec![0x50, 0x02, (pid >> 8) as u8, (pid & 0xFF) as u8])
                    }
                    _ => None,
                };
                (resp, Some(ev), false)
            }
            8 => {
                // SUBSCRIBE (0x82)
                if payload.len() < 2 {
                    return (None, None, false);
                }
                let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
                let mut pos = 2;
                let mut topics = Vec::new();
                while pos + 2 <= payload.len() {
                    let tlen = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2;
                    if pos + tlen <= payload.len() {
                        let t = String::from_utf8_lossy(&payload[pos..pos + tlen]).to_string();
                        pos += tlen;
                        let _req_qos = if pos < payload.len() {
                            payload[pos]
                        } else {
                            0
                        };
                        pos += 1;
                        topics.push(t);
                    } else {
                        break;
                    }
                }

                let ev = Event::new("medium_extra", event_type::COMMAND)
                    .peer(src_ip, src_port, dst_port)
                    .session(session_id)
                    .data(json!({
                        "proto": "mqtt",
                        "action": "subscribe",
                        "packet_id": packet_id,
                        "topics": topics,
                    }));

                // Response: SUBACK (0x90)
                let mut suback = Vec::new();
                suback.push(0x90);
                suback.push((2 + topics.len()) as u8);
                suback.push((packet_id >> 8) as u8);
                suback.push((packet_id & 0xFF) as u8);
                for _ in &topics {
                    suback.push(0x00); // Granted QoS 0
                }
                (Some(suback), Some(ev), false)
            }
            12 => {
                // PINGREQ (0xC0) -> PINGRESP (0xD0 0x00)
                (Some(vec![0xD0, 0x00]), None, false)
            }
            14 => {
                // DISCONNECT (0xE0)
                (None, None, true)
            }
            _ => (None, None, false),
        }
    }

    async fn handle_mqtt_loop(&self, s: &mut Session, initial: Vec<u8>) {
        let mut buffer = initial;
        loop {
            while !buffer.is_empty() {
                if let Some((header_byte, payload, total_len)) = Self::read_mqtt_packet(&buffer) {
                    let payload_vec = payload.to_vec();
                    buffer.drain(..total_len);
                    let (resp, ev, should_disconnect) = self.eval_mqtt_packet(
                        header_byte,
                        &payload_vec,
                        &s.src_ip,
                        s.src_port,
                        s.dst_port,
                        &s.id,
                    );
                    if let Some(r) = resp {
                        let _ = s.send(&r).await;
                    }
                    if let Some(event) = ev {
                        s.emit(event);
                    }
                    if should_disconnect {
                        return;
                    }
                } else {
                    break;
                }
            }
            match s.read(4096, None).await {
                Ok(b) if !b.is_empty() => {
                    buffer.extend_from_slice(&b);
                }
                _ => break,
            }
        }
    }

    /// Handles a TCP connection session.
    pub async fn handle(&self, s: &mut Session) {
        let mode = if self.mode != "auto" {
            self.mode.clone()
        } else if s.dst_port == 1883 {
            "mqtt".to_string()
        } else if s.dst_port == 6379 {
            "redis".to_string()
        } else {
            // Read first chunk with timeout to auto-detect protocol
            let initial = match s.read(4096, Some(2.0)).await {
                Ok(b) if !b.is_empty() => b,
                _ => return,
            };
            if initial.first() == Some(&0x10) {
                self.handle_mqtt_loop(s, initial).await;
                return;
            } else {
                self.handle_redis_loop(s, initial).await;
                return;
            }
        };

        if mode == "mqtt" {
            self.handle_mqtt_loop(s, Vec::new()).await;
        } else {
            self.handle_redis_loop(s, Vec::new()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::EventSink;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn drain(rx: Receiver<Event>) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn test_medium_extra_stub() {
        assert!(true);
    }

    #[test]
    fn test_medium_extra_redis_commands_eval() {
        let trap = MediumExtraTrap::new(&json!({ "redis_version": "7.0.12" })).unwrap();

        // 1. PING
        let (resp, ev) = trap.eval_redis_command(&["PING".into()], "127.0.0.1", 12345, 6379, "s1");
        assert_eq!(resp, "+PONG\r\n");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["command"], "PING");

        // 2. AUTH password
        let (resp, ev) = trap.eval_redis_command(
            &["AUTH".into(), "secret_pass".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp, "+OK\r\n");
        assert_eq!(ev.event_type, "auth");
        assert_eq!(ev.password.as_deref(), Some("secret_pass"));
        assert_eq!(ev.data["password"], "secret_pass");

        // 2b. AUTH with requirepass mismatch
        let trap_secure = MediumExtraTrap::new(&json!({ "requirepass": "strict_secret" })).unwrap();
        let (resp_fail, ev_fail) = trap_secure.eval_redis_command(
            &["AUTH".into(), "wrong_pass".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp_fail, "-ERR invalid password\r\n");
        assert_eq!(ev_fail.password.as_deref(), Some("wrong_pass"));

        // 3. AUTH username password (ACL)
        let (resp, ev) = trap.eval_redis_command(
            &["AUTH".into(), "admin".into(), "acl_pass".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp, "+OK\r\n");
        assert_eq!(ev.event_type, "auth");
        assert_eq!(ev.username.as_deref(), Some("admin"));
        assert_eq!(ev.password.as_deref(), Some("acl_pass"));

        // 4. INFO
        let (resp, ev) = trap.eval_redis_command(&["INFO".into()], "127.0.0.1", 12345, 6379, "s1");
        assert!(resp.starts_with('$'));
        assert!(resp.contains("# Server\r\nredis_version:7.0.12"));
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["command"], "INFO");

        // 5. CONFIG GET *
        let (resp, ev) = trap.eval_redis_command(
            &["CONFIG".into(), "GET".into(), "*".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert!(resp.starts_with('*'));
        assert!(resp.contains("maxclients"));
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["command"], "CONFIG");

        // 6. SET
        let (resp, ev) = trap.eval_redis_command(
            &["SET".into(), "sensor_1".into(), "val_1".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp, "+OK\r\n");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["key"], "sensor_1");
        assert_eq!(ev.data["value"], "val_1");

        // 7. GET
        let (resp, ev) = trap.eval_redis_command(
            &["GET".into(), "sensor_1".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp, "$-1\r\n");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["key"], "sensor_1");

        // 8. SLAVEOF
        let (resp, ev) = trap.eval_redis_command(
            &["SLAVEOF".into(), "10.0.0.1".into(), "6379".into()],
            "127.0.0.1",
            12345,
            6379,
            "s1",
        );
        assert_eq!(resp, "+OK\r\n");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["host"], "10.0.0.1");
        assert_eq!(ev.data["port"], "6379");
    }

    #[tokio::test]
    async fn test_medium_extra_redis_tcp_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = std::sync::Arc::new(
            MediumExtraTrap::new(&json!({
                "mode": "redis",
                "redis_version": "7.0.12"
            }))
            .unwrap(),
        );

        let trap_clone = trap.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, 6379, sink, "medium_extra", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // 1. Send PING
        client.write_all(b"PING\r\n").await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+PONG\r\n");

        // 2. Send AUTH
        client.write_all(b"AUTH pass_redis_99\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+OK\r\n");

        // 3. Send INFO
        client.write_all(b"INFO\r\n").await.unwrap();
        let mut info_buf = vec![0u8; 2048];
        let n = client.read(&mut info_buf).await.unwrap();
        let info_str = String::from_utf8_lossy(&info_buf[..n]);
        assert!(info_str.starts_with('$'));
        assert!(info_str.contains("redis_version:7.0.12"));

        // 4. Send QUIT
        client.write_all(b"QUIT\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+OK\r\n");

        let evs = drain(rx);
        assert_eq!(evs.len(), 4);
        assert_eq!(evs[0].event_type, "command");
        assert_eq!(evs[0].data["command"], "PING");

        assert_eq!(evs[1].event_type, "auth");
        assert_eq!(evs[1].password.as_deref(), Some("pass_redis_99"));

        assert_eq!(evs[2].event_type, "command");
        assert_eq!(evs[2].data["command"], "INFO");

        assert_eq!(evs[3].event_type, "command");
        assert_eq!(evs[3].data["command"], "QUIT");
    }

    #[tokio::test]
    async fn test_medium_extra_redis_resp_format_tcp_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = std::sync::Arc::new(MediumExtraTrap::new(&json!({ "mode": "redis" })).unwrap());

        let trap_clone = trap.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, 6379, sink, "medium_extra", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // RESP format: *2\r\n$4\r\nAUTH\r\n$7\r\npass123\r\n
        let req = b"*2\r\n$4\r\nAUTH\r\n$7\r\npass123\r\n*1\r\n$4\r\nQUIT\r\n";
        client.write_all(req).await.unwrap();

        let mut buf = vec![0u8; 128];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+OK\r\n+OK\r\n");

        let evs = drain(rx);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event_type, "auth");
        assert_eq!(evs[0].password.as_deref(), Some("pass123"));
        assert_eq!(evs[1].event_type, "command");
        assert_eq!(evs[1].data["command"], "QUIT");
    }

    #[test]
    fn test_medium_extra_mqtt_connect_packet_eval() {
        let trap = MediumExtraTrap::new(&json!({})).unwrap();

        let proto_name = b"MQTT";
        let client_id = b"scada_client_01";
        let username = b"industrial_user";
        let password = b"industrial_pass";

        let mut var_hdr = Vec::new();
        var_hdr.extend_from_slice(&(proto_name.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(proto_name);
        var_hdr.push(4); // MQTT 3.1.1
        var_hdr.push(0xC2); // flags: username, password, clean_session
        var_hdr.extend_from_slice(&60u16.to_be_bytes()); // keepalive

        var_hdr.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(client_id);
        var_hdr.extend_from_slice(&(username.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(username);
        var_hdr.extend_from_slice(&(password.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(password);

        let (resp, ev, disc) =
            trap.eval_mqtt_packet(0x10, &var_hdr, "10.0.0.12", 50000, 1883, "m1");

        assert_eq!(disc, false);
        assert_eq!(resp, Some(vec![0x20, 0x02, 0x00, 0x00])); // CONNACK

        let ev = ev.expect("expected auth event");
        assert_eq!(ev.event_type, "auth");
        assert_eq!(ev.username.as_deref(), Some("industrial_user"));
        assert_eq!(ev.password.as_deref(), Some("industrial_pass"));
        assert_eq!(ev.data["client_id"], "scada_client_01");
        assert_eq!(ev.data["protocol_name"], "MQTT");
        assert_eq!(ev.data["protocol_level"], 4);
    }

    #[test]
    fn test_medium_extra_mqtt_mqisdp_connect() {
        let trap = MediumExtraTrap::new(&json!({})).unwrap();

        let proto_name = b"MQIsdp";
        let client_id = b"legacy_plc";

        let mut var_hdr = Vec::new();
        var_hdr.extend_from_slice(&(proto_name.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(proto_name);
        var_hdr.push(3); // MQTT 3.1
        var_hdr.push(0x02); // clean_session
        var_hdr.extend_from_slice(&30u16.to_be_bytes());

        var_hdr.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(client_id);

        let (resp, ev, _) = trap.eval_mqtt_packet(0x10, &var_hdr, "10.0.0.13", 50001, 1883, "m2");
        assert_eq!(resp, Some(vec![0x20, 0x02, 0x00, 0x00]));
        let ev = ev.unwrap();
        assert_eq!(ev.event_type, "auth");
        assert_eq!(ev.data["client_id"], "legacy_plc");
        assert_eq!(ev.data["protocol_name"], "MQIsdp");
        assert_eq!(ev.data["protocol_level"], 3);
    }

    #[tokio::test]
    async fn test_medium_extra_mqtt_tcp_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = std::sync::Arc::new(MediumExtraTrap::new(&json!({ "mode": "mqtt" })).unwrap());

        let trap_clone = trap.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, 1883, sink, "medium_extra", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // 1. Send CONNECT packet
        let proto_name = b"MQTT";
        let client_id = b"scada_power_substation_01";
        let username = b"scada_admin";
        let password = b"grid_pwd_889";

        let mut connect_payload = Vec::new();
        connect_payload.extend_from_slice(&(proto_name.len() as u16).to_be_bytes());
        connect_payload.extend_from_slice(proto_name);
        connect_payload.push(4); // 3.1.1
        connect_payload.push(0xC2); // user, pass, clean
        connect_payload.extend_from_slice(&60u16.to_be_bytes());

        connect_payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        connect_payload.extend_from_slice(client_id);
        connect_payload.extend_from_slice(&(username.len() as u16).to_be_bytes());
        connect_payload.extend_from_slice(username);
        connect_payload.extend_from_slice(&(password.len() as u16).to_be_bytes());
        connect_payload.extend_from_slice(password);

        let mut connect_pkt = vec![0x10];
        MediumExtraTrap::encode_var_int(connect_payload.len(), &mut connect_pkt);
        connect_pkt.extend_from_slice(&connect_payload);

        client.write_all(&connect_pkt).await.unwrap();

        // Expect CONNACK (0x20 0x02 0x00 0x00)
        let mut connack_buf = vec![0u8; 4];
        client.read_exact(&mut connack_buf).await.unwrap();
        assert_eq!(&connack_buf, &[0x20, 0x02, 0x00, 0x00]);

        // 2. Send SUBSCRIBE to "scada/power/meter"
        let topic = "scada/power/meter";
        let mut sub_payload = Vec::new();
        sub_payload.extend_from_slice(&100u16.to_be_bytes()); // packet id
        sub_payload.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        sub_payload.extend_from_slice(topic.as_bytes());
        sub_payload.push(0); // QoS 0

        let mut sub_pkt = vec![0x82];
        MediumExtraTrap::encode_var_int(sub_payload.len(), &mut sub_pkt);
        sub_pkt.extend_from_slice(&sub_payload);

        client.write_all(&sub_pkt).await.unwrap();

        // Expect SUBACK (0x90 0x03 0x00 0x64 0x00)
        let mut suback_buf = vec![0u8; 5];
        client.read_exact(&mut suback_buf).await.unwrap();
        assert_eq!(&suback_buf, &[0x90, 0x03, 0x00, 100, 0x00]);

        // 3. Send PUBLISH to "scada/power/meter" (QoS 0)
        let telemetry = b"{\"voltage\": 230.1, \"frequency\": 50.02, \"active_power_kw\": 420.5}";
        let mut pub_payload = Vec::new();
        pub_payload.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        pub_payload.extend_from_slice(topic.as_bytes());
        pub_payload.extend_from_slice(telemetry);

        let mut pub_pkt = vec![0x30];
        MediumExtraTrap::encode_var_int(pub_payload.len(), &mut pub_pkt);
        pub_pkt.extend_from_slice(&pub_payload);

        client.write_all(&pub_pkt).await.unwrap();

        // 4. Send DISCONNECT (0xE0 0x00)
        client.write_all(&[0xE0, 0x00]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let evs = drain(rx);
        assert_eq!(evs.len(), 3);

        // 1. Auth event from CONNECT
        let ev0 = &evs[0];
        assert_eq!(ev0.event_type, "auth");
        assert_eq!(ev0.username.as_deref(), Some("scada_admin"));
        assert_eq!(ev0.password.as_deref(), Some("grid_pwd_889"));
        assert_eq!(ev0.data["client_id"], "scada_power_substation_01");

        // 2. Command event from SUBSCRIBE
        let ev1 = &evs[1];
        assert_eq!(ev1.event_type, "command");
        assert_eq!(ev1.data["action"], "subscribe");
        assert_eq!(ev1.data["topics"].as_array().unwrap()[0], "scada/power/meter");

        // 3. Data event from PUBLISH
        let ev2 = &evs[2];
        assert_eq!(ev2.event_type, "data");
        assert_eq!(ev2.data["action"], "publish");
        assert_eq!(ev2.data["topic"], "scada/power/meter");
        assert!(ev2.data["payload"].as_str().unwrap().contains("230.1"));
    }
}
