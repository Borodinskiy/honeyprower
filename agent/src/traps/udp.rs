//! UDP-ответчик: DNS, NTP, SSDP, SIP или правила hex/regex. Логирует каждую
//! датаграмму. Защита от отражённого усиления (DDoS): ответ не больше запроса
//! (кроме DNS/NTP) и лимит ответов одному IP в минуту.

use crate::config::Params;
use crate::event::{event_type, now_ts, Event};
use crate::sender::EventSink;
use crate::util::{hex_prefix, parse_hex, safe_text, session_id};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const NTP_DELTA: u64 = 2_208_988_800;

pub struct UdpResponder {
    params: Value,
    replies: Mutex<HashMap<String, Vec<f64>>>,
}

impl UdpResponder {
    pub fn new(params: &Value) -> UdpResponder {
        UdpResponder {
            params: params.clone(),
            replies: Mutex::new(HashMap::new()),
        }
    }

    fn allowed(&self, ip: &str) -> bool {
        let max = Params(&self.params).int("max_replies_per_ip_min", 20) as usize;
        let now = now_ts();
        let mut map = self.replies.lock().unwrap();
        let v = map.entry(ip.to_string()).or_default();
        v.retain(|t| now - t < 60.0);
        if v.len() >= max {
            return false;
        }
        v.push(now);
        true
    }

    fn helper(&self, data: &[u8]) -> (Vec<u8>, Value) {
        let p = Params(&self.params);
        match p.str("helper", "none").as_str() {
            "dns" => {
                let (resp, info) = dns_answer(data, &p.str("dns_answer_ip", "10.0.0.15"), 300);
                (resp, info)
            }
            "ntp" => {
                let resp = ntp_answer(data, p.int("ntp_stratum", 2) as u8);
                (resp, json!({ "ntp_mode": data.first().map(|b| b & 7) }))
            }
            "ssdp" => {
                let text = String::from_utf8_lossy(data);
                if text.starts_with("M-SEARCH") {
                    let st = Regex::new(r"(?im)^ST:\s*(.+)$")
                        .ok()
                        .and_then(|re| re.captures(&text).map(|c| c[1].trim().to_string()))
                        .unwrap_or_else(|| "upnp:rootdevice".to_string());
                    let server = p.str("ssdp_server", "Linux/4.14 UPnP/1.0");
                    let ip = p.str("dns_answer_ip", "10.0.0.15");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://{ip}:1900/rootDesc.xml\r\nSERVER: {server}\r\nST: {st}\r\nUSN: uuid:honeyforge::{st}\r\n\r\n"
                    );
                    return (resp.into_bytes(), json!({ "st": st }));
                }
                (Vec::new(), json!({}))
            }
            "sip" => {
                let text = String::from_utf8_lossy(data);
                if let Some(c) = Regex::new(r"^([A-Z]+) (\S+) SIP/2\.0").ok().and_then(|re| re.captures(&text)) {
                    let keep: Vec<&str> = text
                        .split("\r\n")
                        .filter(|ln| {
                            let l = ln.to_lowercase();
                            l.starts_with("via")
                                || l.starts_with("from")
                                || l.starts_with("to")
                                || l.starts_with("call-id")
                                || l.starts_with("cseq")
                        })
                        .collect();
                    let server = p.str("ssdp_server", "Linux/4.14 UPnP/1.0");
                    let resp = format!(
                        "SIP/2.0 200 OK\r\n{}\r\nUser-Agent: {server}\r\nContent-Length: 0\r\n\r\n",
                        keep.join("\r\n")
                    );
                    return (resp.into_bytes(), json!({ "sip_method": &c[1], "uri": &c[2] }));
                }
                (Vec::new(), json!({}))
            }
            _ => (Vec::new(), json!({})),
        }
    }

    fn rules(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        for r in Params(&self.params).array("rules") {
            let hx = parse_hex(r.get("match_hex").and_then(Value::as_str).unwrap_or(""));
            if !hx.is_empty() && !data.starts_with(&hx) {
                continue;
            }
            let rx = r.get("match_regex").and_then(Value::as_str).unwrap_or("");
            if !rx.is_empty() {
                match Regex::new(&format!("(?is){rx}")) {
                    Ok(re) if re.is_match(&text) => {}
                    _ => continue,
                }
            }
            if hx.is_empty() && rx.is_empty() {
                continue;
            }
            let resp_hex = r.get("response_hex").and_then(Value::as_str).unwrap_or("");
            if !resp_hex.is_empty() {
                return parse_hex(resp_hex);
            }
            let resp = r.get("response").and_then(Value::as_str).unwrap_or("");
            return crate::util::unescape(resp);
        }
        Vec::new()
    }

    /// Обработка одной датаграммы. Возвращает ответ (или пусто).
    pub fn on_datagram(&self, data: &[u8], ip: &str, src_port: u16, dst_port: u16, sink: &EventSink) -> Vec<u8> {
        let (mut resp, info) = self.helper(data);
        if resp.is_empty() {
            resp = self.rules(data);
        }
        let mut ev_data = json!({
            "text": safe_text(data, 1024),
            "hex": hex_prefix(data, 256),
            "len": data.len(),
        });
        if let Value::Object(extra) = info {
            if let Value::Object(base) = &mut ev_data {
                for (k, v) in extra {
                    base.insert(k, v);
                }
            }
        }
        let ev = Event::new("udp", event_type::DATA)
            .proto("udp")
            .peer(ip, src_port, dst_port)
            .session(&session_id())
            .data(ev_data);
        sink.emit(ev);

        if resp.is_empty() {
            return Vec::new();
        }
        let p = Params(&self.params);
        let helper = p.str("helper", "none");
        if p.bool("limit_amplification", true) && helper != "dns" && helper != "ntp" && resp.len() > data.len() {
            return Vec::new(); // обрезанный ответ выглядел бы неправдоподобно — лучше молчать
        }
        if !self.allowed(ip) {
            return Vec::new();
        }
        resp
    }
}

/// Ответ на A-запрос: любое имя -> ip. Возвращает (ответ, разобранный запрос).
fn dns_answer(req: &[u8], ip: &str, ttl: u32) -> (Vec<u8>, Value) {
    if req.len() < 12 {
        return (Vec::new(), json!({}));
    }
    let tid = u16::from_be_bytes([req[0], req[1]]);
    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < req.len() && req[pos] != 0 {
        let len = req[pos] as usize;
        if pos + 1 + len > req.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&req[pos + 1..pos + 1 + len]).into_owned());
        pos += 1 + len;
    }
    let qname = labels.join(".");
    let qtype = if pos + 5 <= req.len() {
        u16::from_be_bytes([req[pos + 1], req[pos + 2]])
    } else {
        1
    };
    let question = req.get(12..pos + 5).unwrap_or(&[]).to_vec();
    let info = json!({ "qname": qname, "qtype": qtype });

    if qtype != 1 {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&tid.to_be_bytes());
        hdr.extend_from_slice(&0x8183u16.to_be_bytes()); // NXDOMAIN
        hdr.extend_from_slice(&1u16.to_be_bytes());
        hdr.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        hdr.extend_from_slice(&question);
        return (hdr, info);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qd
    out.extend_from_slice(&1u16.to_be_bytes()); // an
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&question);
    out.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    for octet in ip.split('.') {
        out.push(octet.parse::<u8>().unwrap_or(0));
    }
    (out, info)
}

fn ntp_answer(req: &[u8], stratum: u8) -> Vec<u8> {
    if req.len() < 48 || (req[0] & 0x07) != 3 {
        return Vec::new();
    }
    let now = now_ts() + NTP_DELTA as f64;
    let sec = now as u32;
    let frac = ((now.fract()) * 4_294_967_296.0) as u32;
    let vn = (req[0] >> 3) & 0x07;
    let mut pkt = vec![0u8; 48];
    pkt[0] = (vn << 3) | 4; // mode server
    pkt[1] = stratum;
    pkt[2] = req[2];
    pkt[3] = 0xE9;
    if stratum == 1 {
        pkt[12..16].copy_from_slice(b"GPS\x00");
    } else {
        pkt[12..16].copy_from_slice(&[0x7f, 0, 0, 1]);
    }
    pkt[16..20].copy_from_slice(&(sec - 30).to_be_bytes());
    pkt[24..32].copy_from_slice(&req[40..48]); // originate = transmit клиента
    pkt[32..36].copy_from_slice(&sec.to_be_bytes());
    pkt[36..40].copy_from_slice(&frac.to_be_bytes());
    pkt[40..44].copy_from_slice(&sec.to_be_bytes());
    pkt[44..48].copy_from_slice(&frac.to_be_bytes());
    pkt
}
