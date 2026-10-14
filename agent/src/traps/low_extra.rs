//! Extended Low-Interaction Traps (Discovery, Probing, Network Services).

use crate::config::Params;
use crate::event::{event_type, Event};
use crate::session::Session;
use crate::util;
use regex::Regex;
use serde_json::{json, Value};

/// Extended Low-Interaction Honeypot Trap.
/// Responds to network discovery / reconnaissance probes (SSDP/UPnP, Echo, Daytime, Chargen, Generic).
pub struct LowExtraTrap {
    params: Value,
    device_location: String,
    device_usn: String,
    server_header: String,
    mode: String,
}

impl LowExtraTrap {
    pub fn new(params: &Value) -> Result<Self, String> {
        let p = Params(params);
        let device_location = p.str("device_location", "http://127.0.0.1:1900/rootDesc.xml");
        let device_usn = p.str("device_usn", "uuid:honeyforge-upnp-device-01");
        let server_header = p.str("server_header", "Linux/4.14 UPnP/1.0");
        let mode = p.str("mode", "auto");
        Ok(Self {
            params: params.clone(),
            device_location,
            device_usn,
            server_header,
            mode,
        })
    }

    /// Processes an incoming probe buffer and generates an optional protocol response and event.
    pub fn process_probe(
        &self,
        data: &[u8],
        src_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> (Option<Vec<u8>>, Event) {
        let text = String::from_utf8_lossy(data);
        let sample = util::safe_text(data, 256);
        let event_kind = Params(&self.params).str("event_type", event_type::SCAN);

        // 1. SSDP / UPnP discovery probe: matches M-SEARCH * HTTP/1.1
        if text.starts_with("M-SEARCH")
            || text.contains("M-SEARCH * HTTP/1.1")
            || (self.mode == "ssdp" && text.contains("M-SEARCH"))
        {
            let st = Regex::new(r"(?im)^ST:\s*(.+)$")
                .ok()
                .and_then(|re| re.captures(&text).map(|c| c[1].trim().to_string()))
                .unwrap_or_else(|| "upnp:rootdevice".to_string());

            let loc = if self.device_location.contains("{ip}") {
                self.device_location.replace("{ip}", src_ip)
            } else {
                self.device_location.clone()
            };
            let usn = format!("{}::{}", self.device_usn, st);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: {loc}\r\nSERVER: {}\r\nST: {st}\r\nUSN: {usn}\r\n\r\n",
                self.server_header
            );
            let ev = Event::new("low_extra", &event_kind)
                .peer(src_ip, src_port, dst_port)
                .data(json!({
                    "probe_signature": "ssdp_msearch",
                    "signature": "ssdp_msearch",
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "dst_port": dst_port,
                    "payload_sample": sample,
                    "st": st,
                    "location": loc,
                    "usn": usn,
                    "proto": "ssdp/upnp",
                }));
            return (Some(resp.into_bytes()), ev);
        }

        // 2. Daytime probe (RFC 867)
        if self.mode == "daytime" || dst_port == 13 || text.to_uppercase().contains("DAYTIME") {
            let dt = format!("{}, {} UTC\r\n", util::http_date(), util::clock_time());
            let ev = Event::new("low_extra", &event_kind)
                .peer(src_ip, src_port, dst_port)
                .data(json!({
                    "probe_signature": "daytime_probe",
                    "signature": "daytime_probe",
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "dst_port": dst_port,
                    "payload_sample": sample,
                    "proto": "daytime",
                }));
            return (Some(dt.into_bytes()), ev);
        }

        // 3. Echo probe (RFC 862)
        if self.mode == "echo" || dst_port == 7 || text.to_uppercase().starts_with("ECHO") {
            let ev = Event::new("low_extra", &event_kind)
                .peer(src_ip, src_port, dst_port)
                .data(json!({
                    "probe_signature": "echo_probe",
                    "signature": "echo_probe",
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "dst_port": dst_port,
                    "payload_sample": sample,
                    "proto": "echo",
                }));
            let resp_bytes = if data.is_empty() {
                b"echo\r\n".to_vec()
            } else {
                data.to_vec()
            };
            return (Some(resp_bytes), ev);
        }

        // 4. Chargen probe (RFC 864)
        if self.mode == "chargen" || dst_port == 19 || text.to_uppercase().contains("CHARGEN") {
            let pattern = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefgh\r\n";
            let ev = Event::new("low_extra", &event_kind)
                .peer(src_ip, src_port, dst_port)
                .data(json!({
                    "probe_signature": "chargen_probe",
                    "signature": "chargen_probe",
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "dst_port": dst_port,
                    "payload_sample": sample,
                    "proto": "chargen",
                }));
            return (Some(pattern.to_vec()), ev);
        }

        // 5. Generic TCP network service probe
        let ev = Event::new("low_extra", &event_kind)
            .peer(src_ip, src_port, dst_port)
            .data(json!({
                "probe_signature": "generic_tcp_probe",
                "signature": "generic_tcp_probe",
                "source_ip": src_ip,
                "source_port": src_port,
                "dst_port": dst_port,
                "payload_sample": sample,
                "proto": "tcp",
            }));
        (None, ev)
    }

    /// Handles a TCP connection session.
    pub async fn handle(&self, s: &mut Session) {
        let timeout_s = if s.idle_timeout > 0.0 {
            Some(s.idle_timeout.min(2.0))
        } else {
            Some(1.5)
        };
        let buf = match s.read(4096, timeout_s).await {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
        let (resp, ev) = self.process_probe(&buf, &s.src_ip, s.src_port, s.dst_port);
        if let Some(resp_bytes) = resp {
            let _ = s.send(&resp_bytes).await;
        }
        s.emit(ev.session(&s.id));
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
    fn test_low_extra_stub() {
        assert!(true);
    }

    #[test]
    fn test_low_extra_ssdp_probe_direct() {
        let trap = LowExtraTrap::new(&json!({
            "device_location": "http://192.168.1.50:1900/rootDesc.xml",
            "device_usn": "uuid:test-upnp-device-1234",
            "server_header": "Linux/5.4 UPnP/1.0"
        })).unwrap();

        let probe = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let (resp, ev) = trap.process_probe(probe, "192.168.1.100", 45678, 1900);

        assert!(resp.is_some());
        let resp_str = String::from_utf8(resp.unwrap()).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_str.contains("LOCATION: http://192.168.1.50:1900/rootDesc.xml"));
        assert!(resp_str.contains("USN: uuid:test-upnp-device-1234::urn:schemas-upnp-org:device:InternetGatewayDevice:1"));
        assert!(resp_str.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"));

        assert_eq!(ev.event_type, "scan");
        assert_eq!(ev.src_ip, "192.168.1.100");
        assert_eq!(ev.src_port, 45678);
        assert_eq!(ev.dst_port, 1900);
        assert_eq!(ev.data["probe_signature"], "ssdp_msearch");
        assert_eq!(ev.data["st"], "urn:schemas-upnp-org:device:InternetGatewayDevice:1");
        assert!(ev.data["payload_sample"].as_str().unwrap().contains("M-SEARCH"));
    }

    #[test]
    fn test_low_extra_echo_probe_direct() {
        let trap = LowExtraTrap::new(&json!({ "mode": "echo" })).unwrap();
        let payload = b"Hello Echo Server 12345";
        let (resp, ev) = trap.process_probe(payload, "10.0.0.5", 55555, 7);

        assert_eq!(resp, Some(payload.to_vec()));
        assert_eq!(ev.event_type, "scan");
        assert_eq!(ev.src_ip, "10.0.0.5");
        assert_eq!(ev.src_port, 55555);
        assert_eq!(ev.data["probe_signature"], "echo_probe");
        assert_eq!(ev.data["payload_sample"], "Hello Echo Server 12345");
    }

    #[test]
    fn test_low_extra_daytime_probe_direct() {
        let trap = LowExtraTrap::new(&json!({})).unwrap();
        let (resp, ev) = trap.process_probe(b"DAYTIME\r\n", "10.0.0.6", 44444, 13);

        assert!(resp.is_some());
        let resp_str = String::from_utf8(resp.unwrap()).unwrap();
        assert!(resp_str.contains("UTC"));
        assert_eq!(ev.event_type, "scan");
        assert_eq!(ev.data["probe_signature"], "daytime_probe");
    }

    #[test]
    fn test_low_extra_chargen_probe_direct() {
        let trap = LowExtraTrap::new(&json!({})).unwrap();
        let (resp, ev) = trap.process_probe(b"", "10.0.0.7", 33333, 19);

        assert!(resp.is_some());
        let resp_bytes = resp.unwrap();
        assert!(resp_bytes.starts_with(b"!\"#$%&'()*+"));
        assert_eq!(ev.event_type, "scan");
        assert_eq!(ev.data["probe_signature"], "chargen_probe");
    }

    #[test]
    fn test_low_extra_generic_tcp_probe_direct() {
        let trap = LowExtraTrap::new(&json!({})).unwrap();
        let payload = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"; // TLS client hello fragment
        let (resp, ev) = trap.process_probe(payload, "10.0.0.8", 22222, 8080);

        assert!(resp.is_none());
        assert_eq!(ev.event_type, "scan");
        assert_eq!(ev.data["probe_signature"], "generic_tcp_probe");
        assert_eq!(ev.data["source_ip"], "10.0.0.8");
        assert_eq!(ev.data["source_port"], 22222);
    }

    #[tokio::test]
    async fn test_low_extra_ssdp_tcp_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = std::sync::Arc::new(
            LowExtraTrap::new(&json!({
                "device_location": "http://127.0.0.1:1900/rootDesc.xml",
                "device_usn": "uuid:honeyforge-001"
            }))
            .unwrap(),
        );

        let trap_clone = trap.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, 1900, sink, "low_extra", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n";
        client.write_all(req).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf.truncate(n);

        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("HTTP/1.1 200 OK"));
        assert!(text.contains("LOCATION: http://127.0.0.1:1900/rootDesc.xml"));
        assert!(text.contains("USN: uuid:honeyforge-001::ssdp:all"));
        assert!(text.contains("ST: ssdp:all"));

        let evs = drain(rx);
        assert_eq!(evs.len(), 1);
        let scan_ev = &evs[0];
        assert_eq!(scan_ev.event_type, "scan");
        assert_eq!(scan_ev.data["probe_signature"], "ssdp_msearch");
        assert_eq!(scan_ev.data["st"], "ssdp:all");
    }

    #[tokio::test]
    async fn test_low_extra_echo_tcp_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = std::sync::Arc::new(LowExtraTrap::new(&json!({ "mode": "echo" })).unwrap());

        let trap_clone = trap.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, 7, sink, "low_extra", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"probe_ping_123").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf.truncate(n);
        assert_eq!(&buf, b"probe_ping_123");

        let evs = drain(rx);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_type, "scan");
        assert_eq!(evs[0].data["probe_signature"], "echo_probe");
    }
}
