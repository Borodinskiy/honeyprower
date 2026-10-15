//! IEC 60870-5-104 (IEC-104) honeypot trap implementation.

use crate::session::Session;
use serde_json::Value;

pub const START_BYTE: u8 = 0x68;

// U-format control functions
pub const STARTDT_ACT: u8 = 0x07;
pub const STARTDT_CON: u8 = 0x0B;
pub const STOPDT_ACT: u8 = 0x13;
pub const STOPDT_CON: u8 = 0x23;
pub const TESTFR_ACT: u8 = 0x43;
pub const TESTFR_CON: u8 = 0x83;

// S-format mask and identifier
pub const S_FORMAT_ID: u8 = 0x01;

// Type IDs
pub const TYPE_M_SP_NA_1: u8 = 1;   // Single-point information
pub const TYPE_M_ME_NC_1: u8 = 13;  // Measured value, short floating point
pub const TYPE_C_SC_NA_1: u8 = 45;  // Single command
pub const TYPE_C_DC_NA_1: u8 = 46;  // Double command
pub const TYPE_C_IC_NA_1: u8 = 100; // Interrogation command

// Causes of Transmission (COT)
pub const COT_ACTIVATION: u8 = 6;
pub const COT_ACTIVATION_CON: u8 = 7;
pub const COT_ACTIVATION_TERM: u8 = 10;
pub const COT_INTERROGATED_BY_GI: u8 = 20;

// Information Object Addresses (IOA)
pub const IOA_BREAKER: u32 = 1001;
pub const IOA_SWITCH: u32 = 1002;
pub const IOA_VOLTAGE: u32 = 2001;
pub const IOA_POWER: u32 = 2002;
pub const IOA_FREQUENCY: u32 = 2003;

/// Simulated substation state per connection.
#[derive(Debug, Clone, PartialEq)]
pub struct SubstationState {
    pub breaker_closed: bool,
    pub switch_closed: bool,
    pub voltage: f32,
    pub power: f32,
    pub frequency: f32,
}

impl Default for SubstationState {
    fn default() -> Self {
        Self {
            breaker_closed: true,
            switch_closed: true,
            voltage: 220.5,
            power: 45.2,
            frequency: 50.0,
        }
    }
}

/// APCI Control Fields representation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ApciFrame {
    /// I-format: send sequence N(S), receive sequence N(R)
    I { ns: u16, nr: u16 },
    /// S-format: receive sequence N(R)
    S { nr: u16 },
    /// U-format: function code (e.g. STARTDT_ACT, TESTFR_ACT, etc.)
    U { function: u8 },
}

impl ApciFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("APCI requires at least 4 bytes".to_string());
        }
        let b0 = bytes[0];
        let b1 = bytes[1];
        let b2 = bytes[2];
        let b3 = bytes[3];

        if (b0 & 0x01) == 0 {
            // I-format: bit0 == 0
            let ns = (((b0 as u16) | ((b1 as u16) << 8)) >> 1) & 0x7FFF;
            let nr = (((b2 as u16) | ((b3 as u16) << 8)) >> 1) & 0x7FFF;
            Ok(ApciFrame::I { ns, nr })
        } else if (b0 & 0x03) == 0x01 {
            // S-format: bits 0..1 == 01
            let nr = (((b2 as u16) | ((b3 as u16) << 8)) >> 1) & 0x7FFF;
            Ok(ApciFrame::S { nr })
        } else if (b0 & 0x03) == 0x03 {
            // U-format: bits 0..1 == 11
            Ok(ApciFrame::U { function: b0 })
        } else {
            Err(format!("Invalid APCI control byte: 0x{:02x}", b0))
        }
    }

    pub fn encode(&self) -> [u8; 4] {
        match *self {
            ApciFrame::I { ns, nr } => {
                let ns_val = (ns & 0x7FFF) << 1;
                let nr_val = (nr & 0x7FFF) << 1;
                [
                    (ns_val & 0xFF) as u8,
                    ((ns_val >> 8) & 0xFF) as u8,
                    (nr_val & 0xFF) as u8,
                    ((nr_val >> 8) & 0xFF) as u8,
                ]
            }
            ApciFrame::S { nr } => {
                let nr_val = (nr & 0x7FFF) << 1;
                [
                    0x01,
                    0x00,
                    (nr_val & 0xFF) as u8,
                    ((nr_val >> 8) & 0xFF) as u8,
                ]
            }
            ApciFrame::U { function } => [function, 0x00, 0x00, 0x00],
        }
    }
}

/// Builds a complete framed APDU: `[0x68, apdu_len, APCI(4), ASDU...]`
pub fn build_apdu(apci: &ApciFrame, asdu: &[u8]) -> Vec<u8> {
    let apci_bytes = apci.encode();
    let apdu_len = 4 + asdu.len();
    let mut frame = Vec::with_capacity(2 + apdu_len);
    frame.push(START_BYTE);
    frame.push(apdu_len as u8);
    frame.extend_from_slice(&apci_bytes);
    frame.extend_from_slice(asdu);
    frame
}

/// Parses a complete framed APDU into APCI and ASDU payload.
pub fn parse_apdu(data: &[u8]) -> Result<(ApciFrame, Vec<u8>), String> {
    if data.len() < 6 {
        return Err("APDU too short".to_string());
    }
    if data[0] != START_BYTE {
        return Err(format!("Invalid start byte: 0x{:02x}", data[0]));
    }
    let length = data[1] as usize;
    if length < 4 {
        return Err("APDU length less than 4".to_string());
    }
    if data.len() < 2 + length {
        return Err("Truncated APDU".to_string());
    }
    let apci = ApciFrame::decode(&data[2..6])?;
    let asdu = data[6..2 + length].to_vec();
    Ok((apci, asdu))
}

pub fn parse_ioa(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 3 {
        None
    } else {
        Some((bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16))
    }
}

pub fn encode_ioa(ioa: u32) -> [u8; 3] {
    [
        (ioa & 0xFF) as u8,
        ((ioa >> 8) & 0xFF) as u8,
        ((ioa >> 16) & 0xFF) as u8,
    ]
}

/// ASDU (Application Service Data Unit) representation.
#[derive(Debug, Clone, PartialEq)]
pub struct Asdu {
    pub type_id: u8,
    pub vsq: u8,
    pub cot: u8,
    pub originator: u8,
    pub coa: u16,
    pub payload: Vec<u8>,
}

impl Asdu {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err("ASDU header requires at least 6 bytes".to_string());
        }
        let type_id = bytes[0];
        let vsq = bytes[1];
        let cot = bytes[2];
        let originator = bytes[3];
        let coa = u16::from_le_bytes([bytes[4], bytes[5]]);
        let payload = bytes[6..].to_vec();

        Ok(Asdu {
            type_id,
            vsq,
            cot,
            originator,
            coa,
            payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.payload.len());
        out.push(self.type_id);
        out.push(self.vsq);
        out.push(self.cot);
        out.push(self.originator);
        out.extend_from_slice(&self.coa.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Connection-level protocol state machine tracking sequences and substation state.
#[derive(Debug, Clone)]
pub struct Iec104Connection {
    pub send_seq: u16,
    pub recv_seq: u16,
    pub peer_acknowledged_nr: u16,
    pub data_transfer_active: bool,
    pub state: SubstationState,
}

impl Default for Iec104Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Iec104Connection {
    pub fn new() -> Self {
        Self::new_with_state(SubstationState::default())
    }

    pub fn new_with_state(state: SubstationState) -> Self {
        Self {
            send_seq: 0,
            recv_seq: 0,
            peer_acknowledged_nr: 0,
            data_transfer_active: false,
            state,
        }
    }

    /// Process a single complete APDU frame and return response frames and optional command event data.
    pub fn process_apdu(&mut self, apdu_bytes: &[u8]) -> (Vec<Vec<u8>>, Option<Value>) {
        let (apci, asdu_bytes) = match parse_apdu(apdu_bytes) {
            Ok(res) => res,
            Err(_) => return (vec![], None),
        };

        match apci {
            ApciFrame::U { function } => {
                match function {
                    STARTDT_ACT => {
                        self.data_transfer_active = true;
                        let resp = build_apdu(&ApciFrame::U { function: STARTDT_CON }, &[]);
                        (vec![resp], None)
                    }
                    STOPDT_ACT => {
                        self.data_transfer_active = false;
                        let resp = build_apdu(&ApciFrame::U { function: STOPDT_CON }, &[]);
                        (vec![resp], None)
                    }
                    TESTFR_ACT => {
                        let resp = build_apdu(&ApciFrame::U { function: TESTFR_CON }, &[]);
                        (vec![resp], None)
                    }
                    _ => (vec![], None),
                }
            }
            ApciFrame::S { nr } => {
                self.peer_acknowledged_nr = nr;
                (vec![], None)
            }
            ApciFrame::I { ns, nr } => {
                self.peer_acknowledged_nr = nr;
                self.recv_seq = (ns.wrapping_add(1)) & 0x7FFF;

                let asdu = match Asdu::parse(&asdu_bytes) {
                    Ok(a) => a,
                    Err(_) => {
                        let s_resp = build_apdu(&ApciFrame::S { nr: self.recv_seq }, &[]);
                        return (vec![s_resp], None);
                    }
                };

                match asdu.type_id {
                    TYPE_C_IC_NA_1 => {
                        // General Interrogation
                        let qoi = if asdu.payload.len() >= 4 { asdu.payload[3] } else { 20 };
                        let mut frames = Vec::with_capacity(4);

                        // 1. Activation Confirmation (COT=7)
                        let asdu1 = Asdu {
                            type_id: TYPE_C_IC_NA_1,
                            vsq: 1,
                            cot: COT_ACTIVATION_CON,
                            originator: asdu.originator,
                            coa: asdu.coa,
                            payload: vec![0, 0, 0, qoi],
                        };
                        let apci1 = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        frames.push(build_apdu(&apci1, &asdu1.encode()));

                        // 2. M_SP_NA_1 (Type 1), Single-point information, COT=20
                        let mut p2 = Vec::with_capacity(8);
                        p2.extend_from_slice(&encode_ioa(IOA_BREAKER));
                        p2.push(if self.state.breaker_closed { 1 } else { 0 });
                        p2.extend_from_slice(&encode_ioa(IOA_SWITCH));
                        p2.push(if self.state.switch_closed { 1 } else { 0 });

                        let asdu2 = Asdu {
                            type_id: TYPE_M_SP_NA_1,
                            vsq: 2,
                            cot: COT_INTERROGATED_BY_GI,
                            originator: 0,
                            coa: asdu.coa,
                            payload: p2,
                        };
                        let apci2 = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        frames.push(build_apdu(&apci2, &asdu2.encode()));

                        // 3. M_ME_NC_1 (Type 13), Short floating point, IEEE 754, COT=20
                        let mut p3 = Vec::with_capacity(24);
                        // IOA 2001: Voltage
                        p3.extend_from_slice(&encode_ioa(IOA_VOLTAGE));
                        p3.extend_from_slice(&self.state.voltage.to_le_bytes());
                        p3.push(0x00);
                        // IOA 2002: Power
                        p3.extend_from_slice(&encode_ioa(IOA_POWER));
                        p3.extend_from_slice(&self.state.power.to_le_bytes());
                        p3.push(0x00);
                        // IOA 2003: Frequency
                        p3.extend_from_slice(&encode_ioa(IOA_FREQUENCY));
                        p3.extend_from_slice(&self.state.frequency.to_le_bytes());
                        p3.push(0x00);

                        let asdu3 = Asdu {
                            type_id: TYPE_M_ME_NC_1,
                            vsq: 3,
                            cot: COT_INTERROGATED_BY_GI,
                            originator: 0,
                            coa: asdu.coa,
                            payload: p3,
                        };
                        let apci3 = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        frames.push(build_apdu(&apci3, &asdu3.encode()));

                        // 4. Activation Termination (COT=10)
                        let asdu4 = Asdu {
                            type_id: TYPE_C_IC_NA_1,
                            vsq: 1,
                            cot: COT_ACTIVATION_TERM,
                            originator: asdu.originator,
                            coa: asdu.coa,
                            payload: vec![0, 0, 0, qoi],
                        };
                        let apci4 = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        frames.push(build_apdu(&apci4, &asdu4.encode()));

                        (frames, None)
                    }
                    TYPE_C_SC_NA_1 => {
                        // Single Command
                        if asdu.payload.len() < 4 {
                            let s_resp = build_apdu(&ApciFrame::S { nr: self.recv_seq }, &[]);
                            return (vec![s_resp], None);
                        }
                        let ioa = parse_ioa(&asdu.payload[0..3]).unwrap_or(0);
                        let sco = asdu.payload[3];
                        let val = (sco & 0x01) != 0;
                        self.state.breaker_closed = val;

                        let event_data = serde_json::json!({
                            "protocol": "iec104",
                            "type_id": 45,
                            "type_name": "C_SC_NA_1",
                            "coa": asdu.coa,
                            "ioa": ioa,
                            "cot": asdu.cot,
                            "command": "single_command",
                            "state": val,
                            "warning": "CRITICAL_ICS_BREAKER_MUTATION"
                        });

                        // Activation Confirmation (COT=7)
                        let resp_asdu = Asdu {
                            type_id: TYPE_C_SC_NA_1,
                            vsq: 1,
                            cot: COT_ACTIVATION_CON,
                            originator: asdu.originator,
                            coa: asdu.coa,
                            payload: asdu.payload.clone(),
                        };
                        let apci = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        let frame = build_apdu(&apci, &resp_asdu.encode());

                        (vec![frame], Some(event_data))
                    }
                    TYPE_C_DC_NA_1 => {
                        // Double Command
                        if asdu.payload.len() < 4 {
                            let s_resp = build_apdu(&ApciFrame::S { nr: self.recv_seq }, &[]);
                            return (vec![s_resp], None);
                        }
                        let ioa = parse_ioa(&asdu.payload[0..3]).unwrap_or(0);
                        let dco = asdu.payload[3];
                        let dcs = dco & 0x03;
                        let val = dcs == 2;
                        if dcs == 1 || dcs == 2 {
                            self.state.switch_closed = val;
                        }

                        let event_data = serde_json::json!({
                            "protocol": "iec104",
                            "type_id": 46,
                            "type_name": "C_DC_NA_1",
                            "coa": asdu.coa,
                            "ioa": ioa,
                            "cot": asdu.cot,
                            "command": "double_command",
                            "state": val,
                            "dcs": dcs,
                            "warning": "CRITICAL_ICS_BREAKER_MUTATION"
                        });

                        // Activation Confirmation (COT=7)
                        let resp_asdu = Asdu {
                            type_id: TYPE_C_DC_NA_1,
                            vsq: 1,
                            cot: COT_ACTIVATION_CON,
                            originator: asdu.originator,
                            coa: asdu.coa,
                            payload: asdu.payload.clone(),
                        };
                        let apci = ApciFrame::I { ns: self.send_seq, nr: self.recv_seq };
                        self.send_seq = (self.send_seq.wrapping_add(1)) & 0x7FFF;
                        let frame = build_apdu(&apci, &resp_asdu.encode());

                        (vec![frame], Some(event_data))
                    }
                    _unknown_type => {
                        // Unknown TypeID: safely acknowledge without crashing
                        let s_resp = build_apdu(&ApciFrame::S { nr: self.recv_seq }, &[]);
                        (vec![s_resp], None)
                    }
                }
            }
        }
    }
}

pub struct Iec104Trap {
    pub params: Value,
}

impl Iec104Trap {
    pub fn new(params: &Value) -> Result<Self, String> {
        Ok(Self {
            params: params.clone(),
        })
    }

    pub fn initial_state(&self) -> SubstationState {
        let mut state = SubstationState::default();
        if let Some(bc) = self.params.get("breaker_closed").and_then(|v| v.as_bool()) {
            state.breaker_closed = bc;
        }
        if let Some(sc) = self.params.get("switch_closed").and_then(|v| v.as_bool()) {
            state.switch_closed = sc;
        }
        if let Some(v) = self.params.get("voltage").and_then(|v| v.as_f64()) {
            state.voltage = v as f32;
        }
        if let Some(p) = self.params.get("power").and_then(|v| v.as_f64()) {
            state.power = p as f32;
        }
        if let Some(f) = self.params.get("frequency").and_then(|v| v.as_f64()) {
            state.frequency = f as f32;
        }
        state
    }

    pub async fn handle(&self, s: &mut Session) {
        super::delay(&self.params).await;

        let mut conn = Iec104Connection::new_with_state(self.initial_state());
        let mut rx_buf = Vec::new();

        loop {
            let chunk = match s.read(4096, None).await {
                Ok(data) if !data.is_empty() => data,
                _ => break,
            };
            rx_buf.extend_from_slice(&chunk);

            while rx_buf.len() >= 2 {
                if rx_buf[0] != START_BYTE {
                    if let Some(pos) = rx_buf.iter().position(|&b| b == START_BYTE) {
                        rx_buf.drain(..pos);
                    } else {
                        rx_buf.clear();
                        break;
                    }
                }

                if rx_buf.len() < 2 {
                    break;
                }

                let apdu_len = rx_buf[1] as usize;
                if apdu_len < 4 || apdu_len > 253 {
                    rx_buf.remove(0);
                    continue;
                }

                let total_len = 2 + apdu_len;
                if rx_buf.len() < total_len {
                    break;
                }

                let apdu: Vec<u8> = rx_buf.drain(..total_len).collect();
                let (responses, command_event) = conn.process_apdu(&apdu);

                if let Some(ev_data) = command_event {
                    s.emit_data("command", ev_data);
                }

                for resp in responses {
                    if s.send(&resp).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::EventSink;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_apci_encoding_decoding() {
        // U-frames
        let u_types = [STARTDT_ACT, STARTDT_CON, STOPDT_ACT, STOPDT_CON, TESTFR_ACT, TESTFR_CON];
        for &u in &u_types {
            let frame = ApciFrame::U { function: u };
            let enc = frame.encode();
            assert_eq!(enc[0], u);
            assert_eq!(enc[1..4], [0x00, 0x00, 0x00]);

            let dec = ApciFrame::decode(&enc).expect("decode U-frame");
            assert_eq!(dec, frame);
        }

        // S-frames
        for nr in [0, 1, 42, 1024, 32767] {
            let frame = ApciFrame::S { nr };
            let enc = frame.encode();
            assert_eq!(enc[0] & 0x03, 0x01);

            let dec = ApciFrame::decode(&enc).expect("decode S-frame");
            assert_eq!(dec, frame);
        }

        // I-frames
        for (ns, nr) in [(0, 0), (1, 2), (100, 200), (32767, 32767)] {
            let frame = ApciFrame::I { ns, nr };
            let enc = frame.encode();
            assert_eq!(enc[0] & 0x01, 0x00);

            let dec = ApciFrame::decode(&enc).expect("decode I-frame");
            assert_eq!(dec, frame);
        }

        // Malformed APCI
        assert!(ApciFrame::decode(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn test_u_frame_handshake_exchange() {
        let mut conn = Iec104Connection::new();
        assert!(!conn.data_transfer_active);

        // STARTDT_ACT
        let startdt_act = build_apdu(&ApciFrame::U { function: STARTDT_ACT }, &[]);
        let (resps, ev) = conn.process_apdu(&startdt_act);
        assert!(ev.is_none());
        assert_eq!(resps.len(), 1);
        assert!(conn.data_transfer_active);

        let (apci, _) = parse_apdu(&resps[0]).expect("parse response");
        assert_eq!(apci, ApciFrame::U { function: STARTDT_CON });

        // TESTFR_ACT
        let testfr_act = build_apdu(&ApciFrame::U { function: TESTFR_ACT }, &[]);
        let (resps, ev) = conn.process_apdu(&testfr_act);
        assert!(ev.is_none());
        assert_eq!(resps.len(), 1);

        let (apci, _) = parse_apdu(&resps[0]).expect("parse response");
        assert_eq!(apci, ApciFrame::U { function: TESTFR_CON });

        // STOPDT_ACT
        let stopdt_act = build_apdu(&ApciFrame::U { function: STOPDT_ACT }, &[]);
        let (resps, ev) = conn.process_apdu(&stopdt_act);
        assert!(ev.is_none());
        assert_eq!(resps.len(), 1);
        assert!(!conn.data_transfer_active);

        let (apci, _) = parse_apdu(&resps[0]).expect("parse response");
        assert_eq!(apci, ApciFrame::U { function: STOPDT_CON });
    }

    #[test]
    fn test_general_interrogation() {
        let mut conn = Iec104Connection::new();

        // General Interrogation request: Type 100, COT=6, COA=1, IOA=0, QOI=20
        let req_asdu = Asdu {
            type_id: TYPE_C_IC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload: vec![0, 0, 0, 20],
        };
        let req_apdu = build_apdu(&ApciFrame::I { ns: 0, nr: 0 }, &req_asdu.encode());

        let (resps, ev) = conn.process_apdu(&req_apdu);
        assert!(ev.is_none());
        assert_eq!(resps.len(), 4);

        // 1. Activation Confirmation (COT=7)
        let (apci1, asdu1_bytes) = parse_apdu(&resps[0]).expect("parse resp 1");
        assert_eq!(apci1, ApciFrame::I { ns: 0, nr: 1 });
        let asdu1 = Asdu::parse(&asdu1_bytes).expect("parse asdu 1");
        assert_eq!(asdu1.type_id, TYPE_C_IC_NA_1);
        assert_eq!(asdu1.cot, COT_ACTIVATION_CON);
        assert_eq!(asdu1.coa, 1);

        // 2. M_SP_NA_1 (Type 1), COT=20: IOA 1001 (breaker) and IOA 1002 (switch)
        let (apci2, asdu2_bytes) = parse_apdu(&resps[1]).expect("parse resp 2");
        assert_eq!(apci2, ApciFrame::I { ns: 1, nr: 1 });
        let asdu2 = Asdu::parse(&asdu2_bytes).expect("parse asdu 2");
        assert_eq!(asdu2.type_id, TYPE_M_SP_NA_1);
        assert_eq!(asdu2.cot, COT_INTERROGATED_BY_GI);
        assert_eq!(asdu2.vsq, 2);
        // IOA 1001
        assert_eq!(parse_ioa(&asdu2.payload[0..3]), Some(1001));
        assert_eq!(asdu2.payload[3], 1); // breaker_closed is true
        // IOA 1002
        assert_eq!(parse_ioa(&asdu2.payload[4..7]), Some(1002));
        assert_eq!(asdu2.payload[7], 1); // switch_closed is true

        // 3. M_ME_NC_1 (Type 13), COT=20: IOA 2001 (220.5), IOA 2002 (45.2), IOA 2003 (50.0)
        let (apci3, asdu3_bytes) = parse_apdu(&resps[2]).expect("parse resp 3");
        assert_eq!(apci3, ApciFrame::I { ns: 2, nr: 1 });
        let asdu3 = Asdu::parse(&asdu3_bytes).expect("parse asdu 3");
        assert_eq!(asdu3.type_id, TYPE_M_ME_NC_1);
        assert_eq!(asdu3.cot, COT_INTERROGATED_BY_GI);
        assert_eq!(asdu3.vsq, 3);
        // IOA 2001: voltage = 220.5
        assert_eq!(parse_ioa(&asdu3.payload[0..3]), Some(2001));
        let v_bytes: [u8; 4] = asdu3.payload[3..7].try_into().unwrap();
        assert_eq!(f32::from_le_bytes(v_bytes), 220.5);
        // IOA 2002: power = 45.2
        assert_eq!(parse_ioa(&asdu3.payload[8..11]), Some(2002));
        let p_bytes: [u8; 4] = asdu3.payload[11..15].try_into().unwrap();
        assert_eq!(f32::from_le_bytes(p_bytes), 45.2);
        // IOA 2003: frequency = 50.0
        assert_eq!(parse_ioa(&asdu3.payload[16..19]), Some(2003));
        let f_bytes: [u8; 4] = asdu3.payload[19..23].try_into().unwrap();
        assert_eq!(f32::from_le_bytes(f_bytes), 50.0);

        // 4. Activation Termination (COT=10)
        let (apci4, asdu4_bytes) = parse_apdu(&resps[3]).expect("parse resp 4");
        assert_eq!(apci4, ApciFrame::I { ns: 3, nr: 1 });
        let asdu4 = Asdu::parse(&asdu4_bytes).expect("parse asdu 4");
        assert_eq!(asdu4.type_id, TYPE_C_IC_NA_1);
        assert_eq!(asdu4.cot, COT_ACTIVATION_TERM);
        assert_eq!(asdu4.coa, 1);
    }

    #[test]
    fn test_single_command() {
        let mut conn = Iec104Connection::new();
        assert!(conn.state.breaker_closed);

        // Send C_SC_NA_1 to open breaker (bit 0 = 0)
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_ioa(IOA_BREAKER));
        payload.push(0x00); // SCO: SCS = 0 (open)
        let req_asdu = Asdu {
            type_id: TYPE_C_SC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload,
        };
        let req_apdu = build_apdu(&ApciFrame::I { ns: 0, nr: 0 }, &req_asdu.encode());

        let (resps, ev) = conn.process_apdu(&req_apdu);
        assert_eq!(resps.len(), 1);
        assert!(!conn.state.breaker_closed); // State mutated

        // Response confirmation
        let (_, asdu_bytes) = parse_apdu(&resps[0]).expect("parse single command response");
        let asdu = Asdu::parse(&asdu_bytes).expect("parse asdu");
        assert_eq!(asdu.type_id, TYPE_C_SC_NA_1);
        assert_eq!(asdu.cot, COT_ACTIVATION_CON);
        assert_eq!(asdu.payload[3], 0x00);

        // Event validation
        let event = ev.expect("command event expected");
        assert_eq!(event["protocol"], "iec104");
        assert_eq!(event["type_id"], 45);
        assert_eq!(event["type_name"], "C_SC_NA_1");
        assert_eq!(event["command"], "single_command");
        assert_eq!(event["state"], false);
        assert_eq!(event["warning"], "CRITICAL_ICS_BREAKER_MUTATION");
        assert_eq!(event["coa"], 1);
        assert_eq!(event["ioa"], 1001);

        // Send C_SC_NA_1 to close breaker (bit 0 = 1)
        let mut payload2 = Vec::new();
        payload2.extend_from_slice(&encode_ioa(IOA_BREAKER));
        payload2.push(0x01); // SCO: SCS = 1 (close)
        let req_asdu2 = Asdu {
            type_id: TYPE_C_SC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload: payload2,
        };
        let req_apdu2 = build_apdu(&ApciFrame::I { ns: 1, nr: 1 }, &req_asdu2.encode());
        let (_, ev2) = conn.process_apdu(&req_apdu2);
        assert!(conn.state.breaker_closed);
        let event2 = ev2.expect("second event");
        assert_eq!(event2["state"], true);
    }

    #[test]
    fn test_double_command() {
        let mut conn = Iec104Connection::new();
        assert!(conn.state.switch_closed);

        // Send C_DC_NA_1 to open switch (DCS = 1: off)
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_ioa(IOA_SWITCH));
        payload.push(0x01); // DCO: DCS = 1
        let req_asdu = Asdu {
            type_id: TYPE_C_DC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload,
        };
        let req_apdu = build_apdu(&ApciFrame::I { ns: 0, nr: 0 }, &req_asdu.encode());

        let (resps, ev) = conn.process_apdu(&req_apdu);
        assert_eq!(resps.len(), 1);
        assert!(!conn.state.switch_closed);

        let (_, asdu_bytes) = parse_apdu(&resps[0]).expect("parse double command response");
        let asdu = Asdu::parse(&asdu_bytes).expect("parse asdu");
        assert_eq!(asdu.type_id, TYPE_C_DC_NA_1);
        assert_eq!(asdu.cot, COT_ACTIVATION_CON);
        assert_eq!(asdu.payload[3], 0x01);

        let event = ev.expect("command event expected");
        assert_eq!(event["protocol"], "iec104");
        assert_eq!(event["type_id"], 46);
        assert_eq!(event["type_name"], "C_DC_NA_1");
        assert_eq!(event["command"], "double_command");
        assert_eq!(event["state"], false);

        // Send C_DC_NA_1 to close switch (DCS = 2: on)
        let mut payload2 = Vec::new();
        payload2.extend_from_slice(&encode_ioa(IOA_SWITCH));
        payload2.push(0x02); // DCO: DCS = 2
        let req_asdu2 = Asdu {
            type_id: TYPE_C_DC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload: payload2,
        };
        let req_apdu2 = build_apdu(&ApciFrame::I { ns: 1, nr: 1 }, &req_asdu2.encode());
        let (_, ev2) = conn.process_apdu(&req_apdu2);
        assert!(conn.state.switch_closed);
        let event2 = ev2.expect("second event");
        assert_eq!(event2["state"], true);
    }

    #[test]
    fn test_malformed_frames_no_panic() {
        let mut conn = Iec104Connection::new();

        let malformed_samples: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x68],
            vec![0x68, 0x00],
            vec![0x68, 0x01, 0x00],
            vec![0x99, 0x04, 0x07, 0x00, 0x00, 0x00],
            vec![0x68, 0x04, 0x07], // truncated
            vec![0x68, 0x10, 0x00, 0x00, 0x00, 0x00], // invalid length
            vec![0x68, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02], // corrupted ASDU
        ];

        for sample in malformed_samples {
            let (resps, ev) = conn.process_apdu(&sample);
            let _ = resps;
            let _ = ev;
        }
    }

    #[tokio::test]
    async fn test_full_session_network_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (sink, rx) = EventSink::test_sink();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session = Session::new(
                stream,
                port,
                sink,
                "iec104",
                "substation01".to_string(),
                5.0,
            );
            let trap = Iec104Trap::new(&serde_json::json!({})).unwrap();
            trap.handle(&mut session).await;
        });

        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

        // 1. Handshake STARTDT_ACT -> STARTDT_CON
        let startdt = build_apdu(&ApciFrame::U { function: STARTDT_ACT }, &[]);
        client.write_all(&startdt).await.unwrap();
        let mut buf = vec![0u8; 6];
        client.read_exact(&mut buf).await.unwrap();
        let (apci, _) = parse_apdu(&buf).unwrap();
        assert_eq!(apci, ApciFrame::U { function: STARTDT_CON });

        // 2. Single Command to toggle breaker
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_ioa(IOA_BREAKER));
        payload.push(0x00); // open breaker
        let sc_asdu = Asdu {
            type_id: TYPE_C_SC_NA_1,
            vsq: 1,
            cot: COT_ACTIVATION,
            originator: 0,
            coa: 1,
            payload,
        };
        let sc_apdu = build_apdu(&ApciFrame::I { ns: 0, nr: 0 }, &sc_asdu.encode());
        client.write_all(&sc_apdu).await.unwrap();

        let mut resp_buf = vec![0u8; sc_apdu.len()];
        client.read_exact(&mut resp_buf).await.unwrap();
        let (_, asdu_bytes) = parse_apdu(&resp_buf).unwrap();
        let resp_asdu = Asdu::parse(&asdu_bytes).unwrap();
        assert_eq!(resp_asdu.type_id, TYPE_C_SC_NA_1);
        assert_eq!(resp_asdu.cot, COT_ACTIVATION_CON);

        // Verify event was received in sink
        let ev = rx.try_recv().expect("event received in sink");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.data["command"], "single_command");
        assert_eq!(ev.data["state"], false);

        // Close client connection
        drop(client);
        server_task.await.unwrap();
    }
}
