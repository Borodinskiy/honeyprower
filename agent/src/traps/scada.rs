//! SCADA (Modbus TCP / Industrial HMI) honeypot trap implementation.

use crate::config::Params;
use crate::event::event_type;
use crate::session::Session;
use serde_json::{json, Value};
use std::sync::{Arc, RwLock};

pub const DEFAULT_REGISTERS_COUNT: usize = 1000;
pub const DEFAULT_COILS_COUNT: usize = 1000;

#[derive(Clone, Debug)]
pub struct PlcState {
    pub holding_registers: Vec<u16>,
    pub input_registers: Vec<u16>,
    pub coils: Vec<bool>,
    pub discrete_inputs: Vec<bool>,
}

impl Default for PlcState {
    fn default() -> Self {
        let mut holding_registers = vec![0u16; DEFAULT_REGISTERS_COUNT];
        let mut input_registers = vec![0u16; DEFAULT_REGISTERS_COUNT];
        let mut coils = vec![false; DEFAULT_COILS_COUNT];
        let mut discrete_inputs = vec![false; DEFAULT_COILS_COUNT];

        // Process image defaults representing a substation PLC / RTU
        // Holding registers (addresses 0..100)
        holding_registers[0] = 22000; // Substation bus voltage (220.00 V / 100x scale)
        holding_registers[1] = 1500;  // Current (15.00 A)
        holding_registers[2] = 5000;  // Grid Frequency (50.00 Hz)
        holding_registers[3] = 68;    // Transformer temperature (68 °C)
        holding_registers[4] = 0;     // Alarm state (0 = normal)

        // Input registers (telemetry)
        input_registers[0] = 22000;
        input_registers[1] = 1500;
        input_registers[2] = 5000;
        input_registers[3] = 68;
        input_registers[4] = 0;

        // Coils
        coils[0] = true; // Main Breaker Q0 (1 = Closed, 0 = Tripped)
        coils[1] = true; // Cooling Fan (1 = Auto, 0 = Manual)

        // Discrete Inputs (contacts)
        discrete_inputs[0] = true;  // Breaker auxiliary contact (Closed)
        discrete_inputs[1] = true;  // Substation door interlock (Closed)
        discrete_inputs[2] = false; // Overcurrent alarm contact

        Self {
            holding_registers,
            input_registers,
            coils,
            discrete_inputs,
        }
    }
}

pub struct ScadaTrap {
    pub state: Arc<RwLock<PlcState>>,
    pub vendor_name: String,
    pub product_code: String,
    pub revision: String,
    pub params: Value,
}

impl ScadaTrap {
    pub fn new(params: &Value) -> Result<Self, String> {
        let p = Params(params);
        let vendor_name = p.str("vendor_name", "Schneider Electric");
        let product_code = p.str("product_code", "Modicon M580");
        let revision = p.str("revision", "v4.10");

        Ok(Self {
            state: Arc::new(RwLock::new(PlcState::default())),
            vendor_name,
            product_code,
            revision,
            params: params.clone(),
        })
    }

    /// Construct a Modbus exception response frame
    pub fn make_exception_response(tx_id: u16, unit_id: u8, fc: u8, exception_code: u8) -> Vec<u8> {
        let mut resp = Vec::with_capacity(9);
        resp.extend_from_slice(&tx_id.to_be_bytes()); // 0..2
        resp.extend_from_slice(&0u16.to_be_bytes());   // 2..4: Protocol ID 0x0000
        resp.extend_from_slice(&3u16.to_be_bytes());   // 4..6: Length = 3 (Unit ID + 2 bytes PDU)
        resp.push(unit_id);                            // 6: Unit ID
        resp.push(fc | 0x80);                          // 7: Function code with MSB set
        resp.push(exception_code);                     // 8: Exception code
        resp
    }

    /// Construct a successful Modbus response frame
    pub fn make_modbus_response(tx_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
        let mut resp = Vec::with_capacity(7 + pdu.len());
        let length = (1 + pdu.len()) as u16;
        resp.extend_from_slice(&tx_id.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes()); // Protocol ID 0x0000
        resp.extend_from_slice(&length.to_be_bytes());
        resp.push(unit_id);
        resp.extend_from_slice(pdu);
        resp
    }

    /// Process a single complete Modbus TCP request frame
    pub fn handle_modbus_frame(&self, frame: &[u8], s: Option<&Session>) -> Option<Vec<u8>> {
        if frame.len() < 8 {
            if frame.len() >= 7 {
                let tx_id = u16::from_be_bytes([frame[0], frame[1]]);
                let unit_id = frame[6];
                return Some(Self::make_exception_response(tx_id, unit_id, 0, 0x03));
            }
            return None;
        }

        let tx_id = u16::from_be_bytes([frame[0], frame[1]]);
        let proto_id = u16::from_be_bytes([frame[2], frame[3]]);
        let unit_id = frame[6];
        let fc = frame[7];
        let data = &frame[8..];

        if proto_id != 0 {
            return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
        }

        match fc {
            // 0x01: Read Coils
            0x01 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                if quantity == 0 || quantity > 2000 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let state = self.state.read().unwrap();
                if addr as usize + quantity as usize > state.coils.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                let byte_count = ((quantity + 7) / 8) as usize;
                let mut coil_bytes = vec![0u8; byte_count];
                for i in 0..quantity as usize {
                    if state.coils[addr as usize + i] {
                        coil_bytes[i / 8] |= 1 << (i % 8);
                    }
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::REQUEST,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 1,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                let mut pdu = Vec::with_capacity(2 + byte_count);
                pdu.push(0x01);
                pdu.push(byte_count as u8);
                pdu.extend_from_slice(&coil_bytes);
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x02: Read Discrete Inputs
            0x02 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                if quantity == 0 || quantity > 2000 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let state = self.state.read().unwrap();
                if addr as usize + quantity as usize > state.discrete_inputs.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                let byte_count = ((quantity + 7) / 8) as usize;
                let mut input_bytes = vec![0u8; byte_count];
                for i in 0..quantity as usize {
                    if state.discrete_inputs[addr as usize + i] {
                        input_bytes[i / 8] |= 1 << (i % 8);
                    }
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::REQUEST,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 2,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                let mut pdu = Vec::with_capacity(2 + byte_count);
                pdu.push(0x02);
                pdu.push(byte_count as u8);
                pdu.extend_from_slice(&input_bytes);
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x03: Read Holding Registers
            0x03 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                if quantity == 0 || quantity > 125 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let state = self.state.read().unwrap();
                if addr as usize + quantity as usize > state.holding_registers.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                let byte_count = (quantity * 2) as usize;
                let mut reg_bytes = Vec::with_capacity(byte_count);
                for i in 0..quantity as usize {
                    let val = state.holding_registers[addr as usize + i];
                    reg_bytes.extend_from_slice(&val.to_be_bytes());
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::REQUEST,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 3,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                let mut pdu = Vec::with_capacity(2 + byte_count);
                pdu.push(0x03);
                pdu.push(byte_count as u8);
                pdu.extend_from_slice(&reg_bytes);
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x04: Read Input Registers
            0x04 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                if quantity == 0 || quantity > 125 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let state = self.state.read().unwrap();
                if addr as usize + quantity as usize > state.input_registers.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                let byte_count = (quantity * 2) as usize;
                let mut reg_bytes = Vec::with_capacity(byte_count);
                for i in 0..quantity as usize {
                    let val = state.input_registers[addr as usize + i];
                    reg_bytes.extend_from_slice(&val.to_be_bytes());
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::REQUEST,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 4,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                let mut pdu = Vec::with_capacity(2 + byte_count);
                pdu.push(0x04);
                pdu.push(byte_count as u8);
                pdu.extend_from_slice(&reg_bytes);
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x05: Write Single Coil
            0x05 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let val = u16::from_be_bytes([data[2], data[3]]);
                if val != 0xFF00 && val != 0x0000 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let mut state = self.state.write().unwrap();
                if addr as usize >= state.coils.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                state.coils[addr as usize] = val == 0xFF00;
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::COMMAND,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 5,
                            "address": addr,
                            "value": val,
                            "unit_id": unit_id
                        }),
                    );
                }
                // Echo back request frame
                let pdu = [0x05, data[0], data[1], data[2], data[3]];
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x06: Write Single Register
            0x06 => {
                if data.len() != 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let val = u16::from_be_bytes([data[2], data[3]]);
                let mut state = self.state.write().unwrap();
                if addr as usize >= state.holding_registers.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                state.holding_registers[addr as usize] = val;
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::COMMAND,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 6,
                            "address": addr,
                            "value": val,
                            "unit_id": unit_id
                        }),
                    );
                }
                // Echo back request frame
                let pdu = [0x06, data[0], data[1], data[2], data[3]];
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x0F: Write Multiple Coils
            0x0F => {
                if data.len() < 5 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                let byte_count = data[4] as usize;
                if quantity == 0 || quantity > 1968 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let expected_bytes = (quantity as usize + 7) / 8;
                if byte_count != expected_bytes || data.len() != 5 + byte_count {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let mut state = self.state.write().unwrap();
                if addr as usize + quantity as usize > state.coils.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                for i in 0..quantity as usize {
                    let bit = (data[5 + i / 8] >> (i % 8)) & 1;
                    state.coils[addr as usize + i] = bit == 1;
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::COMMAND,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 15,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                // Confirmation: echo fc, addr, quantity
                let pdu = [0x0F, data[0], data[1], data[2], data[3]];
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x10: Write Multiple Registers
            0x10 => {
                if data.len() < 5 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let addr = u16::from_be_bytes([data[0], data[1]]);
                let quantity = u16::from_be_bytes([data[2], data[3]]);
                let byte_count = data[4] as usize;
                if quantity == 0 || quantity > 123 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let expected_bytes = quantity as usize * 2;
                if byte_count != expected_bytes || data.len() != 5 + byte_count {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let mut state = self.state.write().unwrap();
                if addr as usize + quantity as usize > state.holding_registers.len() {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }
                for i in 0..quantity as usize {
                    let val = u16::from_be_bytes([data[5 + 2 * i], data[5 + 2 * i + 1]]);
                    state.holding_registers[addr as usize + i] = val;
                }
                drop(state);
                if let Some(s) = s {
                    s.emit_data(
                        event_type::COMMAND,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 16,
                            "address": addr,
                            "quantity": quantity,
                            "unit_id": unit_id
                        }),
                    );
                }
                // Confirmation: echo fc, addr, quantity
                let pdu = [0x10, data[0], data[1], data[2], data[3]];
                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // 0x2B: Encapsulated Interface Transport (MEI)
            0x2B => {
                if data.len() < 3 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                let mei_type = data[0];
                if mei_type != 0x0E {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x01));
                }
                let read_device_id_code = data[1];
                let object_id = data[2];

                if read_device_id_code < 1 || read_device_id_code > 4 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x03));
                }
                if object_id > 2 {
                    return Some(Self::make_exception_response(tx_id, unit_id, fc, 0x02));
                }

                if let Some(s) = s {
                    s.emit_data(
                        event_type::SCAN,
                        json!({
                            "protocol": "modbus_tcp",
                            "function_code": 43,
                            "mei_type": 14,
                            "read_device_id_code": read_device_id_code,
                            "object_id": object_id,
                            "unit_id": unit_id
                        }),
                    );
                }

                let objects: [(&str, u8); 3] = [
                    (&self.vendor_name, 0x00),
                    (&self.product_code, 0x01),
                    (&self.revision, 0x02),
                ];

                let mut pdu = Vec::with_capacity(64);
                pdu.push(0x2B);
                pdu.push(0x0E);
                pdu.push(read_device_id_code);
                pdu.push(0x83); // conformity level
                pdu.push(0x00); // more follows
                pdu.push(0x00); // next object id

                if read_device_id_code == 0x04 {
                    // Individual access
                    let (val, id) = objects[object_id as usize];
                    pdu.push(1); // num objects
                    pdu.push(id);
                    pdu.push(val.len() as u8);
                    pdu.extend_from_slice(val.as_bytes());
                } else {
                    // Stream access (from object_id up to 2)
                    let slice = &objects[object_id as usize..];
                    pdu.push(slice.len() as u8);
                    for (val, id) in slice {
                        pdu.push(*id);
                        pdu.push(val.len() as u8);
                        pdu.extend_from_slice(val.as_bytes());
                    }
                }

                Some(Self::make_modbus_response(tx_id, unit_id, &pdu))
            }

            // Unknown function code: Illegal Function exception
            _ => Some(Self::make_exception_response(tx_id, unit_id, fc, 0x01)),
        }
    }

    async fn handle_http(&self, s: &mut Session, buf: &mut Vec<u8>) {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && !buf.windows(2).any(|w| w == b"\n\n") {
            match s.read(1024, Some(1.0)).await {
                Ok(more) if !more.is_empty() => buf.extend_from_slice(&more),
                _ => break,
            }
        }

        let text = String::from_utf8_lossy(buf);
        let mut lines = text.lines();
        let req_line = lines.next().unwrap_or("");
        let mut parts = req_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let raw_path = parts.next().unwrap_or("/");
        let path = raw_path.split('?').next().unwrap_or("/");

        s.emit_data(
            event_type::REQUEST,
            json!({
                "protocol": "http",
                "method": method,
                "path": path,
                "scada_hmi": true
            }),
        );

        crate::traps::delay(&self.params).await;

        let (v, i, f, t, a, breaker, fan) = {
            let state = self.state.read().unwrap();
            (
                state.holding_registers.first().copied().unwrap_or(22000) as f64 / 100.0,
                state.holding_registers.get(1).copied().unwrap_or(1500) as f64 / 100.0,
                state.holding_registers.get(2).copied().unwrap_or(5000) as f64 / 100.0,
                state.holding_registers.get(3).copied().unwrap_or(68),
                state.holding_registers.get(4).copied().unwrap_or(0),
                if state.coils.first().copied().unwrap_or(true) { "CLOSED" } else { "TRIPPED" },
                if state.coils.get(1).copied().unwrap_or(true) { "AUTO" } else { "MANUAL" },
            )
        };

        let (status, content_type, body) = if path.starts_with("/api/") {
            let json_body = json!({
                "device": format!("{} {}", self.vendor_name, self.product_code),
                "firmware": self.revision,
                "status": "OPERATIONAL",
                "tags": {
                    "voltage_v": v,
                    "current_a": i,
                    "frequency_hz": f,
                    "temperature_c": t,
                    "alarm": a,
                    "breaker_q0": breaker,
                    "cooling_fan": fan
                }
            });
            (200, "application/json", json_body.to_string())
        } else {
            let alarm_badge = if a == 0 {
                r#"<span class="status-ok">NORMAL (0)</span>"#
            } else {
                r#"<span class="status-alarm">ALARM ACTIVE</span>"#
            };
            let breaker_badge = if breaker == "CLOSED" {
                r#"<span class="status-ok">CLOSED (1)</span>"#
            } else {
                r#"<span class="status-alarm">TRIPPED (0)</span>"#
            };
            let fan_badge = if fan == "AUTO" {
                r#"<span class="status-ok">AUTO (1)</span>"#
            } else {
                r#"<span>MANUAL (0)</span>"#
            };

            let html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Substation SCADA Gateway - Web HMI</title>
<style>
body {{ font-family: monospace, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; margin: 0; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 8px; font-size: 22px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #21262d; }}
th {{ background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 12px; }}
.status-ok {{ color: #3fb950; font-weight: bold; }}
.status-alarm {{ color: #f85149; font-weight: bold; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; }}
</style>
</head>
<body>
<h1>Substation SCADA Gateway - Web HMI</h1>
<div class="card">
  <strong>System Status:</strong> <span class="status-ok badge">OPERATIONAL</span> &nbsp;|&nbsp;
  <strong>Vendor:</strong> {vendor} &nbsp;|&nbsp;
  <strong>Device:</strong> {product} &nbsp;|&nbsp;
  <strong>Firmware:</strong> {rev}
</div>
<div class="card">
  <h3>Process Image Telemetry &amp; Actuators</h3>
  <table>
    <thead>
      <tr><th>Tag Description</th><th>Modbus Address</th><th>Live Value</th><th>Unit / State</th></tr>
    </thead>
    <tbody>
      <tr><td>Substation Bus Voltage</td><td>40001 (HR 0)</td><td>{v:.2}</td><td>V AC</td></tr>
      <tr><td>Feeder Load Current</td><td>40002 (HR 1)</td><td>{i:.2}</td><td>A</td></tr>
      <tr><td>Grid Frequency</td><td>40003 (HR 2)</td><td>{f:.2}</td><td>Hz</td></tr>
      <tr><td>Transformer Winding Temp</td><td>40004 (HR 3)</td><td>{t}</td><td>&deg;C</td></tr>
      <tr><td>Substation Alarm Contact</td><td>40005 (HR 4)</td><td>{a}</td><td>{alarm_badge}</td></tr>
      <tr><td>Main Feeder Breaker Q0</td><td>00001 (Coil 0)</td><td>{breaker}</td><td>{breaker_badge}</td></tr>
      <tr><td>Cooling Fan Bank 1</td><td>00002 (Coil 1)</td><td>{fan}</td><td>{fan_badge}</td></tr>
    </tbody>
  </table>
</div>
<div class="card" style="font-size: 11px; color: #8b949e;">
  Modbus TCP Port 502 / IEC 61850 Station Bus Gateway Active
</div>
</body>
</html>"#,
                vendor = self.vendor_name,
                product = self.product_code,
                rev = self.revision,
                v = v,
                i = i,
                f = f,
                t = t,
                a = a,
                breaker = breaker,
                fan = fan,
                alarm_badge = alarm_badge,
                breaker_badge = breaker_badge,
                fan_badge = fan_badge,
            );
            (200, "text/html; charset=utf-8", html)
        };

        let resp = format!(
            "HTTP/1.1 {status} OK\r\nServer: {vendor}-Gateway/{rev}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            vendor = self.vendor_name,
            rev = self.revision,
            len = body.len()
        );

        let _ = s.send(resp.as_bytes()).await;
    }

    pub async fn handle(&self, s: &mut Session) {
        let mut buf: Vec<u8> = Vec::new();
        let mut is_first_read = true;

        loop {
            let chunk = match s.read(4096, None).await {
                Ok(c) => c,
                Err(_) => break,
            };
            if chunk.is_empty() {
                break;
            }
            buf.extend_from_slice(&chunk);

            if is_first_read {
                is_first_read = false;
                if buf.starts_with(b"GET ")
                    || buf.starts_with(b"POST ")
                    || buf.starts_with(b"HEAD ")
                    || buf.starts_with(b"OPTIONS ")
                    || buf.starts_with(b"PUT ")
                {
                    self.handle_http(s, &mut buf).await;
                    break;
                }
            }

            // Process Modbus frames in buffer
            while buf.len() >= 7 {
                let proto_id = u16::from_be_bytes([buf[2], buf[3]]);
                let len_field = u16::from_be_bytes([buf[4], buf[5]]) as usize;

                if proto_id != 0 || len_field < 2 || len_field > 300 {
                    // Malformed packet
                    let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
                    let unit_id = buf[6];
                    let fc = if buf.len() > 7 { buf[7] } else { 0 };
                    let resp = Self::make_exception_response(tx_id, unit_id, fc, 0x03);
                    let _ = s.send(&resp).await;
                    buf.clear();
                    break;
                }

                let total_frame_len = 6 + len_field;
                if buf.len() < total_frame_len {
                    // Need more bytes for this frame
                    break;
                }

                let frame: Vec<u8> = buf.drain(..total_frame_len).collect();
                if let Some(resp) = self.handle_modbus_frame(&frame, Some(s)) {
                    crate::traps::delay(&self.params).await;
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
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_trap() -> ScadaTrap {
        ScadaTrap::new(&json!({})).unwrap()
    }

    // Helper: build standard modbus TCP request
    fn build_mbap_request(tx_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&tx_id.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes()); // Protocol ID: 0x0000
        let len = (1 + pdu.len()) as u16;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.push(unit_id);
        frame.extend_from_slice(pdu);
        frame
    }

    #[test]
    fn test_read_holding_registers_fc03() {
        let trap = test_trap();
        // Read 5 holding registers starting from address 0
        let pdu = [0x03, 0x00, 0x00, 0x00, 0x05];
        let req = build_mbap_request(1, 1, &pdu);

        let resp = trap.handle_modbus_frame(&req, None).expect("response");
        assert_eq!(resp.len(), 7 + 1 + 1 + 10); // MBAP(7) + FC(1) + ByteCount(1) + 10 bytes data
        assert_eq!(&resp[0..2], &1u16.to_be_bytes()); // tx_id
        assert_eq!(&resp[2..4], &[0x00, 0x00]); // proto_id
        assert_eq!(resp[6], 1); // unit_id
        assert_eq!(resp[7], 0x03); // fc
        assert_eq!(resp[8], 10); // byte_count

        // Verify register values:
        // Reg 0: 22000 (0x55F0)
        // Reg 1: 1500 (0x05DC)
        // Reg 2: 5000 (0x1388)
        // Reg 3: 68 (0x0044)
        // Reg 4: 0 (0x0000)
        let r0 = u16::from_be_bytes([resp[9], resp[10]]);
        let r1 = u16::from_be_bytes([resp[11], resp[12]]);
        let r2 = u16::from_be_bytes([resp[13], resp[14]]);
        let r3 = u16::from_be_bytes([resp[15], resp[16]]);
        let r4 = u16::from_be_bytes([resp[17], resp[18]]);
        assert_eq!(r0, 22000);
        assert_eq!(r1, 1500);
        assert_eq!(r2, 5000);
        assert_eq!(r3, 68);
        assert_eq!(r4, 0);
    }

    #[test]
    fn test_read_input_registers_fc04() {
        let trap = test_trap();
        // Read 4 input registers starting from address 0
        let pdu = [0x04, 0x00, 0x00, 0x00, 0x04];
        let req = build_mbap_request(2, 1, &pdu);

        let resp = trap.handle_modbus_frame(&req, None).expect("response");
        assert_eq!(resp[7], 0x04);
        assert_eq!(resp[8], 8); // 4 registers * 2 = 8 bytes
        let r0 = u16::from_be_bytes([resp[9], resp[10]]);
        let r1 = u16::from_be_bytes([resp[11], resp[12]]);
        let r2 = u16::from_be_bytes([resp[13], resp[14]]);
        let r3 = u16::from_be_bytes([resp[15], resp[16]]);
        assert_eq!(r0, 22000);
        assert_eq!(r1, 1500);
        assert_eq!(r2, 5000);
        assert_eq!(r3, 68);
    }

    #[test]
    fn test_read_coils_fc01_and_discrete_inputs_fc02() {
        let trap = test_trap();
        // Read 2 coils at address 0
        let req_coils = build_mbap_request(3, 1, &[0x01, 0x00, 0x00, 0x00, 0x02]);
        let resp_coils = trap.handle_modbus_frame(&req_coils, None).expect("response");
        assert_eq!(resp_coils[7], 0x01);
        assert_eq!(resp_coils[8], 1); // byte count
        // Both coil 0 (breaker) and coil 1 (fan) are true -> 0x03
        assert_eq!(resp_coils[9], 0x03);

        // Read 2 discrete inputs at address 0
        let req_di = build_mbap_request(4, 1, &[0x02, 0x00, 0x00, 0x00, 0x02]);
        let resp_di = trap.handle_modbus_frame(&req_di, None).expect("response");
        assert_eq!(resp_di[7], 0x02);
        assert_eq!(resp_di[8], 1);
        assert_eq!(resp_di[9], 0x03);
    }

    #[test]
    fn test_write_single_register_fc06_and_event() {
        let trap = test_trap();
        // Write register 0 to 23516 (0x5BDC)
        let pdu = [0x06, 0x00, 0x00, 0x5B, 0xDC];
        let req = build_mbap_request(5, 1, &pdu);

        let resp = trap.handle_modbus_frame(&req, None).expect("response");
        // Must echo back the request frame
        assert_eq!(resp, req);

        // Check internal PLC state mutated
        let state = trap.state.read().unwrap();
        assert_eq!(state.holding_registers[0], 23516);
    }

    #[test]
    fn test_write_single_coil_fc05_and_event() {
        let trap = test_trap();
        // Initial state: coil 0 is true (closed)
        assert!(trap.state.read().unwrap().coils[0]);

        // Write coil 0 to OFF (0x0000)
        let pdu_off = [0x05, 0x00, 0x00, 0x00, 0x00];
        let req_off = build_mbap_request(6, 1, &pdu_off);
        let resp_off = trap.handle_modbus_frame(&req_off, None).expect("response");
        assert_eq!(resp_off, req_off);
        assert!(!trap.state.read().unwrap().coils[0]);

        // Write coil 0 to ON (0xFF00)
        let pdu_on = [0x05, 0x00, 0x00, 0xFF, 0x00];
        let req_on = build_mbap_request(7, 1, &pdu_on);
        let resp_on = trap.handle_modbus_frame(&req_on, None).expect("response");
        assert_eq!(resp_on, req_on);
        assert!(trap.state.read().unwrap().coils[0]);
    }

    #[test]
    fn test_write_multiple_coils_fc0f_and_registers_fc10() {
        let trap = test_trap();
        // Write coils 0..2: coil 0=false, coil 1=true, coil 2=true -> binary 0b110 = 0x06
        let pdu_mc = [0x0F, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06];
        let req_mc = build_mbap_request(8, 1, &pdu_mc);
        let resp_mc = trap.handle_modbus_frame(&req_mc, None).expect("response");
        assert_eq!(resp_mc[7], 0x0F);
        assert_eq!(&resp_mc[8..12], &[0x00, 0x00, 0x00, 0x03]); // echoes addr and qty
        {
            let st = trap.state.read().unwrap();
            assert!(!st.coils[0]);
            assert!(st.coils[1]);
            assert!(st.coils[2]);
        }

        // Write multiple registers 0..2 to [1111, 2222]
        let pdu_mr = [0x10, 0x00, 0x00, 0x00, 0x02, 0x04, 0x04, 0x57, 0x08, 0xAE];
        let req_mr = build_mbap_request(9, 1, &pdu_mr);
        let resp_mr = trap.handle_modbus_frame(&req_mr, None).expect("response");
        assert_eq!(resp_mr[7], 0x10);
        assert_eq!(&resp_mr[8..12], &[0x00, 0x00, 0x00, 0x02]);
        {
            let st = trap.state.read().unwrap();
            assert_eq!(st.holding_registers[0], 1111);
            assert_eq!(st.holding_registers[1], 2222);
        }
    }

    #[test]
    fn test_read_device_identification_mei() {
        let trap = test_trap();
        // Request basic stream device identification: FC 0x2B, MEI 0x0E, Read Device ID 0x01, Object 0x00
        let pdu = [0x2B, 0x0E, 0x01, 0x00];
        let req = build_mbap_request(10, 1, &pdu);

        let resp = trap.handle_modbus_frame(&req, None).expect("response");
        assert_eq!(resp[7], 0x2B); // FC
        assert_eq!(resp[8], 0x0E); // MEI Type
        assert_eq!(resp[9], 0x01); // Read Device ID code
        assert_eq!(resp[10], 0x83); // Conformity level
        assert_eq!(resp[11], 0x00); // More follows
        assert_eq!(resp[12], 0x00); // Next object ID
        assert_eq!(resp[13], 3); // Number of objects

        // Parse objects
        let mut idx = 14;
        let mut found_vendor = false;
        let mut found_product = false;
        let mut found_rev = false;

        for _ in 0..3 {
            let obj_id = resp[idx];
            let obj_len = resp[idx + 1] as usize;
            let obj_val = String::from_utf8_lossy(&resp[idx + 2..idx + 2 + obj_len]);
            idx += 2 + obj_len;

            match obj_id {
                0 => {
                    assert_eq!(obj_val, "Schneider Electric");
                    found_vendor = true;
                }
                1 => {
                    assert_eq!(obj_val, "Modicon M580");
                    found_product = true;
                }
                2 => {
                    assert_eq!(obj_val, "v4.10");
                    found_rev = true;
                }
                _ => {}
            }
        }

        assert!(found_vendor && found_product && found_rev);

        // Test individual object read (code 0x04, object 1 = ProductCode)
        let pdu_ind = [0x2B, 0x0E, 0x04, 0x01];
        let req_ind = build_mbap_request(11, 1, &pdu_ind);
        let resp_ind = trap.handle_modbus_frame(&req_ind, None).expect("response");
        assert_eq!(resp_ind[13], 1); // 1 object
        assert_eq!(resp_ind[14], 0x01); // object id 1
        let p_len = resp_ind[15] as usize;
        let p_name = String::from_utf8_lossy(&resp_ind[16..16 + p_len]);
        assert_eq!(p_name, "Modicon M580");
    }

    #[test]
    fn test_malformed_packets_and_exceptions() {
        let trap = test_trap();

        // 1. Unknown Function code (e.g. 0x19) -> Exception 0x01 (Illegal Function)
        let req_unsupported = build_mbap_request(12, 1, &[0x19, 0x00, 0x00]);
        let resp = trap.handle_modbus_frame(&req_unsupported, None).expect("response");
        assert_eq!(resp[7], 0x19 | 0x80); // 0x99
        assert_eq!(resp[8], 0x01); // Illegal Function

        // 2. Read Holding Registers with Quantity = 0 -> Exception 0x03 (Illegal Data Value)
        let req_zero_qty = build_mbap_request(13, 1, &[0x03, 0x00, 0x00, 0x00, 0x00]);
        let resp_zero = trap.handle_modbus_frame(&req_zero_qty, None).expect("response");
        assert_eq!(resp_zero[7], 0x83);
        assert_eq!(resp_zero[8], 0x03);

        // 3. Read Holding Registers beyond max address -> Exception 0x02 (Illegal Data Address)
        let req_oob = build_mbap_request(14, 1, &[0x03, 0x27, 0x10, 0x00, 0x05]); // addr 10000
        let resp_oob = trap.handle_modbus_frame(&req_oob, None).expect("response");
        assert_eq!(resp_oob[7], 0x83);
        assert_eq!(resp_oob[8], 0x02);

        // 4. Write Single Coil with invalid value (e.g. 0x1234) -> Exception 0x03
        let req_bad_coil = build_mbap_request(15, 1, &[0x05, 0x00, 0x00, 0x12, 0x34]);
        let resp_bad_coil = trap.handle_modbus_frame(&req_bad_coil, None).expect("response");
        assert_eq!(resp_bad_coil[7], 0x85);
        assert_eq!(resp_bad_coil[8], 0x03);

        // 5. Non-zero Protocol ID -> Exception 0x03
        let mut req_bad_proto = build_mbap_request(16, 1, &[0x03, 0x00, 0x00, 0x00, 0x01]);
        req_bad_proto[2] = 0x01; // corrupt proto id
        let resp_bad_proto = trap.handle_modbus_frame(&req_bad_proto, None).expect("response");
        assert_eq!(resp_bad_proto[7], 0x83);
        assert_eq!(resp_bad_proto[8], 0x03);
    }

    #[tokio::test]
    async fn test_full_session_events_and_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = Arc::new(test_trap());
        let trap_clone = trap.clone();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, addr.port(), sink, "scada", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Send Write Single Register (0x06) to change Reg 0 to 22500
        let req_reg = build_mbap_request(101, 1, &[0x06, 0x00, 0x00, 0x57, 0xE4]);
        client.write_all(&req_reg).await.unwrap();
        let mut resp_buf = vec![0u8; req_reg.len()];
        client.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, req_reg);

        // Send Write Single Coil (0x05) to trip Main Breaker Q0 (0x0000)
        let req_coil = build_mbap_request(102, 1, &[0x05, 0x00, 0x00, 0x00, 0x00]);
        client.write_all(&req_coil).await.unwrap();
        let mut resp_coil_buf = vec![0u8; req_coil.len()];
        client.read_exact(&mut resp_coil_buf).await.unwrap();
        assert_eq!(resp_coil_buf, req_coil);

        // Close connection cleanly
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify trap state mutated
        assert_eq!(trap.state.read().unwrap().holding_registers[0], 22500);
        assert!(!trap.state.read().unwrap().coils[0]);

        // Drain and verify emitted events
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        assert_eq!(events.len(), 2);
        // Event 1: FC 0x06
        assert_eq!(events[0].event_type, "command");
        assert_eq!(events[0].data["protocol"], "modbus_tcp");
        assert_eq!(events[0].data["function_code"], 6);
        assert_eq!(events[0].data["address"], 0);
        assert_eq!(events[0].data["value"], 22500);

        // Event 2: FC 0x05
        assert_eq!(events[1].event_type, "command");
        assert_eq!(events[1].data["protocol"], "modbus_tcp");
        assert_eq!(events[1].data["function_code"], 5);
        assert_eq!(events[1].data["address"], 0);
        assert_eq!(events[1].data["value"], 0);
    }

    #[tokio::test]
    async fn test_http_scada_hmi_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = Arc::new(test_trap());
        let trap_clone = trap.clone();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, addr.port(), sink, "scada", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let http_req = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.88.1\r\n\r\n";
        client.write_all(http_req).await.unwrap();

        let mut resp_data = Vec::new();
        client.read_to_end(&mut resp_data).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_data);

        // Verify HTML status and content
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_str.contains("Substation SCADA Gateway - Web HMI"));
        assert!(resp_str.contains("Schneider Electric"));
        assert!(resp_str.contains("Modicon M580"));
        assert!(resp_str.contains("220.00")); // Voltage
        assert!(resp_str.contains("CLOSED")); // Breaker Q0

        // Verify HTTP request event emitted
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "request");
        assert_eq!(events[0].data["protocol"], "http");
        assert_eq!(events[0].data["method"], "GET");
        assert_eq!(events[0].data["path"], "/");
    }

    #[tokio::test]
    async fn test_http_api_tags_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sink, rx) = EventSink::test_sink();
        let trap = Arc::new(test_trap());
        let trap_clone = trap.clone();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = Session::new(stream, addr.port(), sink, "scada", "srv01".into(), 2.0);
            trap_clone.handle(&mut s).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let http_req = b"GET /api/v1/tags HTTP/1.1\r\nHost: localhost\r\n\r\n";
        client.write_all(http_req).await.unwrap();

        let mut resp_data = Vec::new();
        client.read_to_end(&mut resp_data).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_data);

        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_str.contains("application/json"));
        assert!(resp_str.contains("\"status\":\"OPERATIONAL\""));
        assert!(resp_str.contains("\"voltage_v\":220.0"));
        assert!(resp_str.contains("\"breaker_q0\":\"CLOSED\""));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "request");
        assert_eq!(events[0].data["path"], "/api/v1/tags");
    }
}
