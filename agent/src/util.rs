//! Общие утилиты: шаблоны ответов, hex, разбор списков портов.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// `\r\n` в шаблоне -> реальные CRLF, `\xNN` -> байт, `\t`,`\0`. Остальное как есть.
pub fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'0' => {
                    out.push(0);
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'x' if i + 3 < b.len() => {
                    let hi = (b[i + 2] as char).to_digit(16);
                    let lo = (b[i + 3] as char).to_digit(16);
                    if let (Some(h), Some(l)) = (hi, lo) {
                        out.push((h * 16 + l) as u8);
                        i += 4;
                    } else {
                        out.push(b[i]);
                        i += 1;
                    }
                }
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            }
        } else {
            // Многобайтовый UTF-8 проходит как есть.
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Подстановка `{var}` в текст, затем unescape. Неизвестные переменные остаются как есть.
pub fn render(tpl: &str, ctx: &HashMap<String, String>) -> Vec<u8> {
    let mut rendered = String::with_capacity(tpl.len());
    let b = tpl.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if let Some(end) = tpl[i + 1..].find('}') {
                let key = &tpl[i + 1..i + 1 + end];
                if !key.is_empty() && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                    if let Some(val) = ctx.get(key) {
                        rendered.push_str(val);
                    } else {
                        rendered.push('{');
                        rendered.push_str(key);
                        rendered.push('}');
                    }
                    i += end + 2;
                    continue;
                }
            }
        }
        // Байт как символ latin-1 → сохранит произвольные байты до unescape.
        rendered.push(b[i] as char);
        i += 1;
    }
    // rendered собран как latin-1; вернём байты, затем раскроем escape-последовательности.
    let latin: Vec<u8> = rendered.chars().map(|c| c as u8).collect();
    unescape(&String::from_utf8_lossy(&latin))
}

pub fn parse_hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push(hi * 16 + lo);
        i += 2;
    }
    out
}

/// Безопасное текстовое представление байтов (для журнала).
pub fn safe_text(b: &[u8], limit: usize) -> String {
    let slice = &b[..b.len().min(limit)];
    String::from_utf8_lossy(slice).replace('\u{FFFD}', ".")
}

/// Первые `limit` байт в hex.
pub fn hex_prefix(b: &[u8], limit: usize) -> String {
    b[..b.len().min(limit)]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// "8000-8003,9200" -> [8000,8001,8002,8003,9200].
pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut set = std::collections::BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                for p in a..=b {
                    if (1..=65535).contains(&p) {
                        set.insert(p as u16);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u32>() {
            if (1..=65535).contains(&p) {
                set.insert(p as u16);
            }
        }
    }
    set.into_iter().collect()
}

/// Простой не-криптографический ГПСЧ (xorshift64), сид от времени и счётчика.
pub fn rand_u64() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(0);
    }
    STATE.with(|s| {
        let mut x = s.get();
        if x == 0 {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x1234_5678);
            static CTR: AtomicU64 = AtomicU64::new(0x9E37_79B9);
            x = t ^ CTR.fetch_add(0x6C8E_9CF5, Ordering::Relaxed).wrapping_mul(2654435761);
            if x == 0 {
                x = 0xDEAD_BEEF;
            }
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}

/// Случайное число в диапазоне [lo, hi].
pub fn rand_range(lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    lo + rand_u64() % (hi - lo + 1)
}

/// Задержка ответа по спецификации "50" (всегда) или "30-120" (случайно), в мс.
pub fn delay_ms(spec: &str) -> f64 {
    let spec = spec.trim();
    if let Some((a, b)) = spec.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.trim().parse::<f64>(), b.trim().parse::<f64>()) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            return lo + (rand_u64() % 1000) as f64 / 1000.0 * (hi - lo);
        }
    }
    spec.parse::<f64>().unwrap_or(0.0)
}

/// Короткий случайный id сессии (12 hex-символов).
pub fn session_id() -> String {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mix = t ^ (n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    format!("{mix:012x}")[..12].to_string()
}

/// UTC-строки для подстановок {date}/{time}.
pub fn http_date() -> String {
    // Минимальный RFC1123 без внешних крейтов. Для баннеров точность не критична.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s, wd) = civil_from_unix(secs);
    const WD: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WD[wd as usize], d, MO[(mo - 1) as usize], y, h, mi, s
    )
}

pub fn clock_time() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (_, _, _, h, mi, s, _) = civil_from_unix(secs);
    format!("{h:02}:{mi:02}:{s:02}")
}

/// Разбор unix-времени в UTC (без внешних крейтов).
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = (secs % 86400) as u32;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let wd = ((days % 7 + 4) % 7) as u32; // 1970-01-01 — четверг
    // алгоритм Howard Hinnant civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s, wd)
}
