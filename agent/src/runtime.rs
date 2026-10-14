//! Запуск ловушек хоста: сборка из конфига, захват портов и приём соединений.
//!
//! Все порты занимаются до начала работы. Если хоть один занят или недоступен,
//! агент не стартует и пишет, какой именно: иначе деплой показал бы «успешно»,
//! а часть ловушек молча бы не работала.

use crate::config::{Params, TrapUnit};
use crate::event::event_type;
use crate::sender::EventSink;
use crate::session::Session;
use crate::traps::Trap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// Ловушка, собранная из конфига, с портами, которые она займёт.
pub struct Unit {
    pub cfg: TrapUnit,
    pub trap: Arc<Trap>,
    pub ports: Vec<u16>,
    pub label: String,
}

/// Собирает ловушки и проверяет, что порты не пересекаются (TCP и UDP — разные пространства).
pub fn build_units(units: Vec<TrapUnit>) -> Result<Vec<Unit>, String> {
    let mut out = Vec::with_capacity(units.len());
    let mut taken: HashMap<(&'static str, u16), String> = HashMap::new();
    for (i, u) in units.into_iter().enumerate() {
        let label = u.trap.label(i);
        let trap = Trap::build(&u.trap).map_err(|e| format!("ловушка {label}: {e}"))?;
        let ports = trap.ports(&u.trap);
        if ports.is_empty() || ports.contains(&0) {
            return Err(format!("ловушка {label}: не задан порт"));
        }
        for &p in &ports {
            if let Some(other) = taken.insert((trap.transport(), p), label.clone()) {
                return Err(format!(
                    "порт {p}/{} нужен двум ловушкам: {other} и {label}",
                    trap.transport()
                ));
            }
        }
        out.push(Unit { cfg: u, trap: Arc::new(trap), ports, label });
    }
    Ok(out)
}

pub enum Socket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// Занятый порт ловушки с индексом в списке units.
pub struct Bound {
    pub unit: usize,
    pub port: u16,
    pub socket: Socket,
}

/// Занимает все порты всех ловушек. При ошибках возвращает их все сразу.
pub async fn bind_all(units: &[Unit]) -> Result<Vec<Bound>, Vec<String>> {
    let mut bound = Vec::new();
    let mut errors = Vec::new();
    for (i, u) in units.iter().enumerate() {
        let bind = u.cfg.trap.bind.as_str();
        for &port in &u.ports {
            let socket = if u.trap.transport() == "udp" {
                UdpSocket::bind((bind, port)).await.map(Socket::Udp)
            } else {
                TcpListener::bind((bind, port)).await.map(Socket::Tcp)
            };
            match socket {
                Ok(socket) => bound.push(Bound { unit: i, port, socket }),
                Err(e) => errors.push(format!(
                    "ловушка {}: не удалось открыть {bind}:{port}/{}: {e}",
                    u.label,
                    u.trap.transport()
                )),
            }
        }
    }
    if errors.is_empty() {
        Ok(bound)
    } else {
        Err(errors)
    }
}

/// Запускает приём соединений на занятых портах. sinks[i] — канал событий units[i].
pub fn serve(units: &[Unit], bound: Vec<Bound>, sinks: &[EventSink]) -> Vec<JoinHandle<()>> {
    // Лимит клиентов — на ловушку, а не на порт: многопортовая ловушка делит его.
    let active: Vec<Arc<AtomicUsize>> = units.iter().map(|_| Arc::new(AtomicUsize::new(0))).collect();
    bound
        .into_iter()
        .map(|b| {
            let u = &units[b.unit];
            let sink = sinks[b.unit].clone();
            match b.socket {
                Socket::Udp(socket) => tokio::spawn(udp_loop(u.trap.clone(), socket, b.port, sink)),
                Socket::Tcp(listener) => tokio::spawn(tcp_loop(
                    u.trap.clone(),
                    listener,
                    b.port,
                    sink,
                    TcpLimits {
                        hostname: u.trap.hostname(&u.cfg.trap),
                        idle: u.trap.idle_timeout(&u.cfg.trap),
                        max_clients: Params(&u.cfg.trap.params).int("max_clients", 200).max(1) as usize,
                        active: active[b.unit].clone(),
                        class: u.cfg.trap.class.clone(),
                    },
                )),
            }
        })
        .collect()
}

/// Файл буфера ловушки. Одна ловушка — путь как есть (совместимо со старым
/// форматом), несколько — у каждой свой файл с суффиксом из её KeyID.
pub fn buffer_path_for(base: &Path, token: &str, multi: bool) -> PathBuf {
    if !multi {
        return base.to_path_buf();
    }
    let id: String = crate::crypto::compute_key_id(token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("honeyforge-agent-buffer");
    let name = match base.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{stem}-{id}.{ext}"),
        None => format!("{stem}-{id}"),
    };
    base.with_file_name(name)
}

struct TcpLimits {
    hostname: String,
    idle: f64,
    max_clients: usize,
    active: Arc<AtomicUsize>,
    class: String,
}

async fn tcp_loop(trap: Arc<Trap>, listener: TcpListener, port: u16, sink: EventSink, lim: TcpLimits) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if lim.active.load(Ordering::Relaxed) >= lim.max_clients {
            drop(stream); // слишком много клиентов — тихо отбрасываем
            continue;
        }
        lim.active.fetch_add(1, Ordering::Relaxed);
        let (trap, sink, hostname, class, active) = (
            trap.clone(),
            sink.clone(),
            lim.hostname.clone(),
            lim.class.clone(),
            lim.active.clone(),
        );
        let idle = lim.idle;
        tokio::spawn(async move {
            let mut s = Session::new(stream, port, sink, &class, hostname, idle);
            s.emit(s.event(event_type::CONNECT));
            trap.handle(&mut s).await;
            s.emit(s.disconnect_event("closed"));
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn udp_loop(trap: Arc<Trap>, socket: UdpSocket, port: u16, sink: EventSink) {
    let responder = match &*trap {
        Trap::Udp(u) => u.clone(),
        _ => return,
    };
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, addr) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let resp = responder.on_datagram(&buf[..n], &addr.ip().to_string(), addr.port(), port, &sink);
        if !resp.is_empty() {
            let _ = socket.send_to(&resp, addr).await;
        }
    }
}
