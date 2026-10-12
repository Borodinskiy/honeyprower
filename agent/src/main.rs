//! HoneyForge agent — low-interaction honeypot.
//!
//! Конфиг едет вместе с бинарником (JSON-файл рядом). Агент поднимает ловушку
//! и шлёт телеметрию в центр. Канал односторонний: из центра ничего не приходит.
//!
//! Запуск:  honeyforge-agent [путь-к-config.json]
//! По умолчанию конфиг берётся из $HF_CONFIG или ./config.json.

mod config;
mod event;
mod sender;
mod session;
mod traps;
mod util;

#[cfg(test)]
mod tests;

use config::Config;
use event::event_type;
use session::Session;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use traps::Trap;

#[tokio::main]
async fn main() -> ExitCode {
    let cfg_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("HF_CONFIG").ok())
        .unwrap_or_else(|| "config.json".to_string());

    let cfg = match load_config(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("конфиг {cfg_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let trap = match Trap::build(&cfg.trap) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("ловушка: {e}");
            return ExitCode::FAILURE;
        }
    };

    let buffer_path = PathBuf::from(format!("{cfg_path}.buffer"));
    let sink = sender::start(cfg.clone(), buffer_path);

    let ports = trap.ports(&cfg.trap);
    if ports.is_empty() || (ports.len() == 1 && ports[0] == 0) {
        eprintln!("не задан порт ловушки");
        return ExitCode::FAILURE;
    }

    let bind = cfg.trap.bind.clone();
    let hostname = trap.hostname(&cfg.trap);
    let idle = trap.idle_timeout(&cfg.trap);
    let max_clients = config::Params(&cfg.trap.params).int("max_clients", 200) as usize;

    eprintln!(
        "honeyforge-agent: класс={} транспорт={} порты={:?} центр={}",
        cfg.trap.class,
        trap.transport(),
        ports,
        cfg.center_url
    );

    let mut handles = Vec::new();

    if trap.transport() == "udp" {
        for port in ports {
            let (trap, bind, sink) = (trap.clone(), bind.clone(), sink.clone());
            handles.push(tokio::spawn(udp_loop(trap, bind, port, sink)));
        }
    } else {
        let active = Arc::new(AtomicUsize::new(0));
        for port in ports {
            let trap = trap.clone();
            let bind = bind.clone();
            let sink = sink.clone();
            let hostname = hostname.clone();
            let active = active.clone();
            let class = cfg.trap.class.clone();
            handles.push(tokio::spawn(tcp_loop(
                trap, bind, port, sink, hostname, idle, max_clients, active, class,
            )));
        }
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("honeyforge-agent: остановка");
        }
        _ = futures_any(handles) => {}
    }
    ExitCode::SUCCESS
}

/// Ждёт завершения любой из задач (если слушатель упал — выходим).
async fn futures_any(handles: Vec<tokio::task::JoinHandle<()>>) {
    if handles.is_empty() {
        std::future::pending::<()>().await;
        return;
    }
    let (res, _idx, _rest) = select_all(handles).await;
    let _ = res;
}

/// Минимальный аналог futures::future::select_all без зависимости от крейта futures.
async fn select_all(
    mut handles: Vec<tokio::task::JoinHandle<()>>,
) -> (Result<(), tokio::task::JoinError>, usize, Vec<tokio::task::JoinHandle<()>>) {
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    poll_fn(move |cx| {
        for i in 0..handles.len() {
            if let Poll::Ready(res) = std::pin::Pin::new(&mut handles[i]).poll(cx) {
                let rest = std::mem::take(&mut handles);
                return Poll::Ready((res, i, rest));
            }
        }
        Poll::Pending
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn tcp_loop(
    trap: Arc<Trap>,
    bind: String,
    port: u16,
    sink: sender::EventSink,
    hostname: String,
    idle: f64,
    max_clients: usize,
    active: Arc<AtomicUsize>,
    class: String,
) {
    let listener = match TcpListener::bind((bind.as_str(), port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("не удалось открыть {bind}:{port}/tcp: {e}");
            return;
        }
    };
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if active.load(Ordering::Relaxed) >= max_clients {
            drop(stream); // слишком много клиентов — тихо отбрасываем
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let (trap, sink, hostname, class, active) =
            (trap.clone(), sink.clone(), hostname.clone(), class.clone(), active.clone());
        tokio::spawn(async move {
            let mut s = Session::new(stream, port, sink, &class, hostname, idle);
            s.emit(s.event(event_type::CONNECT));
            trap.handle(&mut s).await;
            s.emit(s.disconnect_event("closed"));
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn udp_loop(trap: Arc<Trap>, bind: String, port: u16, sink: sender::EventSink) {
    let socket = match UdpSocket::bind((bind.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("не удалось открыть {bind}:{port}/udp: {e}");
            return;
        }
    };
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

fn load_config(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
