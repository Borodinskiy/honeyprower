//! HoneyForge agent — low-interaction honeypot.
//!
//! Конфиг едет вместе с бинарником (JSON-файл рядом). Агент поднимает все
//! ловушки своего хоста и шлёт телеметрию каждой в центр под её токеном.
//! Канал односторонний: из центра ничего не приходит.
//!
//! Запуск:  honeyforge-agent [путь-к-config.json]
//! По умолчанию конфиг берётся из $HF_CONFIG или ./config.json.

pub mod config;
pub mod crypto;
pub mod event;
pub mod runtime;
pub mod sender;
pub mod session;
pub mod traps;
pub mod util;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod plugin_tests;

use config::Config;
use std::path::PathBuf;
use std::process::ExitCode;

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

    let units = match cfg.units().and_then(runtime::build_units) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("конфиг {cfg_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Порты занимаем до запуска отправителей: если хоть один занят, агент не стартует.
    let bound = match runtime::bind_all(&units).await {
        Ok(b) => b,
        Err(errors) => {
            for e in errors {
                eprintln!("{e}");
            }
            return ExitCode::FAILURE;
        }
    };

    let base_buffer = cfg
        .buffer_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(resolve_buffer_path);
    let multi = units.len() > 1;
    let sinks: Vec<sender::EventSink> = units
        .iter()
        .map(|u| {
            let mut scfg = u.cfg.sender.clone();
            scfg.buffer_path = None;
            let path = runtime::buffer_path_for(&base_buffer, &scfg.token, multi);
            let clock = sender::IngestClock::default();
            let sink = sender::start(scfg.clone(), path, clock.clone());
            sender::start_heartbeat(scfg, clock);
            sink
        })
        .collect();

    eprintln!("honeyforge-agent: ловушек={} центр={}", units.len(), cfg.center_url);
    for u in &units {
        eprintln!(
            "  {} класс={} транспорт={} порты={:?}",
            u.label,
            u.cfg.trap.class,
            u.trap.transport(),
            u.ports
        );
    }

    let (bound, mut handles) = match runtime::start_plugins(&units, bound, &sinks).await {
        Ok(x) => x,
        Err(errors) => {
            for e in errors {
                eprintln!("{e}");
            }
            return ExitCode::FAILURE;
        }
    };
    handles.extend(runtime::serve(&units, bound, &sinks));

    tokio::select! {
        _ = shutdown_signal() => {
            eprintln!("honeyforge-agent: остановка");
        }
        _ = futures_any(handles) => {}
    }
    ExitCode::SUCCESS
}

/// Ctrl+C или SIGTERM (его шлют docker/podman/systemd при остановке).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
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

fn load_config(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cfg: Config = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    cfg.base_dir = std::path::Path::new(path)
        .parent()
        .map(|p| if p.as_os_str().is_empty() { std::path::Path::new(".") } else { p })
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    Ok(cfg)
}

pub fn resolve_buffer_path() -> PathBuf {
    if let Ok(val) = std::env::var("HF_BUFFER_PATH") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    std::env::temp_dir().join("honeyforge-agent-buffer.dat")
}

#[cfg(test)]
mod buffer_tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_resolve_buffer_path_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("HF_BUFFER_PATH");
        assert_eq!(
            resolve_buffer_path(),
            std::env::temp_dir().join("honeyforge-agent-buffer.dat")
        );
    }

    #[test]
    fn test_resolve_buffer_path_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("HF_BUFFER_PATH", "/var/run/custom_buffer.dat");
        assert_eq!(
            resolve_buffer_path(),
            PathBuf::from("/var/run/custom_buffer.dat")
        );
        std::env::remove_var("HF_BUFFER_PATH");
    }

    #[test]
    fn test_resolve_buffer_path_empty_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("HF_BUFFER_PATH", "   ");
        assert_eq!(
            resolve_buffer_path(),
            std::env::temp_dir().join("honeyforge-agent-buffer.dat")
        );
        std::env::remove_var("HF_BUFFER_PATH");
    }
}
