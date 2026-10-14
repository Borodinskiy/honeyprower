//! Реестр классов ловушек и диспетчер. Каждый класс — самостоятельный
//! механизм эмуляции; конкретная ловушка = класс + параметры из конфига.

pub mod banner;
pub mod dialog;
pub mod http;
pub mod honeytoken;
pub mod port_listener;
pub mod ssh;
pub mod tarpit;
pub mod udp;

use crate::config::{Params, TrapConfig};
use crate::session::Session;
use crate::util;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub enum Trap {
    PortListener(Arc<port_listener::PortListener>),
    Banner(Arc<banner::Banner>),
    Dialog(Arc<dialog::Dialog>),
    Http(Arc<http::HttpDecoy>),
    Tarpit(Arc<tarpit::Tarpit>),
    Honeytoken(Arc<honeytoken::Honeytoken>),
    Udp(Arc<udp::UdpResponder>),
    Ssh(Arc<ssh::SshTrap>),
}

impl Trap {
    pub fn build(cfg: &TrapConfig) -> Result<Trap, String> {
        let p = &cfg.params;
        Ok(match cfg.class.as_str() {
            "port_listener" => Trap::PortListener(Arc::new(port_listener::PortListener::new(p))),
            "banner" => Trap::Banner(Arc::new(banner::Banner::new(p))),
            "dialog" => Trap::Dialog(Arc::new(dialog::Dialog::new(p)?)),
            "http" => Trap::Http(Arc::new(http::HttpDecoy::new(p)?)),
            "tarpit" => Trap::Tarpit(Arc::new(tarpit::Tarpit::new(p))),
            "honeytoken" => Trap::Honeytoken(Arc::new(honeytoken::Honeytoken::new(p))),
            "udp" => Trap::Udp(Arc::new(udp::UdpResponder::new(p))),
            "ssh" => Trap::Ssh(Arc::new(ssh::SshTrap::new(p, &cfg.key_seed)?)),
            other => return Err(format!("неизвестный класс ловушки: {other}")),
        })
    }

    pub fn transport(&self) -> &'static str {
        match self {
            Trap::Udp(_) => "udp",
            _ => "tcp",
        }
    }

    pub fn multi_port(&self) -> bool {
        matches!(self, Trap::PortListener(_))
    }

    /// Порты, которые должна открыть ловушка.
    pub fn ports(&self, cfg: &TrapConfig) -> Vec<u16> {
        if self.multi_port() {
            let p = Params(&cfg.params);
            let spec = p.str("ports", &cfg.ports);
            util::parse_ports(&spec)
        } else {
            vec![cfg.port]
        }
    }

    pub fn idle_timeout(&self, cfg: &TrapConfig) -> f64 {
        // SSH: человек вводит пароль медленно; 120 с — как LoginGraceTime в sshd.
        let def = if matches!(self, Trap::Ssh(_)) { 120.0 } else { 30.0 };
        Params(&cfg.params).float("idle_timeout", def)
    }

    pub fn hostname(&self, cfg: &TrapConfig) -> String {
        Params(&cfg.params).str("hostname", "srv01")
    }

    /// Обработка одного TCP-соединения (для UDP не вызывается).
    pub async fn handle(&self, s: &mut Session) {
        match self {
            Trap::PortListener(t) => t.handle(s).await,
            Trap::Banner(t) => t.handle(s).await,
            Trap::Dialog(t) => t.handle(s).await,
            Trap::Http(t) => t.handle(s).await,
            Trap::Tarpit(t) => t.handle(s).await,
            Trap::Honeytoken(t) => t.handle(s).await,
            Trap::Ssh(t) => t.handle(s).await,
            Trap::Udp(_) => {}
        }
    }
}

/// Задержка ответа по параметру response_delay_ms (мгновенные ответы выдают эмулятор).
pub async fn delay(params: &serde_json::Value) {
    let spec = Params(params).str("response_delay_ms", "0");
    let ms = util::delay_ms(&spec);
    if ms > 0.0 {
        sleep(Duration::from_secs_f64(ms / 1000.0)).await;
    }
}
