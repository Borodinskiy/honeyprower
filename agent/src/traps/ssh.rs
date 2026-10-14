//! SSH-ловушка среднего взаимодействия: настоящий SSH-протокол (обмен ключами,
//! шифрование) на russh. Клиент видит обычный OpenSSH, вводит логин и пароль —
//! мы их записываем и отвечаем «Permission denied». Войти нельзя.
//!
//! Ключ хоста выводится из секрета ловушки (токена), поэтому он один и тот же
//! после перезапусков и повторных деплоев: клиент не увидит предупреждения
//! «REMOTE HOST IDENTIFICATION HAS CHANGED».

use crate::config::Params;
use crate::event::{event_type, Event};
use crate::sender::EventSink;
use crate::session::Session;
use crate::util::safe_text;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Config, Handler};
use russh::{cipher, compression, kex, mac, MethodKind, MethodSet, Preferred, SshId};
use std::borrow::Cow;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEFAULT_VERSION: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10";

// Алгоритмы OpenSSH 8.9 по умолчанию (то, что у него есть и в russh). Свежие вроде
// mlkem768x25519 выдали бы ловушку: в 8.9 их нет, а сканеры сверяют списки KEXINIT.
const KEX_8_9: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G18_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];
const CIPHER_8_9: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
    cipher::AES_128_GCM,
    cipher::AES_256_GCM,
];
const MAC_8_9: &[mac::Name] = &[
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA256,
    mac::HMAC_SHA512,
    mac::HMAC_SHA1,
];
const COMPRESSION_8_9: &[compression::Name] = &[compression::NONE, compression::ZLIB_LEGACY];

pub struct SshTrap {
    config: Arc<Config>,
    params: Value,
}

impl SshTrap {
    pub fn new(params: &Value, key_seed: &str) -> Result<SshTrap, String> {
        let p = Params(params);

        let version = p.str("version", DEFAULT_VERSION).trim().to_string();
        if !version.starts_with("SSH-2.0-") {
            return Err("version должна начинаться с SSH-2.0-".into());
        }

        let key = match p.str("host_key", "").trim() {
            "" => derive_host_key(key_seed),
            pem => PrivateKey::from_openssh(pem).map_err(|e| format!("host_key: {e}"))?,
        };


        let config = Config {
            server_id: SshId::Standard(version.into()),
            methods: methods(),
            // Задержку после неверного пароля делаем сами (как PAM), отказ по ключу — мгновенный, как в sshd.
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            max_auth_attempts: p.int("max_auth_tries", 6).clamp(1, 100) as usize,
            inactivity_timeout: Some(Duration::from_secs_f64(p.float("idle_timeout", 120.0).max(1.0))),
            nodelay: true,
            preferred: Preferred {
                kex: Cow::Borrowed(KEX_8_9),
                cipher: Cow::Borrowed(CIPHER_8_9),
                mac: Cow::Borrowed(MAC_8_9),
                compression: Cow::Borrowed(COMPRESSION_8_9),
                ..Preferred::DEFAULT
            },
            ..Default::default()
        };

        Ok(SshTrap {
            config: Arc::new(config),
            params: params.clone(),
        })
    }

    /// Отпечаток ключа хоста в формате ssh-keygen -l (SHA256:...).
    pub fn host_fingerprint(&self) -> String {
        self.config.keys[0].public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    pub async fn handle(&self, s: &mut Session) {
        let p = Params(&self.params);
        let handler = AuthLogger {
            base: s.event(event_type::AUTH),
            sink: s.sink(),
            fail_delay: p.str("fail_delay_ms", "1800-2600"),
            banner: p.str("auth_banner", ""),
            attempts: 0,
        };

        // russh работает со своим концом канала в памяти, а мы перекачиваем байты
        // между ним и сокетом через Session — так сохраняются таймаут и счётчики.
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let config = self.config.clone();
        let ssh = tokio::spawn(async move {
            if let Ok(running) = russh::server::run_stream(config, theirs, handler).await {
                let _ = running.await;
            }
        });

        let (mut from_ssh, mut to_ssh) = tokio::io::split(ours);
        let mut buf = vec![0u8; 16 * 1024];
        let mut ident = Vec::new();
        let mut ident_done = false;
        loop {
            tokio::select! {
                r = s.read(16 * 1024, None) => {
                    let data = match r {
                        Ok(d) if !d.is_empty() => d,
                        _ => break,
                    };
                    if !ident_done {
                        ident_done = sniff_ident(s, &mut ident, &data);
                    }
                    if to_ssh.write_all(&data).await.is_err() {
                        break;
                    }
                }
                n = from_ssh.read(&mut buf) => {
                    match n {
                        Ok(n) if n > 0 => {
                            if s.send(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
        ssh.abort();
    }
}

/// Копит первую строку клиента (SSH-2.0-...) и шлёт событие handshake. true — строка разобрана.
fn sniff_ident(s: &Session, ident: &mut Vec<u8>, data: &[u8]) -> bool {
    ident.extend_from_slice(data);
    let Some(end) = ident.iter().position(|&b| b == b'\n') else {
        return ident.len() > 255;
    };
    let line = String::from_utf8_lossy(&ident[..end]).trim_end_matches('\r').to_string();
    s.emit_data(event_type::HANDSHAKE, json!({ "client_version": safe_text(line.as_bytes(), 255) }));
    true
}

/// Как в Ubuntu по умолчанию: KbdInteractiveAuthentication no.
fn methods() -> MethodSet {
    MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password][..])
}

/// Отказ без вычёркивания метода: sshd даёт повторить пароль, а russh по умолчанию убирает его из списка.
fn deny() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(methods()),
        partial_success: false,
    }
}

/// Ключ хоста ed25519 из секрета ловушки: стабилен между запусками, файлы не нужны.
fn derive_host_key(seed: &str) -> PrivateKey {
    let digest = Sha256::digest(format!("honeyforge-ssh-hostkey:{seed}").as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    PrivateKey::from(Ed25519Keypair::from_seed(&bytes))
}

struct AuthLogger {
    base: Event,
    sink: EventSink,
    fail_delay: String,
    banner: String,
    attempts: u32,
}

impl AuthLogger {
    fn emit(&mut self, username: &str, password: Option<&str>, data: Value) {
        self.attempts += 1;
        let mut data = data;
        data["attempt"] = json!(self.attempts);
        let ev = self
            .base
            .clone()
            .username(Some(username.to_string()))
            .password(password.map(str::to_string))
            .data(data);
        self.sink.emit(Event { ts: crate::event::now_ts(), ..ev });
    }
}

impl Handler for AuthLogger {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.emit(user, Some(password), json!({ "method": "password" }));
        let ms = crate::util::delay_ms(&self.fail_delay);
        if ms > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(ms / 1000.0)).await;
        }
        Ok(deny())
    }

    async fn auth_publickey_offered(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.emit(
            user,
            None,
            json!({
                "method": "publickey",
                "key_type": key.algorithm().to_string(),
                "fingerprint": key.fingerprint(HashAlg::Sha256).to_string(),
            }),
        );
        Ok(deny())
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        if self.banner.is_empty() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&crate::util::unescape(&self.banner)).into_owned()))
    }
}
