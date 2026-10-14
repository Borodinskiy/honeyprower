//! Crypto envelope handling for HoneyForge telemetry.
//!
//! Provides KeyID derivation and asymmetric hybrid encryption (X25519 + ChaCha20-Poly1305)
//! over gzip-compressed telemetry payloads.

use std::io::Write;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::event::IngestEvent;

#[derive(serde::Serialize)]
struct InnerPayload<'a> {
    t: &'a str,
    k: &'a str,
    e: &'a [IngestEvent],
}

/// Compute 8-byte KeyID from the first 8 bytes of SHA-256(token).
pub fn compute_key_id(token: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let hash = hasher.finalize();
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&hash[..8]);
    key_id
}

/// Seals telemetry data into an encrypted binary envelope.
///
/// Envelope format:
/// `[KeyID: 8B] || [Ephem_PK: 32B] || [Nonce: 12B] || [Ciphertext + Tag: N + 16B]`
pub fn seal_envelope(
    server_pub_hex: &str,
    token: &str,
    kind: &str,
    events: &[IngestEvent],
) -> Result<Vec<u8>, String> {
    // 1. Compute KeyID
    let key_id = compute_key_id(token);

    // 2. Serialize inner payload to JSON: {"t": token, "k": kind, "e": events}
    let payload = InnerPayload {
        t: token,
        k: kind,
        e: events,
    };
    let json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize payload to JSON: {e}"))?;

    // 3. Compress with standard gzip (RFC 1952)
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json_bytes)
        .map_err(|e| format!("gzip compression error: {e}"))?;
    let compressed = encoder
        .finish()
        .map_err(|e| format!("gzip finish error: {e}"))?;

    // 4. Parse server public key (32 bytes from 64-char hex)
    let server_pub_bytes = hex::decode(server_pub_hex)
        .map_err(|e| format!("invalid hex in server_pub_hex: {e}"))?;
    if server_pub_bytes.len() != 32 {
        return Err(format!(
            "server_pub_hex must decode to 32 bytes, got {}",
            server_pub_bytes.len()
        ));
    }
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(&server_pub_bytes);
    let server_pub_key = x25519_dalek::PublicKey::from(server_pub_arr);

    // 5. Generate ephemeral X25519 secret and public key
    let ephem_sk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephem_pk = x25519_dalek::PublicKey::from(&ephem_sk);

    // 6. Diffie-Hellman shared secret
    let shared_secret = ephem_sk.diffie_hellman(&server_pub_key);

    // 7. Derive 32-byte symmetric key via HKDF-SHA256
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&key_id[..]), shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    let expand_res = hk.expand(b"honeyforge-envelope-v1", &mut sym_key);
    if let Err(e) = expand_res {
        sym_key.zeroize();
        return Err(format!("hkdf expand error: {e}"));
    }

    // 8. Generate 12-byte random nonce
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    // 9. Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    let encrypt_res = cipher.encrypt(Nonce::from_slice(&nonce), compressed.as_slice());

    // Zeroize symmetric key in memory
    sym_key.zeroize();

    let ciphertext = encrypt_res.map_err(|e| format!("aead encryption error: {e}"))?;

    // 10. Assemble envelope: [KeyID: 8B] || [Ephem_PK: 32B] || [Nonce: 12B] || [Ciphertext+Tag]
    let mut envelope = Vec::with_capacity(8 + 32 + 12 + ciphertext.len());
    envelope.extend_from_slice(&key_id);
    envelope.extend_from_slice(ephem_pk.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[test]
    fn test_compute_key_id() {
        let token = "test-token-12345";
        let key_id = compute_key_id(token);

        // Reference SHA-256 for "test-token-12345":
        // e4c0a87e760240da600e6d0c5c37516742a3d691feb803a33dcbbe8405e64b1e
        // First 8 bytes: [0xe4, 0xc0, 0xa8, 0x7e, 0x76, 0x02, 0x40, 0xda]
        let expected: [u8; 8] = [0xe4, 0xc0, 0xa8, 0x7e, 0x76, 0x02, 0x40, 0xda];
        assert_eq!(key_id, expected);

        // Also test with another known string
        let empty_key_id = compute_key_id("");
        // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected_empty: [u8; 8] = [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14];
        assert_eq!(empty_key_id, expected_empty);
    }

    #[test]
    fn test_seal_envelope_format() {
        let server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        let token = "test-token-format-check";
        let kind = "ingest";
        let events = vec![IngestEvent::new("ssh", "connect")];

        let envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal_envelope failed");

        // Envelope length must be >= 68 (8 + 32 + 12 + 16 min)
        assert!(
            envelope.len() >= 68,
            "envelope must be at least 68 bytes, got {}",
            envelope.len()
        );

        // First 8 bytes must match KeyID
        let expected_key_id = compute_key_id(token);
        assert_eq!(
            &envelope[0..8],
            &expected_key_id,
            "first 8 bytes must match compute_key_id(token)"
        );
    }

    #[test]
    fn test_seal_and_decrypt() {
        // 1. Generate X25519 keypair for the server
        let server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        // 2. Prepare test data
        let token = "secret-token-test-123";
        let kind = "ingest";
        let mut ev1 = IngestEvent::new("http", "request");
        ev1.src_ip = "192.168.1.50".to_string();
        ev1.src_port = 45678;
        ev1.dst_port = 8080;
        ev1.session = "sess-001".to_string();
        ev1.ts = 1700000000.0;
        let mut ev2 = IngestEvent::new("banner", "connect").peer("10.0.0.1", 1234, 22);
        ev2.ts = 1700000001.0;
        let events = vec![ev1, ev2];

        // 3. Seal envelope
        let envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal_envelope should succeed");
        assert!(envelope.len() >= 68);

        // 4. Server-side decryption:
        // Extract envelope fields
        let key_id = &envelope[0..8];
        assert_eq!(key_id, &compute_key_id(token));

        let ephem_pk_bytes: [u8; 32] = envelope[8..40]
            .try_into()
            .expect("ephem_pk must be 32 bytes");
        let ephem_pk = x25519_dalek::PublicKey::from(ephem_pk_bytes);
        let nonce = &envelope[40..52];
        let ciphertext_with_tag = &envelope[52..];

        // Compute DH shared secret on server
        let shared_secret = server_sk.diffie_hellman(&ephem_pk);

        // Derive symmetric key on server
        let hk = hkdf::Hkdf::<Sha256>::new(Some(key_id), shared_secret.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(b"honeyforge-envelope-v1", &mut sym_key)
            .expect("hkdf expand failed");

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let decrypted_gzip = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
            .expect("aead decryption failed");

        // Gzip decompression
        let mut decoder = GzDecoder::new(&decrypted_gzip[..]);
        let mut json_bytes = Vec::new();
        decoder
            .read_to_end(&mut json_bytes)
            .expect("gzip decompression failed");

        // JSON deserialization & assertions
        let parsed: serde_json::Value =
            serde_json::from_slice(&json_bytes).expect("JSON deserialization failed");
        assert_eq!(parsed["t"].as_str().unwrap(), token);
        assert_eq!(parsed["k"].as_str().unwrap(), kind);

        let expected_events_json = serde_json::to_value(&events).unwrap();
        assert_eq!(parsed["e"], expected_events_json);
    }

    #[test]
    fn test_seal_heartbeat_empty_events() {
        let server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        let token = "hb-token-999";
        let kind = "hb";
        let events: Vec<IngestEvent> = vec![];

        let envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal hb should succeed");
        assert!(envelope.len() >= 68);

        // Verify decryption of heartbeat envelope
        let ephem_pk_bytes: [u8; 32] = envelope[8..40].try_into().unwrap();
        let ephem_pk = x25519_dalek::PublicKey::from(ephem_pk_bytes);
        let nonce = &envelope[40..52];
        let ciphertext_with_tag = &envelope[52..];

        let shared_secret = server_sk.diffie_hellman(&ephem_pk);
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&envelope[0..8]), shared_secret.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(b"honeyforge-envelope-v1", &mut sym_key).unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let decrypted_gzip = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
            .unwrap();

        let mut decoder = GzDecoder::new(&decrypted_gzip[..]);
        let mut json_bytes = Vec::new();
        decoder.read_to_end(&mut json_bytes).unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["t"].as_str().unwrap(), token);
        assert_eq!(parsed["k"].as_str().unwrap(), "hb");
        assert_eq!(parsed["e"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_invalid_server_pub_hex() {
        let token = "test-token";
        let kind = "ingest";
        let events: Vec<IngestEvent> = vec![];

        // Non-hex string
        let res = seal_envelope("not-a-valid-hex-string", token, kind, &events);
        assert!(res.is_err());

        // Hex string with incorrect length (not 32 bytes)
        let res = seal_envelope("aabbcc", token, kind, &events);
        assert!(res.is_err());
    }
}
