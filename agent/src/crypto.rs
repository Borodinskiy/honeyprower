//! Crypto envelope handling for HoneyForge telemetry.
//!
//! Provides KeyID derivation and asymmetric hybrid encryption (X25519 + ChaCha20-Poly1305)
//! over gzip-compressed telemetry payloads.

use std::io::{Read, Write};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use flate2::read::GzDecoder;
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


#[derive(serde::Deserialize)]
struct DecryptedPayload {
    t: String,
    k: String,
    e: Vec<IngestEvent>,
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
    server_pub_arr.zeroize();

    // 5. Generate ephemeral X25519 secret and public key
    let ephem_sk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephem_pk = x25519_dalek::PublicKey::from(&ephem_sk);

    // 6. Diffie-Hellman shared secret (ephem_sk is consumed and zeroized on drop)
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

/// Decrypts and decompresses a sealed envelope using a recipient's static secret key.
/// Returns Ok((token, kind, events)) on success, or Err on any decryption or decompression failure.
pub fn decrypt_envelope(
    server_sk: &x25519_dalek::StaticSecret,
    envelope: &[u8],
) -> Result<(String, String, Vec<IngestEvent>), String> {
    if envelope.len() < 68 {
        return Err(format!(
            "envelope too short: expected at least 68 bytes, got {}",
            envelope.len()
        ));
    }

    let key_id = &envelope[0..8];
    let ephem_pk_bytes: [u8; 32] = envelope[8..40]
        .try_into()
        .map_err(|e| format!("invalid ephemeral public key length: {e}"))?;
    let ephem_pk = x25519_dalek::PublicKey::from(ephem_pk_bytes);
    let nonce = &envelope[40..52];
    let ciphertext_with_tag = &envelope[52..];

    // ECDH shared secret
    let shared_secret = server_sk.diffie_hellman(&ephem_pk);

    // HKDF key derivation
    let hk = hkdf::Hkdf::<Sha256>::new(Some(key_id), shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    let expand_res = hk.expand(b"honeyforge-envelope-v1", &mut sym_key);
    if let Err(e) = expand_res {
        sym_key.zeroize();
        return Err(format!("hkdf expand error: {e}"));
    }

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    let decrypt_res = cipher.decrypt(Nonce::from_slice(nonce), ciphertext_with_tag);
    sym_key.zeroize();

    let decrypted_gzip = decrypt_res.map_err(|e| format!("aead decryption failed: {e}"))?;

    // Decompress with gzip
    let mut decoder = GzDecoder::new(&decrypted_gzip[..]);
    let mut json_bytes = Vec::new();
    decoder
        .read_to_end(&mut json_bytes)
        .map_err(|e| format!("gzip decompression failed: {e}"))?;

    let payload: DecryptedPayload = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("json deserialization failed: {e}"))?;

    Ok((payload.t, payload.k, payload.e))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expected_empty: [u8; 8] = [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14];
        assert_eq!(empty_key_id, expected_empty);
    }

    #[test]
    fn test_seal_envelope_format() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
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
        server_sk.zeroize();
    }

    #[test]
    fn test_seal_and_decrypt() {
        // 1. Generate X25519 keypair for the server
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
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

        // 4. Server-side decryption using decrypt_envelope helper
        let (dec_token, dec_kind, dec_events) =
            decrypt_envelope(&server_sk, &envelope).expect("decrypt_envelope failed");

        assert_eq!(dec_token, token);
        assert_eq!(dec_kind, kind);
        assert_eq!(dec_events.len(), 2);
        assert_eq!(dec_events[0].src_ip, "192.168.1.50");
        assert_eq!(dec_events[1].src_ip, "10.0.0.1");

        server_sk.zeroize();
    }

    #[test]
    fn test_seal_heartbeat_empty_events() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        let token = "hb-token-999";
        let kind = "hb";
        let events: Vec<IngestEvent> = vec![];

        let envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal hb should succeed");
        assert!(envelope.len() >= 68);

        let (dec_token, dec_kind, dec_events) =
            decrypt_envelope(&server_sk, &envelope).expect("decrypt hb failed");
        assert_eq!(dec_token, token);
        assert_eq!(dec_kind, "hb");
        assert_eq!(dec_events.len(), 0);

        server_sk.zeroize();
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

    #[test]
    fn test_corrupted_poly1305_tag_handling() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        let token = "tag-tamper-test";
        let kind = "ingest";
        let events = vec![IngestEvent::new("ssh", "login")];

        let mut envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal should succeed");

        // Flip 1 bit in the Poly1305 authentication tag (last 16 bytes)
        let tag_idx = envelope.len() - 1;
        envelope[tag_idx] ^= 0x01;

        // Decryption must cleanly fail without panic
        let res = decrypt_envelope(&server_sk, &envelope);
        assert!(res.is_err(), "decryption with tampered tag must fail");
        let err = res.err().unwrap();
        assert!(
            err.contains("aead decryption failed"),
            "expected AEAD error message, got: {err}"
        );

        server_sk.zeroize();
    }

    #[test]
    fn test_corrupted_ciphertext_handling() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);
        let server_pub_hex = hex::encode(server_pk.as_bytes());

        let token = "ct-tamper-test";
        let kind = "ingest";
        let events = vec![IngestEvent::new("ssh", "login")];

        let mut envelope =
            seal_envelope(&server_pub_hex, token, kind, &events).expect("seal should succeed");

        // Flip 1 bit in ciphertext payload (byte 53)
        envelope[53] ^= 0x02;

        let res = decrypt_envelope(&server_sk, &envelope);
        assert!(res.is_err(), "decryption with tampered ciphertext must fail");

        server_sk.zeroize();
    }

    #[test]
    fn test_corrupted_gzip_handling() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&server_sk);

        let token = "corrupt-gzip-token";
        let key_id = compute_key_id(token);

        // Client ephemeral key
        let ephem_sk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephem_pk = x25519_dalek::PublicKey::from(&ephem_sk);
        let shared_secret = ephem_sk.diffie_hellman(&server_pk);

        let hk = hkdf::Hkdf::<Sha256>::new(Some(&key_id[..]), shared_secret.as_bytes());
        let mut sym_key = [0u8; 32];
        hk.expand(b"honeyforge-envelope-v1", &mut sym_key).unwrap();

        // Encrypt invalid (non-gzip) bytes with valid Poly1305 MAC tag
        let invalid_gzip_data = b"This is plain text and definitely not valid gzip stream data!";
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), invalid_gzip_data.as_ref())
            .unwrap();
        sym_key.zeroize();

        let mut envelope = Vec::new();
        envelope.extend_from_slice(&key_id);
        envelope.extend_from_slice(ephem_pk.as_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let res = decrypt_envelope(&server_sk, &envelope);
        assert!(res.is_err(), "decompression of invalid gzip must fail");
        let err = res.err().unwrap();
        assert!(
            err.contains("gzip decompression failed"),
            "expected gzip decompression error, got: {err}"
        );

        server_sk.zeroize();
    }

    #[test]
    fn test_truncated_envelope_handling() {
        let mut server_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let short_env = vec![0u8; 50];
        let res = decrypt_envelope(&server_sk, &short_env);
        assert!(res.is_err());
        assert!(res.err().unwrap().contains("envelope too short"));
        server_sk.zeroize();
    }

    #[test]
    fn test_secret_zeroize_on_drop() {
        use zeroize::Zeroize;
        let mut sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        sk.zeroize();

        let mut ephem = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        ephem.zeroize();
    }
}
