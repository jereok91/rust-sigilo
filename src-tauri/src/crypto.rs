//! Cifrado y descifrado AES-256 con detección automática de formato.
//!
//! Clave: 32 bytes en Base64 (`openssl rand -base64 32`), opcionalmente con
//! prefijo `base64:`; también se acepta en hex (64 caracteres).
//!
//! Formatos de texto cifrado soportados (partes en Base64 o hex):
//!   - `nonce(12) || ciphertext || tag(16)`          AES-256-GCM (un solo blob)
//!   - `nonce(12) || tag(16) || ciphertext`          AES-256-GCM (un solo blob)
//!   - `iv(16) || ciphertext`                        AES-256-CBC + PKCS7
//!   - `iv:tag:ciphertext` / `iv:ciphertext:tag`     AES-256-GCM (separado por `:` o `.`)
//!   - `iv:ciphertext`                               AES-256-GCM (tag al final) o CBC
//!   - JSON Base64 estilo Laravel `{"iv","value","tag"?}`

use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{AesGcm, Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256Gcm16 = AesGcm<Aes256, U16>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const TAG_LEN: usize = 16;

pub fn decrypt(key: &str, ciphertext: &str) -> Result<(String, String), String> {
    let key = parse_key(key)?;
    let input: String = ciphertext.chars().filter(|c| !c.is_whitespace()).collect();
    if input.is_empty() {
        return Err("El texto cifrado está vacío.".into());
    }

    for attempt in candidates(&input) {
        if let Some(plain) = attempt.run(&key) {
            return Ok((plain, attempt.label));
        }
    }
    Err("No se pudo descifrar: la clave no corresponde o el formato del texto cifrado no es reconocido.".into())
}

/// Cifra `plaintext` con un nonce/IV aleatorio en el formato indicado:
///   - `gcm-b64`: Base64(nonce(12) || ciphertext || tag)   (por defecto)
///   - `gcm-hex`: hex(iv):hex(tag):hex(ciphertext)
///   - `cbc-b64`: Base64(iv(16) || ciphertext)  con PKCS7
pub fn encrypt(key: &str, plaintext: &str, format: &str) -> Result<String, String> {
    let key = parse_key(key)?;
    if plaintext.is_empty() {
        return Err("El texto en claro está vacío.".into());
    }

    match format {
        "gcm-b64" | "gcm-hex" => {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let out = Aes256Gcm::new(&key.into())
                .encrypt(&nonce, plaintext.as_bytes())
                .map_err(|_| "Error al cifrar.")?;
            if format == "gcm-b64" {
                Ok(STANDARD.encode([nonce.as_slice(), &out].concat()))
            } else {
                let (ct, tag) = out.split_at(out.len() - TAG_LEN);
                Ok(format!("{}:{}:{}", hex::encode(nonce), hex::encode(tag), hex::encode(ct)))
            }
        }
        "cbc-b64" => {
            let mut iv = [0u8; 16];
            OsRng.fill_bytes(&mut iv);
            let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
            Ok(STANDARD.encode([iv.as_slice(), &ct].concat()))
        }
        other => Err(format!("Formato desconocido: {other}")),
    }
}

fn parse_key(key: &str) -> Result<[u8; 32], String> {
    let key = key.trim();
    let key = key.strip_prefix("base64:").unwrap_or(key);
    let bytes = if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(key).ok()
    } else {
        decode_b64(key)
    }
    .ok_or("La clave no es Base64 válido.")?;

    bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("La clave debe tener 32 bytes (AES-256); tiene {}.", b.len()))
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
}

/// Todas las interpretaciones posibles de una parte: hex y/o Base64.
fn decodings(s: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(b) = hex::decode(s) {
            out.push(b);
        }
    }
    if let Some(b) = decode_b64(s) {
        out.push(b);
    }
    out
}

enum Mode {
    /// `data` = ciphertext || tag
    Gcm { nonce: Vec<u8>, data: Vec<u8> },
    Cbc { iv: Vec<u8>, data: Vec<u8> },
}

struct Attempt {
    label: String,
    mode: Mode,
}

impl Attempt {
    fn gcm(label: &str, nonce: &[u8], ct: &[u8], tag: &[u8]) -> Self {
        let data = [ct, tag].concat();
        Attempt { label: label.into(), mode: Mode::Gcm { nonce: nonce.to_vec(), data } }
    }

    fn cbc(label: &str, iv: &[u8], ct: &[u8]) -> Self {
        Attempt { label: label.into(), mode: Mode::Cbc { iv: iv.to_vec(), data: ct.to_vec() } }
    }

    fn run(&self, key: &[u8; 32]) -> Option<String> {
        match &self.mode {
            Mode::Gcm { nonce, data } => {
                if data.len() < TAG_LEN {
                    return None;
                }
                let payload = Payload { msg: data, aad: b"" };
                let plain = match nonce.len() {
                    12 => Aes256Gcm::new(key.into()).decrypt(Nonce::from_slice(nonce), payload),
                    16 => Aes256Gcm16::new(key.into())
                        .decrypt(aes_gcm::Nonce::<U16>::from_slice(nonce), payload),
                    _ => return None,
                }
                .ok()?;
                // GCM está autenticado: si llegamos aquí el descifrado es correcto.
                Some(String::from_utf8(plain.clone()).unwrap_or_else(|_| format!("(binario, hex) {}", hex::encode(plain))))
            }
            Mode::Cbc { iv, data } => {
                if iv.len() != 16 || data.is_empty() || data.len() % 16 != 0 {
                    return None;
                }
                let plain = Aes256CbcDec::new(key.into(), iv.as_slice().into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .ok()?;
                // CBC no está autenticado: exigimos UTF-8 válido para evitar falsos positivos.
                String::from_utf8(plain).ok()
            }
        }
    }
}

fn candidates(input: &str) -> Vec<Attempt> {
    let mut gcm = Vec::new();
    let mut cbc = Vec::new();

    // JSON estilo Laravel: base64({"iv":..,"value":..,"mac":..,"tag":..})
    if let Some(json) = decode_b64(input).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) {
        let field = |k: &str| json.get(k).and_then(|v| v.as_str()).and_then(decode_b64);
        if let (Some(iv), Some(value)) = (field("iv"), field("value")) {
            match field("tag") {
                Some(tag) if !tag.is_empty() => gcm.push(Attempt::gcm("AES-256-GCM (JSON iv/value/tag)", &iv, &value, &tag)),
                _ => cbc.push(Attempt::cbc("AES-256-CBC (JSON iv/value)", &iv, &value)),
            }
        }
    }

    let parts: Vec<&str> = input.split([':', '.']).filter(|p| !p.is_empty()).collect();
    match parts.len() {
        3 => {
            for a in decodings(parts[0]) {
                for b in decodings(parts[1]) {
                    for c in decodings(parts[2]) {
                        if b.len() == TAG_LEN {
                            gcm.push(Attempt::gcm("AES-256-GCM (iv:tag:ciphertext)", &a, &c, &b));
                        }
                        if c.len() == TAG_LEN {
                            gcm.push(Attempt::gcm("AES-256-GCM (iv:ciphertext:tag)", &a, &b, &c));
                        }
                    }
                }
            }
        }
        2 => {
            for iv in decodings(parts[0]) {
                for ct in decodings(parts[1]) {
                    gcm.push(Attempt::gcm("AES-256-GCM (iv:ciphertext+tag)", &iv, &ct, &[]));
                    cbc.push(Attempt::cbc("AES-256-CBC (iv:ciphertext)", &iv, &ct));
                }
            }
        }
        _ => {}
    }

    // Un solo blob (Base64 o hex).
    for blob in decodings(input) {
        for n in [12, 16] {
            if blob.len() > n + TAG_LEN {
                let (nonce, rest) = blob.split_at(n);
                gcm.push(Attempt::gcm(&format!("AES-256-GCM (nonce{n} || ciphertext || tag)"), nonce, rest, &[]));
                let (tag, ct) = rest.split_at(TAG_LEN);
                gcm.push(Attempt::gcm(&format!("AES-256-GCM (nonce{n} || tag || ciphertext)"), nonce, ct, tag));
            }
        }
        if blob.len() > 16 {
            let (iv, ct) = blob.split_at(16);
            cbc.push(Attempt::cbc("AES-256-CBC (iv16 || ciphertext)", iv, ct));
        }
    }

    // GCM primero: es autenticado, así que un acierto es definitivo.
    gcm.extend(cbc);
    gcm
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str = "q0sZb3m2m5YlqfV1Rj2sQ0mJzG0c9fR6kHn1pX8wYtE=";

    fn key() -> [u8; 32] {
        parse_key(KEY_B64).unwrap()
    }

    #[test]
    fn gcm_blob() {
        let cipher = Aes256Gcm::new(&key().into());
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let ct = cipher.encrypt(&nonce, b"JBSWY3DPEHPK3PXP".as_ref()).unwrap();
        let blob = STANDARD.encode([nonce.as_slice(), &ct].concat());
        assert_eq!(decrypt(KEY_B64, &blob).unwrap().0, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn gcm_iv_tag_ct_hex() {
        let cipher = Aes256Gcm::new(&key().into());
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let out = cipher.encrypt(&nonce, b"secreto".as_ref()).unwrap();
        let (ct, tag) = out.split_at(out.len() - TAG_LEN);
        let s = format!("{}:{}:{}", hex::encode(nonce), hex::encode(tag), hex::encode(ct));
        assert_eq!(decrypt(KEY_B64, &s).unwrap().0, "secreto");
    }

    #[test]
    fn cbc_blob() {
        let iv = [7u8; 16];
        let ct = cbc::Encryptor::<Aes256>::new(&key().into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(b"hola mundo");
        let blob = STANDARD.encode([iv.as_slice(), &ct].concat());
        assert_eq!(decrypt(KEY_B64, &blob).unwrap().0, "hola mundo");
    }

    #[test]
    fn wrong_key_fails() {
        let cipher = Aes256Gcm::new(&key().into());
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let ct = cipher.encrypt(&nonce, b"x".as_ref()).unwrap();
        let blob = STANDARD.encode([nonce.as_slice(), &ct].concat());
        let other = STANDARD.encode([1u8; 32]);
        assert!(decrypt(&other, &blob).is_err());
    }

    #[test]
    fn encrypt_roundtrip_all_formats() {
        for (fmt, label) in [("gcm-b64", "nonce12 || ciphertext"), ("gcm-hex", "iv:tag:ciphertext"), ("cbc-b64", "CBC (iv16")] {
            let enc = encrypt(KEY_B64, "texto ñandú ✓", fmt).unwrap();
            let (plain, method) = decrypt(KEY_B64, &enc).unwrap();
            assert_eq!(plain, "texto ñandú ✓", "{fmt}");
            assert!(method.contains(label), "{fmt}: {method}");
        }
    }

    #[test]
    fn bad_key_length() {
        assert!(decrypt("YWJj", "AAAA").unwrap_err().contains("32 bytes"));
    }
}
