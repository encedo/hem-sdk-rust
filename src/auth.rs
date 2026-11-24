//! Password authorisation crypto and the token cache. No I/O here, so every
//! function is checked against vectors recorded from hem-sdk-js
//! (`tests/vectors/`).
//!
//! Flow (hem-sdk-js `authorizePassword`):
//! 1. `GET /api/auth/token` -> challenge `{ eid, spk, jti }`
//! 2. seed = PBKDF2-SHA256(password, salt = eid, 600 000 iterations, 32 B);
//!    X25519 key pair from the seed (`iss` = public key, standard base64)
//! 3. eJWT = b64url(header) . b64url(payload) . b64url(HMAC-SHA256(input, X25519(seed, spk)))
//! 4. `POST /api/auth/token { auth: eJWT }` -> `{ token }`
//!
//! A remembered password is `K_s = X25519(seed, spk)` (DEV-532, [`SessionKey`]),
//! not the seed: it signs every `auth` JWT of this device boot and dies with
//! the next one (new `spk`).

use std::time::{Duration, Instant};

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{HemError, Result};
use crate::limits::TOKEN_CTX;

pub(crate) const PBKDF2_ITERATIONS: u32 = 600_000;

/// The eJWT header, byte for byte what hem-sdk-js sends.
const EJWT_HEADER: &[u8] = br#"{"ecdh":"x25519","alg":"HS256","typ":"JWT"}"#;

const B64_ANY_PAD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// hem-sdk-js `fromB64`: standard or url-safe alphabet, padding optional.
pub(crate) fn from_b64(s: &str) -> Result<Vec<u8>> {
    let std: String = s.chars().map(|c| match c { '-' => '+', '_' => '/', c => c }).collect();
    B64_ANY_PAD
        .decode(std)
        .map_err(|_| HemError::new("bad_response", "invalid base64"))
}

pub(crate) fn to_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// One scope value, or 1..8 of them (DEV-436). Serialised as the caller gave
/// it: a string stays a string, a list stays a list - as hem-sdk-js does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scope {
    One(String),
    Many(Vec<String>),
}

impl Scope {
    pub fn values(&self) -> Vec<&str> {
        match self {
            Scope::One(s) => vec![s.as_str()],
            Scope::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }

    /// hem-sdk-js `checkScope`: the device answers a bad one with a bare 400.
    pub(crate) fn check(&self) -> Result<()> {
        let v = self.values();
        let mut seen = std::collections::HashSet::new();
        let ok = (1..=8).contains(&v.len())
            && v.iter().all(|s| !s.is_empty() && s.len() <= 44 && seen.insert(*s))
            && v.iter().filter(|s| s.starts_with("storage:")).count() <= 1;
        if ok {
            Ok(())
        } else {
            Err(HemError::invalid_arg(
                "a scope is a string, or 1..8 distinct strings with at most one storage:*",
            ))
        }
    }
}

impl From<&str> for Scope {
    fn from(s: &str) -> Self { Scope::One(s.to_owned()) }
}
impl From<String> for Scope {
    fn from(s: String) -> Self { Scope::One(s) }
}
impl From<Vec<String>> for Scope {
    fn from(v: Vec<String>) -> Self { Scope::Many(v) }
}
impl From<&[&str]> for Scope {
    fn from(v: &[&str]) -> Self { Scope::Many(v.iter().map(|s| (*s).to_owned()).collect()) }
}
impl<const N: usize> From<[&str; N]> for Scope {
    fn from(v: [&str; N]) -> Self { Scope::Many(v.iter().map(|s| (*s).to_owned()).collect()) }
}

pub(crate) fn check_token_ctx(ctx: Option<&str>) -> Result<()> {
    match ctx {
        Some(c) if c.is_empty() || c.len() > TOKEN_CTX => Err(HemError::invalid_arg(format!(
            "ctx is 1..{TOKEN_CTX} bytes of UTF-8"
        ))),
        _ => Ok(()),
    }
}

/// The challenge of `GET /api/auth/token`.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Challenge {
    pub eid: String,
    pub spk: String,
    pub jti: String,
}

/// The X25519 key pair a password (or the master secret) stands for.
pub(crate) struct DerivedKeys {
    secret: StaticSecret, // zeroized on drop (x25519-dalek "zeroize")
    pub pubkey_b64: String,
}

impl DerivedKeys {
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed); // clamped as RFC 7748 / WebCrypto
        let pubkey_b64 = to_b64(PublicKey::from(&secret).as_bytes());
        Self { secret, pubkey_b64 }
    }
}

/// DEV-532: what a remembered password leaves behind - the per-boot secret
/// `K_s = X25519(user_sk, spk)`, the HMAC key of every `auth` JWT of this
/// device boot. It dies with the device's next boot (new `spk`) and does not
/// give `user_sk`.
pub(crate) struct SessionKey {
    eid: String,
    spk: String,
    iss: String, // user_pk, standard base64 (the `iss` claim)
    k_s: Zeroizing<[u8; 32]>,
    until: Option<Instant>, // HemOptions::key_cache_ttl
}

impl SessionKey {
    /// `K_s` for this challenge. The caller drops `keys` right after.
    pub(crate) fn new(keys: &DerivedKeys, ch: &Challenge, ttl: Option<Duration>) -> Result<Self> {
        let shared = keys.secret.diffie_hellman(&PublicKey::from(spk_bytes(&ch.spk)?)); // zeroized on drop
        Ok(Self {
            eid: ch.eid.clone(),
            spk: ch.spk.clone(),
            iss: keys.pubkey_b64.clone(),
            k_s: Zeroizing::new(*shared.as_bytes()),
            until: ttl.map(|t| Instant::now() + t),
        })
    }

    /// Usable for this challenge: the same device boot (`eid`, `spk`), within the TTL.
    pub(crate) fn fits(&self, ch: &Challenge) -> bool {
        self.eid == ch.eid && self.spk == ch.spk && self.until.map_or(true, |u| Instant::now() < u)
    }

    /// The signed `auth` JWT for this challenge.
    pub(crate) fn ejwt(
        &self,
        ch: &Challenge,
        scope: &Scope,
        exp_seconds: u32,
        ctx: Option<&str>,
        now: i64,
    ) -> Result<String> {
        build_ejwt(&self.k_s, &EjwtPayload::new(ch, &self.iss, scope, exp_seconds, ctx, now))
    }

    pub(crate) fn iss(&self) -> &str {
        &self.iss
    }
}

fn spk_bytes(spk_b64: &str) -> Result<[u8; 32]> {
    from_b64(spk_b64)?
        .try_into()
        .map_err(|_| HemError::new("bad_response", "device key (spk) is not 32 bytes"))
}

/// PBKDF2-SHA256(password, eid, 600 000) -> X25519 key pair.
/// Slow on purpose (~0.3 s optimised); call it off the async runtime.
pub(crate) fn derive_x25519(password: &str, eid: &str) -> DerivedKeys {
    let mut seed = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), eid.as_bytes(), PBKDF2_ITERATIONS, seed.as_mut());
    DerivedKeys::from_seed(*seed)
}

/// The eJWT payload. Field order is the wire order of hem-sdk-js and must not change.
#[derive(Debug, Serialize)]
pub(crate) struct EjwtPayload<'a> {
    pub jti: &'a str,
    pub aud: &'a str,
    pub exp: i64,
    pub iat: i64,
    pub iss: &'a str,
    pub scope: &'a Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<&'a str>,
}

impl<'a> EjwtPayload<'a> {
    /// `iat` is now - 5 s (clock drift), `exp` = `iat` + `exp_seconds`.
    pub(crate) fn new(
        challenge: &'a Challenge,
        iss: &'a str,
        scope: &'a Scope,
        exp_seconds: u32,
        ctx: Option<&'a str>,
        now: i64,
    ) -> Self {
        let iat = now - 5;
        Self {
            jti: &challenge.jti,
            aud: &challenge.spk,
            exp: iat + i64::from(exp_seconds),
            iat,
            iss,
            scope,
            ctx,
        }
    }
}

/// The eJWT signed with `K_s` (DEV-532: the key, not the seed and `spk`).
pub(crate) fn build_ejwt(k_s: &[u8; 32], payload: &EjwtPayload<'_>) -> Result<String> {
    let body = serde_json::to_vec(payload).map_err(|e| HemError::invalid_arg(e.to_string()))?;
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(EJWT_HEADER), URL_SAFE_NO_PAD.encode(body));

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(k_s)
        .map_err(|_| HemError::new("auth_failed", "HMAC key"))?;
    mac.update(input.as_bytes());
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())))
}

/// Decode a JWT payload without verifying it (scope, exp, ...). `None` on malformed input.
pub fn jwt_parse(jwt: &str) -> Option<Value> {
    let mut parts = jwt.split('.');
    let (_, body, _, None) = (parts.next()?, parts.next()?, parts.next()?, parts.next()) else {
        return None;
    };
    serde_json::from_slice(&from_b64(body).ok()?).ok()
}

struct CacheEntry {
    scopes: Vec<String>,
    ctx: Option<String>,
    token: String,
    exp: i64,
}

/// Scoped tokens, keyed by what each token holds (read from the token: the
/// phone may approve less than was asked) and its `ctx`. hem-sdk-js `#tokenCache`.
#[derive(Default)]
pub(crate) struct TokenCache {
    entries: Vec<CacheEntry>,
}

impl TokenCache {
    pub(crate) fn store(&mut self, asked: &Scope, token: &str, ctx: Option<&str>, now: i64) {
        let payload = jwt_parse(token);
        let exp = payload
            .as_ref()
            .and_then(|p| p.get("exp"))
            .and_then(Value::as_i64)
            .unwrap_or(now + 300);
        let granted: Scope = payload
            .and_then(|p| p.get("scope").cloned())
            .and_then(|s| serde_json::from_value(s).ok())
            .unwrap_or_else(|| asked.clone());
        self.entries.push(CacheEntry {
            scopes: granted.values().into_iter().map(str::to_owned).collect(),
            ctx: ctx.map(str::to_owned),
            token: token.to_owned(),
            exp,
        });
        self.purge(now);
    }

    pub(crate) fn find(&mut self, scope: &Scope, ctx: Option<&str>, now: i64) -> Option<String> {
        self.purge(now);
        let wanted = scope.values();
        self.entries
            .iter()
            .find(|e| e.ctx.as_deref() == ctx && wanted.iter().all(|w| e.scopes.iter().any(|s| s == w)))
            .map(|e| e.token.clone())
    }

    fn purge(&mut self, now: i64) {
        self.entries.retain(|e| e.exp > now);
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_checks() {
        assert!(Scope::from("keymgmt:list").check().is_ok());
        assert!(Scope::from("").check().is_err());
        assert!(Scope::from(["a", "a"]).check().is_err());
        assert!(Scope::from(["storage:disk0:rw", "storage:disk1:rw"]).check().is_err());
        assert!(Scope::Many(vec![]).check().is_err());
    }

    #[test]
    fn scope_serialises_as_given() {
        assert_eq!(serde_json::to_string(&Scope::from("x")).unwrap(), r#""x""#);
        assert_eq!(serde_json::to_string(&Scope::from(["x"])).unwrap(), r#"["x"]"#);
    }

    #[test]
    fn cache_matches_scope_and_ctx() {
        // header.payload.sig with payload {"exp":2000,"scope":["a","b"]}
        let p = URL_SAFE_NO_PAD.encode(br#"{"exp":2000,"scope":["a","b"]}"#);
        let jwt = format!("h.{p}.s");
        let mut c = TokenCache::default();
        c.store(&Scope::from(["a", "b"]), &jwt, None, 1000);
        assert_eq!(c.find(&Scope::from("b"), None, 1000).as_deref(), Some(jwt.as_str()));
        assert!(c.find(&Scope::from("b"), Some("x"), 1000).is_none());
        assert!(c.find(&Scope::from("c"), None, 1000).is_none());
        assert!(c.find(&Scope::from("a"), None, 2000).is_none()); // expired
    }

    fn challenge(spk_byte: u8) -> Challenge {
        Challenge { eid: to_b64(&[7u8; 32]), spk: to_b64(&[spk_byte; 32]), jti: to_b64(&[1u8; 32]) }
    }

    // DEV-532: a remembered password fits only the device boot it came from.
    #[test]
    fn session_key_fits_one_boot() {
        let keys = DerivedKeys::from_seed([5u8; 32]);
        let ch = challenge(9);
        let s = SessionKey::new(&keys, &ch, None).unwrap();
        assert!(s.fits(&ch));
        assert!(s.fits(&Challenge { jti: to_b64(&[2u8; 32]), ..ch.clone() })); // a new nonce, same boot
        assert!(!s.fits(&challenge(10))); // new spk: the device rebooted
        assert!(!s.fits(&Challenge { eid: to_b64(&[8u8; 32]), ..ch.clone() })); // another device
        let expired = SessionKey::new(&keys, &ch, Some(Duration::ZERO)).unwrap();
        assert!(!expired.fits(&ch));
    }

    // DEV-532: K_s is X25519(user_sk, spk) - the same key the device computes
    // as X25519(spk_sk, iss).
    #[test]
    fn session_key_is_the_device_shared_secret() {
        let user = DerivedKeys::from_seed([5u8; 32]);
        let spk_sk = StaticSecret::from([9u8; 32]);
        let ch = Challenge { spk: to_b64(PublicKey::from(&spk_sk).as_bytes()), ..challenge(0) };
        let s = SessionKey::new(&user, &ch, None).unwrap();
        let iss: [u8; 32] = from_b64(s.iss()).unwrap().try_into().unwrap();
        assert_eq!(*s.k_s, *spk_sk.diffie_hellman(&PublicKey::from(iss)).as_bytes());
    }
}
