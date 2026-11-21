//! Cryptography (hem-sdk-js "Cryptography"). Every /api/crypto/* call needs a
//! token with `keymgmt:use:<KID>` for the key it names. Data in and out is
//! bytes; `msg` is at most 2048 bytes.

use reqwest::Method;
use serde_json::{json, Map, Value};

use crate::auth::{from_b64, to_b64};
use crate::error::{HemError, Result};
use crate::hem::Hem;
use crate::limits::{CRYPTO_MSG, SIG_CTX};

/// Options for [`Hem::exdsa_sign`].
#[derive(Clone, Debug)]
pub struct SignOptions {
    /// `SHA256WithECDSA`, `SHA384WithECDSA`, `SHA512WithECDSA`, `ECDSA`
    /// (prehashed), `Ed25519`, `Ed25519ph`, `Ed25519ctx`, `Ed448`, `Ed448ph`,
    /// fitting the key's curve.
    pub alg: String,
    /// RFC 8032 context, 1..255 bytes; required for `Ed25519ctx`.
    pub ctx: Option<Vec<u8>>,
    /// Deterministic ECDSA (RFC 6979). Ignored for EdDSA.
    pub det: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self { alg: "Ed25519".into(), ctx: None, det: false }
    }
}

/// Options for [`Hem::exdsa_verify`].
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// As [`SignOptions::alg`].
    pub alg: String,
    /// As signed.
    pub ctx: Option<Vec<u8>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { alg: "Ed25519".into(), ctx: None }
    }
}

fn check_msg_size(op: &str, data: &[u8]) -> Result<()> {
    if data.len() > CRYPTO_MSG {
        return Err(HemError::invalid_arg(format!(
            "{op}: message is {} bytes, max {CRYPTO_MSG}",
            data.len()
        )));
    }
    Ok(())
}

fn sig_ctx(op: &str, ctx: &[u8]) -> Result<String> {
    if ctx.is_empty() || ctx.len() > SIG_CTX {
        return Err(HemError::invalid_arg(format!(
            "{op}: ctx is {} bytes, must be 1..{SIG_CTX}",
            ctx.len()
        )));
    }
    Ok(to_b64(ctx))
}

impl Hem {
    /// Sign with an ECDSA (NIST, secp256k1) or EdDSA (Ed25519, Ed448) key in
    /// the HEM. ECDSA comes back as raw `r || s` (64 / 96 / 132 bytes),
    /// Ed25519 64 bytes, Ed448 114 bytes.
    ///
    /// `data`: the message, 1..2048 bytes; for `ECDSA` the digest (20..64 B).
    ///
    /// Required scope: `keymgmt:use:<KID>`
    pub async fn exdsa_sign(&self, token: &str, kid: &str, data: &[u8], opts: SignOptions) -> Result<Vec<u8>> {
        check_msg_size("exdsa_sign", data)?;
        let mut body = Map::new();
        body.insert("kid".into(), json!(kid));
        body.insert("alg".into(), json!(opts.alg));
        body.insert("msg".into(), json!(to_b64(data)));
        if let Some(c) = &opts.ctx {
            body.insert("ctx".into(), json!(sig_ctx("exdsa_sign", c)?));
        }
        if opts.det {
            body.insert("det".into(), json!(true));
        }
        let v = self.req(Method::POST, "/api/crypto/exdsa/sign", Some(&Value::Object(body)), Some(token)).await?;
        match v.get("sign").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => from_b64(s),
            _ => Err(HemError::new("sign_error", "No sign in exdsa/sign response")),
        }
    }

    /// Verify an EdDSA / ECDSA signature with a key in the HEM (a key pair or
    /// an imported public key). The device answers 200 for every well-formed
    /// request and puts the verdict in the body: this returns that verdict.
    /// Any other status (unknown key, wrong curve for `alg`, bad length) is an error.
    ///
    /// `sig`: ECDSA `r || s` (exactly twice the curve size), EdDSA raw.
    ///
    /// Required scope: `keymgmt:use:<KID>`
    pub async fn exdsa_verify(
        &self,
        token: &str,
        kid: &str,
        data: &[u8],
        sig: &[u8],
        opts: VerifyOptions,
    ) -> Result<bool> {
        check_msg_size("exdsa_verify", data)?;
        let mut body = Map::new();
        body.insert("kid".into(), json!(kid));
        body.insert("alg".into(), json!(opts.alg));
        body.insert("msg".into(), json!(to_b64(data)));
        body.insert("sign".into(), json!(to_b64(sig)));
        if let Some(c) = &opts.ctx {
            body.insert("ctx".into(), json!(sig_ctx("exdsa_verify", c)?));
        }
        let v = self.req(Method::POST, "/api/crypto/exdsa/verify", Some(&Value::Object(body)), Some(token)).await?;
        Ok(v.get("verified") == Some(&Value::Bool(true)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hem::HemOptions;

    // Nothing listens on port 9: a request that got through would fail as `network`.
    fn offline() -> Hem {
        Hem::new("http://127.0.0.1:9", HemOptions::default()).unwrap()
    }

    #[tokio::test]
    async fn sign_refuses_a_long_message_before_sending() {
        let e = offline()
            .exdsa_sign("t", "k", &[0u8; CRYPTO_MSG + 1], SignOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid_arg");
    }

    #[tokio::test]
    async fn sign_refuses_an_empty_or_long_ctx() {
        for ctx in [vec![], vec![0u8; SIG_CTX + 1]] {
            let opts = SignOptions { ctx: Some(ctx), ..Default::default() };
            let e = offline().exdsa_sign("t", "k", b"m", opts).await.unwrap_err();
            assert_eq!(e.code, "invalid_arg");
        }
    }
}
