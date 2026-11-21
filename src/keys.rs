//! Key management (hem-sdk-js "Key Management": createKeyPair,
//! getKeyPublicInfo, listKeys, searchKeys and the `*All` walks).
//!
//! Field rules (API 1.3): a label is 1..64 printable ASCII characters; a
//! description is a byte field of up to 128 bytes, carried as base64 - the SDK
//! takes and returns it as bytes. The SDK polices neither; the device answers
//! 400 to what will not fit.

use reqwest::Method;
use serde_json::{json, Map, Value};

use crate::auth::{from_b64, to_b64};
use crate::error::{HemError, Result};
use crate::hem::Hem;
use crate::limits::{MAX_OFFSET, PAGE_SIZE};

/// One key as the SDK hands it out, from a list, search, get or create answer.
/// The device's `type` is the flags and the type joined by commas
/// (`ATT,PKEY,ExDSA,ED25519`); it is split here so no caller has to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyEntry {
    /// 32 hex characters.
    pub kid: String,
    pub label: String,
    /// The key type, e.g. `ED25519`, `SECP256R1`, `AES256`, `GENERIC_DER`.
    pub key_type: String,
    /// Device flags: `ATT` (made inside the HEM), `PKEY` (private half stored),
    /// `ECDH`, `ExDSA`, `CERT`, `PQC`, `HPKE`.
    pub flags: Vec<String>,
    pub description: Option<Vec<u8>>,
    /// Unix seconds.
    pub created: Option<i64>,
    pub updated: Option<i64>,
    /// When the call asked for it (or `get_key_public_info`).
    pub pubkey: Option<Vec<u8>>,
    /// Certificate records, `get_key_public_info` only.
    pub der: Option<Vec<u8>>,
}

fn b64_field(v: &Value, name: &str) -> Result<Option<Vec<u8>>> {
    match v.get(name).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => from_b64(s).map(Some),
        _ => Ok(None),
    }
}

fn str_field(v: &Value, name: &str) -> String {
    v.get(name).and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// hem-sdk-js `keyEntry`.
pub(crate) fn key_entry(v: &Value) -> Result<KeyEntry> {
    let mut parts: Vec<String> = str_field(v, "type")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let key_type = parts.pop().unwrap_or_default();
    Ok(KeyEntry {
        kid: str_field(v, "kid"),
        label: str_field(v, "label"),
        key_type,
        flags: parts,
        description: b64_field(v, "descr")?,
        created: v.get("created").and_then(Value::as_i64),
        updated: v.get("updated").and_then(Value::as_i64),
        pubkey: b64_field(v, "pubkey")?,
        der: b64_field(v, "der")?,
    })
}

/// One page of a list or a search. `listed` drives the paging: the next page
/// starts at `offset + listed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPage {
    pub list: Vec<KeyEntry>,
    pub offset: u32,
    /// List: every record. Search: every record too, not the matches.
    pub total: u32,
    pub listed: u32,
    pub deleted: u32,
    /// Records that fail their CRC: they take a slot but are not in `list`.
    pub invalid: u32,
}

fn u32_field(v: &Value, name: &str) -> Option<u32> {
    v.get(name).and_then(Value::as_u64).map(|n| n.min(u64::from(u32::MAX)) as u32)
}

/// hem-sdk-js `keyPage`.
pub(crate) fn key_page(v: &Value, offset: u32) -> Result<KeyPage> {
    let list = v
        .get("list")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(key_entry).collect::<Result<Vec<_>>>())
        .transpose()?
        .unwrap_or_default();
    let n = list.len() as u32;
    Ok(KeyPage {
        offset: u32_field(v, "offset").unwrap_or(offset),
        total: u32_field(v, "total").unwrap_or(n),
        listed: u32_field(v, "listed").unwrap_or(n),
        deleted: u32_field(v, "deleted").unwrap_or(0),
        invalid: u32_field(v, "invalid").unwrap_or(0),
        list,
    })
}

/// A KID in a path segment: 32 hex characters, or the device answers 400 / 404.
pub(crate) fn check_kid(op: &str, kid: &str) -> Result<()> {
    if kid.len() == 32 && kid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(HemError::invalid_arg(format!("{op}: kid is 32 hex characters")))
    }
}

/// What an asymmetric key may be used for (API 1.3, keymgmt/create, key
/// types); hem-sdk-js `KEY_MODES`. Only the types that can do more than one
/// thing take a mode; everything else (ED448, ML-DSA, HMAC, OTP, AES) none.
fn key_modes(key_type: &str) -> &'static [&'static str] {
    const NIST: &[&str] = &["ECDH", "ExDSA", "ECDH,ExDSA", "HPKE"];
    match key_type {
        "SECP256R1" | "SECP384R1" | "SECP521R1" => NIST,
        "SECP256K1" => &NIST[..3],
        "ED25519" => &["ExDSA", "ECDH", "ECDH,ExDSA"],
        "CURVE25519" | "CURVE448" => &["ECDH", "HPKE"],
        "MLKEM512" | "MLKEM768" | "MLKEM1024" => &["HPKE"],
        _ => &[],
    }
}

/// `bad_mode` before the request when a mode does not fit the key type
/// (the device answers a bare 400). hem-sdk-js `checkMode`.
pub(crate) fn check_mode(key_type: &str, mode: Option<&str>) -> Result<()> {
    let Some(mode) = mode.filter(|m| !m.is_empty()) else { return Ok(()) };
    let allowed = key_modes(key_type);
    if allowed.contains(&mode) {
        return Ok(());
    }
    let msg = if allowed.is_empty() {
        format!("A key of type {key_type} takes no mode, got '{mode}'")
    } else {
        let list: Vec<String> = allowed.iter().map(|m| format!("'{m}'")).collect();
        format!("A key of type {key_type} takes mode {}, not '{mode}'", list.join(", "))
    };
    Err(HemError::new("bad_mode", msg))
}

/// Options for [`Hem::create_key_pair`].
#[derive(Clone, Debug, Default)]
pub struct CreateOptions {
    /// Description, up to 128 bytes.
    pub descr: Option<Vec<u8>>,
    /// `ECDH`, `ExDSA`, `ECDH,ExDSA` or `HPKE` - only where the type takes one.
    pub mode: Option<String>,
    /// Return the public key with the answer.
    pub return_pubkey: bool,
}

/// Options for [`Hem::list_keys`].
#[derive(Clone, Debug)]
pub struct ListOptions {
    pub offset: u32,
    /// The device caps it at 15.
    pub limit: u32,
    /// Add public keys - only with the `pubkey_in_list` policy, ignored without it.
    pub return_pubkey: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self { offset: 0, limit: PAGE_SIZE, return_pubkey: false }
    }
}

/// Where a search pattern must match the description.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Match {
    #[default]
    Prefix,
    Suffix,
    Contains,
}

/// Options for [`Hem::search_keys`].
#[derive(Clone, Debug)]
pub struct SearchOptions {
    pub matching: Match,
    /// Matches to skip.
    pub offset: u32,
    pub limit: u32,
    /// Only keys of this type, e.g. `ED25519`.
    pub key_type: Option<String>,
    /// Only keys with these flags: `ECDH`, `ExDSA`, `ECDH,ExDSA`, `HPKE`.
    pub mode: Option<String>,
    /// Add public keys (`pubkey_in_search` policy).
    pub return_pubkey: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            matching: Match::Prefix,
            offset: 0,
            limit: PAGE_SIZE,
            key_type: None,
            mode: None,
            return_pubkey: false,
        }
    }
}

impl Hem {
    /// Generate a new key inside the HEM from its RNG. The private half, or the
    /// secret of a symmetric key, never leaves the device.
    ///
    /// Required scope: `keymgmt:gen`
    pub async fn create_key_pair(
        &self,
        token: &str,
        label: &str,
        key_type: &str,
        opts: CreateOptions,
    ) -> Result<KeyEntry> {
        check_mode(key_type, opts.mode.as_deref())?;
        let mut body = Map::new();
        body.insert("type".into(), json!(key_type));
        body.insert("label".into(), json!(label));
        if let Some(d) = &opts.descr {
            body.insert("descr".into(), json!(to_b64(d)));
        }
        if let Some(m) = opts.mode.as_deref().filter(|m| !m.is_empty()) {
            body.insert("mode".into(), json!(m));
        }
        if opts.return_pubkey {
            body.insert("return_pubkey".into(), json!(true));
        }
        let v = self.req(Method::POST, "/api/keymgmt/create", Some(&Value::Object(body)), Some(token)).await?;
        key_entry(&v)
    }

    /// One key's metadata and public part (`GET /api/keymgmt/get/<kid>`). No
    /// private material ever comes back: an asymmetric key gives its public
    /// key, a certificate record its DER, a symmetric key metadata only.
    ///
    /// Required scope: `keymgmt:get`, `keymgmt:gen` or `keymgmt:use:<kid>`
    pub async fn get_key_public_info(&self, token: &str, kid: &str) -> Result<KeyEntry> {
        check_kid("get_key_public_info", kid)?;
        let mut v = self.req(Method::GET, &format!("/api/keymgmt/get/{kid}"), None, Some(token)).await?;
        if let Value::Object(m) = &mut v {
            m.insert("kid".into(), json!(kid));
        }
        key_entry(&v)
    }

    /// One page of the key repository, in storage order (a changed key moves
    /// to the end). At most 15 entries; fewer with public keys.
    ///
    /// Required scope: `keymgmt:list`
    pub async fn list_keys(&self, token: &str, opts: ListOptions) -> Result<KeyPage> {
        let suffix = if opts.return_pubkey { "/pubkey" } else { "" };
        let path = format!("/api/keymgmt/list/{}/{}{suffix}", opts.offset, opts.limit);
        let v = self.req(Method::GET, &path, None, Some(token)).await?;
        key_page(&v, opts.offset)
    }

    /// Every key `list_keys` would page through. Pages run on `listed` until
    /// the offset reaches `total`; an empty page ends the walk too.
    /// (hem-sdk-js `listKeysAll` is a generator; here the result is collected.)
    ///
    /// Required scope: `keymgmt:list`
    pub async fn list_keys_all(&self, token: &str, return_pubkey: bool) -> Result<Vec<KeyEntry>> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let page = self.list_keys(token, ListOptions { offset, limit: PAGE_SIZE, return_pubkey }).await?;
            out.extend(page.list);
            if page.listed == 0 {
                return Ok(out);
            }
            offset = offset.saturating_add(page.listed);
            if offset >= page.total || offset > MAX_OFFSET {
                return Ok(out);
            }
        }
    }

    /// Keys whose description matches a byte pattern (1..128 bytes), with
    /// optional filters. The pattern goes base64-encoded with the anchor on
    /// the base64 text: `^` prefix, `$` suffix, none for anywhere.
    ///
    /// Without a token the device answers only a prefix search of at least
    /// 6 bytes, and only when `allow_keysearch` is on.
    ///
    /// Required scope: one of `keymgmt:search`, `keymgmt:list`, `auth:ext:pair`
    pub async fn search_keys(&self, token: Option<&str>, pattern: &[u8], opts: SearchOptions) -> Result<KeyPage> {
        let b64 = to_b64(pattern);
        let descr = match opts.matching {
            Match::Prefix => format!("^{b64}"),
            Match::Suffix => format!("{b64}$"),
            Match::Contains => b64,
        };
        let mut body = Map::new();
        body.insert("descr".into(), json!(descr));
        body.insert("offset".into(), json!(opts.offset));
        body.insert("limit".into(), json!(opts.limit));
        if let Some(t) = opts.key_type.as_deref().filter(|t| !t.is_empty()) {
            body.insert("type".into(), json!(t));
        }
        if let Some(m) = opts.mode.as_deref().filter(|m| !m.is_empty()) {
            body.insert("mode".into(), json!(m));
        }
        if opts.return_pubkey {
            body.insert("return_pubkey".into(), json!(true));
        }
        let v = self.req(Method::POST, "/api/keymgmt/search", Some(&Value::Object(body)), token).await?;
        key_page(&v, opts.offset)
    }

    /// Every key `search_keys` would find, across pages. A search page's
    /// `total` counts every record, not the matches, so the walk goes on from
    /// `offset + listed` until a page comes back empty (the device's rule).
    /// `opts.offset` / `opts.limit` are ignored.
    ///
    /// Required scope: as `search_keys`
    pub async fn search_keys_all(
        &self,
        token: Option<&str>,
        pattern: &[u8],
        opts: SearchOptions,
    ) -> Result<Vec<KeyEntry>> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let page = self
                .search_keys(token, pattern, SearchOptions { offset, limit: PAGE_SIZE, ..opts.clone() })
                .await?;
            out.extend(page.list);
            if page.listed == 0 {
                return Ok(out);
            }
            offset = offset.saturating_add(page.listed);
            if offset > MAX_OFFSET {
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_splits_type_and_decodes_fields() {
        let v = json!({
            "kid": "00112233445566778899aabbccddeeff", "label": "k",
            "type": "ATT,PKEY,ExDSA,ED25519", "descr": "aGVsbG8=", "created": 5,
            "pubkey": "AAEC"
        });
        let e = key_entry(&v).unwrap();
        assert_eq!(e.key_type, "ED25519");
        assert_eq!(e.flags, vec!["ATT", "PKEY", "ExDSA"]);
        assert_eq!(e.description.as_deref(), Some(&b"hello"[..]));
        assert_eq!(e.created, Some(5));
        assert_eq!(e.updated, None);
        assert_eq!(e.pubkey.as_deref(), Some(&[0u8, 1, 2][..]));
        assert_eq!(e.der, None);
    }

    #[test]
    fn page_defaults_follow_the_list() {
        let p = key_page(&json!({ "list": [{ "type": "AES256" }] }), 7).unwrap();
        assert_eq!((p.offset, p.total, p.listed, p.deleted, p.invalid), (7, 1, 1, 0, 0));
    }

    #[test]
    fn modes_and_kids() {
        assert!(check_mode("ED25519", Some("ExDSA")).is_ok());
        assert!(check_mode("ED25519", None).is_ok());
        assert_eq!(check_mode("ED25519", Some("HPKE")).unwrap_err().code, "bad_mode");
        assert_eq!(check_mode("SECP256K1", Some("HPKE")).unwrap_err().code, "bad_mode");
        assert_eq!(check_mode("AES256", Some("ECDH")).unwrap_err().code, "bad_mode");
        assert!(check_kid("t", "00112233445566778899aabbccddeeff").is_ok());
        assert!(check_kid("t", "0011").is_err());
        assert!(check_kid("t", "zz112233445566778899aabbccddeeff").is_err());
    }
}
