//! Device limits checked before a request (hem-sdk-js `LIMITS`), each with the
//! section of the API reference (`HEM_API_reference_1.3.x.md`) it comes from.

/// "Common rules (HMAC, ExDSA, cipher endpoints)": `msg` at most 2048 bytes decoded.
pub(crate) const CRYPTO_MSG: usize = 2048;
/// exdsa/sign, exdsa/verify: `ctx` 1..255 bytes (RFC 8032 context).
pub(crate) const SIG_CTX: usize = 255;
/// keymgmt/list, keymgmt/search: at most 15 entries a page.
pub(crate) const PAGE_SIZE: u32 = 15;
/// auth/token (auth claim), auth/ext/request: `ctx` 1..64 bytes of UTF-8.
pub(crate) const TOKEN_CTX: usize = 64;
/// auth/ext/request: `note` 1..128 bytes of UTF-8, shown with the request on the phone.
pub(crate) const REMOTE_NOTE: usize = 128;
/// Paging stops here even if a device keeps answering (hem-sdk-js `0xffff`).
pub(crate) const MAX_OFFSET: u32 = 0xffff;
