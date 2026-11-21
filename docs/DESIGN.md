# hem-sdk-rust - design

Status: v0.1 in progress (2026-11-21). The design decisions behind the code;
what is still open is at the end.

## Goal

A Rust client for the Encedo HEM, firmware 1.3 and later, as a counterpart of
[hem-sdk-js](https://github.com/encedo/hem-sdk-js). First consumer:
[hem-ssh-agent](https://github.com/encedo/hem-ssh-agent), which takes this
repository as a git submodule. Later consumers: any Rust tool that talks to a
HEM (CLI tools, the desktop side of encedo-authenticator).

Private keys never leave the device: the SDK only shapes requests and checks
answers.

## Principles

1. **Mirror hem-sdk-js.** The same types (`Hem`, `Broker`, later `Attest`),
   the same flows, the same `HemError` codes (`http_<status>`, `timeout`,
   `network`, `invalid_arg`, `auth_failed`, `auth_password_required`,
   `checkin_error`, `broker_error`, `denied`, ...). Someone who knows one SDK
   finds their way in the other. Method names are the Rust spelling of the JS
   ones (`authorizePassword` -> `authorize_password`).
2. **One to one with the firmware API** in the end, as hem-sdk-js: every
   release endpoint gets a method. Built incrementally, in the order consumers
   need them.
3. **Byte-identical wire format.** Everything the device checks
   cryptographically (eJWT, derived keys, later the broker frames) is verified
   against vectors recorded from the real hem-sdk-js (`tests/vectors/gen.mjs`),
   not against a second copy of the algorithm.
4. **Device facts are built into the transport** (`src/http.rs`), learnt in
   hem-sdk-js:
   - the request body always carries `Content-Length` (a chunked body gets 411);
   - no connection pool: the device closes some connections after the answer
     while still saying keep-alive, and the next request on that socket fails.
5. **Validate before sending** where the device would only answer a bare 400
   (scope shape, `ctx` length, ...). Limits come from the API reference
   (`encedo_firmware/docs/HEM_API_reference_1.3.x.md`) and are named after it.
6. **Air gap first.** Only `Broker` talks to api.encedo.com. No device-only
   method may need it.
7. **Secrets:** a password is held as `Zeroizing<String>` only for the key
   derivation; the derived X25519 secret is zeroized on drop; PBKDF2 (600 000
   iterations) runs on `spawn_blocking`, off the async runtime.

## Technical choices

| Topic | Choice | Why |
|---|---|---|
| Async | tokio | reqwest needs it; hem-ssh-agent and encedo-authenticator use it |
| HTTP | reqwest 0.12, no default features | as encedo-authenticator |
| TLS | rustls + bundled Mozilla roots (`webpki-roots`) on every platform | one stack to test everywhere; devices use public (Let's Encrypt) certificates. Needs a C compiler for `ring` (on Windows GNU: MinGW-w64 on PATH) |
| Crypto | x25519-dalek, pbkdf2 + sha2, hmac (RustCrypto) | pure Rust, as encedo-authenticator |
| JSON | serde_json; system answers as `serde_json::Value` for now | typed structs where the shape is stable and a consumer needs them |
| Errors | one `HemError { code, status, data }` | the JS codes; `data` = the device's answer body |
| Cancellation | drop the future; per-request timeout in `HemOptions` | no `aborted` code: Rust has no detached request to cancel |
| MSRV | 1.80 | |
| Licence | MIT | as hem-sdk-js |

## Layout

```
src/lib.rs      public surface
src/error.rs    HemError
src/http.rs     the single HTTP entry point (device and broker)
src/auth.rs     password -> X25519, eJWT, scope checks, token cache (no I/O)
src/hem.rs      Hem: system + authorisation methods
src/keys.rs     impl Hem: key management (create, get, list, search), KeyEntry, KeyPage
src/crypto.rs   impl Hem: cryptography (exdsa sign / verify, ...)
src/limits.rs   device limits, each with its API reference section
src/broker.rs   Broker: api.encedo.com
tests/vectors/  gen.mjs + recorded vectors (from hem-sdk-js)
tests/*.rs      vector tests (offline), live tests (HEM_URL)
```

## Testing

- `cargo test` - offline: unit tests and the hem-sdk-js vectors.
- `HEM_URL=... [HEM_PASSWORD=...] cargo test --test live` - against a device.
- Regenerate vectors after a change in hem-sdk-js auth code:
  `node tests/vectors/gen.mjs > tests/vectors/password_v1.json`, then
  `cargo test`. A changed vector file is a wire-format change: say so in the
  commit.

## Roadmap

- v0.1 (for hem-ssh-agent): done - `get_version`, `get_status`,
  `hem_checkin`, `authorize_password`, `create_key_pair`,
  `get_key_public_info`, `list_keys(_all)`, `search_keys(_all)`,
  `exdsa_sign`, `exdsa_verify`, `authorize_remote` (broker + phone; live
  test with a paired authenticator behind `HEM_REMOTE=1`) with the broker's
  `session`, `event_new`, `event_check`, `event_delete`, `wait_event`.
  A pending event is withdrawn on error, timeout or when the caller drops
  the future (no `onPending` / `onEvent` callbacks yet).
- Methods are grouped in `impl Hem` blocks per file, as hem-sdk-js groups
  them; the `*_all` walks return a `Vec` (hem-sdk-js: async generators).
- Later: `authorize_master` (BIP39), key management, ECDH, cipher, HPKE, PQC,
  storage, logs, attestation, firmware upload - in the order consumers need.

## Open

- Typed answer structs vs `serde_json::Value` per method.
- Custom trust anchors (a device with a private CA) - not needed so far.
- Publishing to crates.io (name, owner) - not decided; `publish = false`.
