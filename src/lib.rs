//! Rust client for the Encedo HEM, firmware 1.3 and later.
//!
//! The Rust counterpart of [hem-sdk-js](https://github.com/encedo/hem-sdk-js):
//! the same classes (`Hem`, `Broker`), the same error codes, the same wire
//! format. Private keys never leave the device. See `docs/DESIGN.md`.
//!
//! ```no_run
//! # async fn demo() -> hem_sdk::Result<()> {
//! use hem_sdk::{AuthOptions, Hem, HemOptions};
//!
//! let hem = Hem::new("https://my.ence.do", HemOptions::default())?;
//! let token = hem
//!     .authorize_password(Some("password"), "keymgmt:list", AuthOptions::default())
//!     .await?;
//! # let _ = token; Ok(()) }
//! ```

mod auth;
mod broker;
mod crypto;
mod error;
mod hem;
mod http;
mod keys;
mod limits;

pub use auth::{jwt_parse, Scope};
pub use broker::{Broker, DEFAULT_BROKER_URL};
pub use crypto::{SignOptions, VerifyOptions};
pub use error::{HemError, Result};
pub use hem::{AuthOptions, Hem, HemOptions, RemoteOptions, Uv};
pub use keys::{CreateOptions, KeyEntry, KeyPage, ListOptions, Match, SearchOptions};

/// Internals exposed for the cross-language vector tests only. Not a public API.
#[doc(hidden)]
pub mod __vectors {
    use crate::auth::{derive_x25519, Challenge, Scope, SessionKey};
    use crate::error::Result;

    /// (iss, eJWT) for a password, a challenge, a scope and a fixed clock.
    #[allow(clippy::too_many_arguments)]
    pub fn password_ejwt(
        password: &str,
        eid: &str,
        spk: &str,
        jti: &str,
        scope: &Scope,
        exp_seconds: u32,
        ctx: Option<&str>,
        now: i64,
    ) -> Result<(String, String)> {
        // DEV-532: through the remembered-password path - the recorded vectors
        // prove the wire is unchanged.
        let keys = derive_x25519(password, eid);
        let ch = Challenge { eid: eid.into(), spk: spk.into(), jti: jti.into() };
        let session = SessionKey::new(&keys, &ch, None)?;
        let ejwt = session.ejwt(&ch, scope, exp_seconds, ctx, now)?;
        Ok((session.iss().to_owned(), ejwt))
    }
}
