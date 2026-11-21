//! The device (hem-sdk-js `HEM`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Method;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::auth::{
    build_ejwt, check_token_ctx, derive_x25519, now_unix, Challenge, DerivedKeys, EjwtPayload, Scope,
    TokenCache,
};
use crate::broker::{Broker, DEFAULT_BROKER_URL};
use crate::error::{HemError, Result};
use crate::http::Http;

/// Options for [`Hem::new`].
#[derive(Clone, Debug, Default)]
pub struct HemOptions {
    /// The broker to use; `None` = api.encedo.com.
    pub broker: Option<Broker>,
    /// Per-request timeout (`HemError` code `timeout`); `None` = no limit.
    pub timeout: Option<Duration>,
}

/// Options for [`Hem::authorize_password`].
#[derive(Clone, Debug)]
pub struct AuthOptions {
    /// Requested token lifetime; the device's own default without one is 60 s.
    pub exp_seconds: u32,
    /// Keep the derived key for the scopes that follow (no password again).
    /// Tokens are cached either way.
    pub remember: bool,
    /// 1..64 bytes of UTF-8, copied into the token.
    pub ctx: Option<String>,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self { exp_seconds: 300, remember: true, ctx: None }
    }
}

/// One HEM device.
pub struct Hem {
    base_url: String,
    http: Http,
    broker: Broker,
    tokens: Mutex<TokenCache>,
    keys: Mutex<Option<Arc<DerivedKeys>>>,
}

impl Hem {
    /// `url` is the device base URL, e.g. `https://my.ence.do`.
    pub fn new(url: &str, opts: HemOptions) -> Result<Self> {
        let broker = match opts.broker {
            Some(b) => b,
            None => Broker::new(DEFAULT_BROKER_URL, opts.timeout)?,
        };
        Ok(Self {
            base_url: url.trim_end_matches('/').to_owned(),
            http: Http::new("HEM", opts.timeout)?,
            broker,
            tokens: Mutex::new(TokenCache::default()),
            keys: Mutex::new(None),
        })
    }

    /// The broker this instance uses for every api.encedo.com call.
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    pub(crate) async fn req(&self, method: Method, path: &str, body: Option<&Value>, token: Option<&str>) -> Result<Value> {
        self.http.request(method, &format!("{}{path}", self.base_url), body, token).await
    }

    // -- Caches ---------------------------------------------------------------

    /// Drop the derived key and every cached token (logout).
    pub fn clear_keys(&self) {
        *self.keys.lock().unwrap() = None;
        self.tokens.lock().unwrap().clear();
    }

    /// Drop every cached token.
    pub fn clear_cache(&self) {
        self.tokens.lock().unwrap().clear();
    }

    // -- System ---------------------------------------------------------------

    /// `GET /api/system/version`. No token needed.
    pub async fn get_version(&self, token: Option<&str>) -> Result<Value> {
        self.req(Method::GET, "/api/system/version", None, token).await
    }

    /// `GET /api/system/status`. No token needed.
    pub async fn get_status(&self) -> Result<Value> {
        self.req(Method::GET, "/api/system/status", None, None).await
    }

    /// The 3-step check-in: device challenge, broker counter-signature, device
    /// clock sync. Resolves with the device's step-3 answer (`status`, maybe
    /// `newfws` / `newuis`). Without a reachable broker this fails with
    /// `broker_error` or `network`; password authorisation still works after.
    pub async fn hem_checkin(&self) -> Result<Value> {
        let step1 = self.req(Method::GET, "/api/system/checkin", None, None).await?;
        if step1.get("check").is_none() {
            return Err(HemError::new("checkin_error", "HSM checkin failed (no check field)"));
        }
        let step2 = self.broker.checkin(&step1).await?;
        if step2.get("checked").is_none() {
            return Err(HemError::new("broker_error", "Broker checkin failed (no checked field)"));
        }
        let step3 = self.req(Method::POST, "/api/system/checkin", Some(&step2), None).await?;
        if step3.get("status").is_none() {
            return Err(HemError::new("checkin_error", "HSM checkin step 3 failed (no status field)"));
        }
        Ok(step3)
    }

    // -- Authorisation: password ----------------------------------------------

    /// Authenticate with the local password and get a scoped JWT.
    ///
    /// `password` `None` reuses the key a previous call remembered
    /// (`auth_password_required` if there is none). A token already cached for
    /// the scope and `ctx` is returned without asking the device.
    pub async fn authorize_password(
        &self,
        password: Option<&str>,
        scope: impl Into<Scope>,
        opts: AuthOptions,
    ) -> Result<String> {
        let scope = scope.into();
        scope.check()?;
        check_token_ctx(opts.ctx.as_deref())?;
        if let Some(t) = self.tokens.lock().unwrap().find(&scope, opts.ctx.as_deref(), now_unix()) {
            return Ok(t);
        }

        let challenge: Challenge = serde_json::from_value(self.req(Method::GET, "/api/auth/token", None, None).await?)
            .map_err(|_| HemError::new("bad_response", "auth challenge without eid / spk / jti"))?;

        let keys = match password {
            Some(p) => {
                let p = Zeroizing::new(p.to_owned());
                let eid = challenge.eid.clone();
                let k = Arc::new(
                    tokio::task::spawn_blocking(move || derive_x25519(&p, &eid))
                        .await
                        .map_err(|e| HemError::new("auth_failed", format!("key derivation: {e}")))?,
                );
                if opts.remember {
                    *self.keys.lock().unwrap() = Some(k.clone());
                }
                k
            }
            None => self
                .keys
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| HemError::new("auth_password_required", "Password required (no cached keys)"))?,
        };

        self.authorize_with_keys(&keys, &challenge, &scope, opts.exp_seconds, opts.ctx.as_deref()).await
    }

    /// Sign the device's challenge with `keys` and exchange it for a scoped token.
    async fn authorize_with_keys(
        &self,
        keys: &DerivedKeys,
        challenge: &Challenge,
        scope: &Scope,
        exp_seconds: u32,
        ctx: Option<&str>,
    ) -> Result<String> {
        let payload = EjwtPayload::new(challenge, keys, scope, exp_seconds, ctx, now_unix());
        let ejwt = build_ejwt(keys, &challenge.spk, &payload)?;
        let resp = self.req(Method::POST, "/api/auth/token", Some(&json!({ "auth": ejwt })), None).await?;
        let token = resp
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| HemError::new("auth_failed", "No token in auth response"))?
            .to_owned();
        self.tokens.lock().unwrap().store(scope, &token, ctx, now_unix());
        Ok(token)
    }
}
