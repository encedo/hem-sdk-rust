//! The device (hem-sdk-js `HEM`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Method;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::auth::{
    build_ejwt, check_token_ctx, derive_x25519, jwt_parse, now_unix, Challenge, DerivedKeys, EjwtPayload,
    Scope, TokenCache,
};
use crate::broker::{Broker, DEFAULT_BROKER_URL};
use crate::error::{HemError, Result};
use crate::http::Http;
use crate::limits::{REMOTE_NOTE, TOKEN_CTX};

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

    // -- Authorisation: remote (mobile authenticator via the broker) ------------

    /// Authorise on the paired phone (encedo-authenticator) through the broker
    /// and get a scoped JWT. No local secret: the phone signs.
    ///
    /// Flow (hem-sdk-js `authorizeRemote`):
    /// 1. `GET {broker}/notify/session` - an ephemeral broker key `{ epk }`;
    /// 2. `POST /api/auth/ext/request { epk.., scope, ctx?, note? }` - the device
    ///    seals the request for every paired phone;
    /// 3. `POST {broker}/notify/event/new` - `{ eventid }`, the phone is notified;
    /// 4. poll `{broker}/notify/event/check/{eventid}` (202 pending, 200 done);
    /// 5. `POST /api/auth/ext/token { authreply }` - `{ token }`.
    ///
    /// The token lifetime is the phone's answer. A refusal on the phone is
    /// `denied`; no answer within `poll_timeout` is `timeout`. Running out of
    /// time, an error, or dropping the future withdraws the event, so the phone
    /// stops showing a request nobody waits for. The phone may approve less
    /// than was asked; a token holding a scope that was not asked for is
    /// refused here (`scope_widened`) - the firmware does not compare them.
    /// The device has to be checked in first (`hem_checkin`).
    pub async fn authorize_remote(&self, scope: impl Into<Scope>, opts: RemoteOptions) -> Result<String> {
        let scope = scope.into();
        scope.check()?;
        let ctx = remote_ctx(opts.ctx.as_deref(), opts.require)?;
        if let Some(n) = &opts.note {
            if n.is_empty() || n.len() > REMOTE_NOTE {
                return Err(HemError::invalid_arg(format!(
                    "authorize_remote: note is 1..{REMOTE_NOTE} bytes of UTF-8"
                )));
            }
        }
        if let Some(t) = self.tokens.lock().unwrap().find(&scope, ctx.as_deref(), now_unix()) {
            return Ok(t);
        }

        // Step 1: broker session key
        let mut request = self.broker.session(None).await?;
        let Some(obj) = request.as_object_mut() else {
            return Err(HemError::new("broker_error", "Broker session is not an object"));
        };
        // Step 2: the device seals the scope for every paired phone
        obj.insert("scope".into(), serde_json::to_value(&scope).expect("scope serialises"));
        if let Some(c) = &ctx {
            obj.insert("ctx".into(), Value::String(c.clone()));
        }
        if let Some(n) = &opts.note {
            obj.insert("note".into(), Value::String(n.clone()));
        }
        let challenge = self.req(Method::POST, "/api/auth/ext/request", Some(&request), None).await?;

        // Step 3: publish the challenge -> eventid
        let ev = self.broker.event_new(&challenge).await?;
        let eventid = ev
            .get("eventid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| HemError::new("broker_error", "No eventid from broker"))?
            .to_owned();

        // Step 4: wait for the phone; withdraw the event unless it answered
        let mut pending = PendingEvent { broker: Some(self.broker.clone()), eventid };
        let result = self.broker.wait_event(&pending.eventid, opts.poll_interval, opts.poll_timeout).await?;
        pending.broker = None;

        // Step 5: refused, or exchange the reply for a token
        if result.get("deny").is_some_and(truthy) {
            return Err(HemError::new("denied", "Auth denied by user"));
        }
        let authreply = result
            .get("authreply")
            .filter(|v| truthy(v))
            .ok_or_else(|| HemError::new("broker_error", "Missing authreply"))?;
        let resp = self
            .req(Method::POST, "/api/auth/ext/token", Some(&json!({ "authreply": authreply })), None)
            .await?;
        let token = resp
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| HemError::new("auth_failed", "No token in ext/token response"))?
            .to_owned();

        let granted: Scope = jwt_parse(&token)
            .and_then(|p| p.get("scope").cloned())
            .and_then(|s| serde_json::from_value(s).ok())
            .unwrap_or_else(|| scope.clone());
        let asked = scope.values();
        let extra: Vec<&str> = granted.values().into_iter().filter(|s| !asked.contains(s)).collect();
        if !extra.is_empty() {
            return Err(HemError::new(
                "scope_widened",
                format!("authorize_remote: the token carries scope that was not asked for: {}", extra.join(" ")),
            ));
        }

        self.tokens.lock().unwrap().store(&scope, &token, ctx.as_deref(), now_unix());
        Ok(token)
    }
}

/// What the authenticator app must ask of its user for an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uv {
    /// `uv=bio`: a fingerprint / face at this approval.
    Bio,
    /// `uv=pin`: the app's PIN or biometrics.
    Pin,
}

/// Options for [`Hem::authorize_remote`].
#[derive(Clone, Debug)]
pub struct RemoteOptions {
    /// Copied into the token; with `require` added, 1..64 bytes of UTF-8.
    pub ctx: Option<String>,
    /// Appended to `ctx` as `uv=bio` / `uv=pin`. A request to the app, not a
    /// guarantee: what the app did is in the token's `actx`, signed by the app.
    pub require: Option<Uv>,
    /// 1..128 bytes of UTF-8 shown with the request on the phone.
    pub note: Option<String>,
    pub poll_interval: Duration,
    pub poll_timeout: Duration,
}

impl Default for RemoteOptions {
    fn default() -> Self {
        Self {
            ctx: None,
            require: None,
            note: None,
            poll_interval: Duration::from_secs(2),
            poll_timeout: Duration::from_secs(60),
        }
    }
}

/// hem-sdk-js `remoteCtx`: the caller's `ctx` plus `uv=..`, joined with ';'.
fn remote_ctx(ctx: Option<&str>, require: Option<Uv>) -> Result<Option<String>> {
    let mut parts: Vec<&str> = ctx.into_iter().filter(|c| !c.is_empty()).collect();
    match require {
        Some(Uv::Bio) => parts.push("uv=bio"),
        Some(Uv::Pin) => parts.push("uv=pin"),
        None => {}
    }
    let out = parts.join(";");
    if out.len() > TOKEN_CTX {
        return Err(HemError::invalid_arg(format!(
            "authorize_remote: ctx is at most {TOKEN_CTX} bytes of UTF-8"
        )));
    }
    Ok((!out.is_empty()).then_some(out))
}

/// JavaScript truthiness of a JSON value (`if (result.deny)`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// A broker event still waiting for the phone. Dropped while `broker` is set
/// (an error, a timeout, or the caller dropping the future): withdraw it.
struct PendingEvent {
    broker: Option<Broker>,
    eventid: String,
}

impl Drop for PendingEvent {
    fn drop(&mut self) {
        let Some(broker) = self.broker.take() else { return };
        let eventid = std::mem::take(&mut self.eventid);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = broker.event_delete(&eventid).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_ctx_as_js() {
        assert_eq!(remote_ctx(None, None).unwrap(), None);
        assert_eq!(remote_ctx(Some("app"), None).unwrap().as_deref(), Some("app"));
        assert_eq!(remote_ctx(None, Some(Uv::Bio)).unwrap().as_deref(), Some("uv=bio"));
        assert_eq!(remote_ctx(Some("app"), Some(Uv::Pin)).unwrap().as_deref(), Some("app;uv=pin"));
        assert_eq!(remote_ctx(Some(&"x".repeat(64)), Some(Uv::Bio)).unwrap_err().code, "invalid_arg");
    }

    #[test]
    fn truthy_as_js() {
        assert!(!truthy(&Value::Null) && !truthy(&json!(false)) && !truthy(&json!("")) && !truthy(&json!(0)));
        assert!(truthy(&json!(true)) && truthy(&json!("x")) && truthy(&json!(1)) && truthy(&json!({})));
    }

    #[tokio::test]
    async fn remote_checks_before_sending() {
        let hem = Hem::new("http://127.0.0.1:9", HemOptions::default()).unwrap();
        let long = RemoteOptions { note: Some("n".repeat(129)), ..Default::default() };
        assert_eq!(hem.authorize_remote("keymgmt:list", long).await.unwrap_err().code, "invalid_arg");
        let empty = RemoteOptions { note: Some(String::new()), ..Default::default() };
        assert_eq!(hem.authorize_remote("keymgmt:list", empty).await.unwrap_err().code, "invalid_arg");
    }
}
