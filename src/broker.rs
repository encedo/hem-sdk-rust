//! The Encedo backend (api.encedo.com). Every call to it lives here, one method
//! per endpoint (hem-sdk-js `Broker`). A device behind an air gap never needs it.

use std::time::Duration;

use reqwest::Method;
use serde_json::{json, Value};

use crate::error::{HemError, Result};
use crate::http::Http;

pub const DEFAULT_BROKER_URL: &str = "https://api.encedo.com";

#[derive(Clone, Debug)]
pub struct Broker {
    url: String,
    http: Http,
}

impl Broker {
    pub fn new(url: &str, timeout: Option<Duration>) -> Result<Self> {
        Ok(Self { url: url.trim_end_matches('/').to_owned(), http: Http::new("Broker", timeout)? })
    }

    /// Broker base URL, without a trailing slash.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Step 2 of the check-in: the broker counter-signs the device's challenge.
    pub async fn checkin(&self, check: &Value) -> Result<Value> {
        self.http.request(Method::POST, &format!("{}/checkin", self.url), Some(check), None).await
    }

    // -- Sessions --------------------------------------------------------------

    /// Open a broker session.
    ///
    /// With `eid` (the device id from its config or auth challenge) the session
    /// belongs to that device and the answer also says whether it has a paired
    /// authenticator: `{ epk, paired }`. Without it the session is an ephemeral
    /// key for one remote authorisation: `{ epk, ... }`, passed whole to
    /// `/api/auth/ext/request`.
    pub async fn session(&self, eid: Option<&str>) -> Result<Value> {
        let url = format!("{}/notify/session", self.url);
        match eid {
            Some(e) => self.http.request(Method::POST, &url, Some(&json!({ "eid": e })), None).await,
            None => self.http.request(Method::GET, &url, None, None).await,
        }
    }

    // -- Remote authorisation events -------------------------------------------

    /// Publish a device challenge as a push event: `{ eventid }`.
    pub async fn event_new(&self, challenge: &Value) -> Result<Value> {
        self.http.request(Method::POST, &format!("{}/notify/event/new", self.url), Some(challenge), None).await
    }

    /// One poll. `None` while the phone has not answered yet (HTTP 202).
    pub async fn event_check(&self, eventid: &str) -> Result<Option<Value>> {
        let (status, data) = self
            .http
            .request_status(Method::GET, &format!("{}/notify/event/check/{eventid}", self.url), None, None)
            .await?;
        Ok((status != 202).then_some(data))
    }

    /// Withdraw a pending event, so the phone stops showing it.
    pub async fn event_delete(&self, eventid: &str) -> Result<Value> {
        self.http.request(Method::DELETE, &format!("{}/notify/event/{eventid}", self.url), None, None).await
    }

    /// Poll an event until the phone answers or `timeout` passes: the broker's
    /// answer (`{ authreply }` or `{ deny }`), or `HemError` `timeout`. The
    /// event is left as it is; `Hem::authorize_remote` withdraws it.
    pub async fn wait_event(&self, eventid: &str, interval: Duration, timeout: Duration) -> Result<Value> {
        poll(|| self.event_check(eventid), interval, timeout, "Remote auth timed out").await
    }
}

/// hem-sdk-js `Broker.#poll`: wait, poll, until a result or the deadline.
async fn poll<F, Fut>(mut step: F, interval: Duration, timeout: Duration, timeout_message: &str) -> Result<Value>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<Value>>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(interval).await;
        if let Some(v) = step().await? {
            return Ok(v);
        }
    }
    Err(HemError::new("timeout", timeout_message))
}
