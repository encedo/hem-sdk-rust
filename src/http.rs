//! The single HTTP entry point, for the device and the broker alike
//! (hem-sdk-js `httpRequest`).
//!
//! Two device facts are built in, both learnt the hard way in hem-sdk-js:
//! - the body is always sent with `Content-Length` (a chunked body gets 411);
//! - no connection pool: the device closes some connections after answering
//!   while still saying keep-alive, and the next request on such a socket fails.

use std::time::Duration;

use reqwest::{header, Client, Method};
use serde_json::Value;

use crate::error::{HemError, Result};

#[derive(Clone, Debug)]
pub(crate) struct Http {
    client: Client,
    tag: &'static str,
}

impl Http {
    pub(crate) fn new(tag: &'static str, timeout: Option<Duration>) -> Result<Self> {
        let mut b = Client::builder().pool_max_idle_per_host(0);
        if let Some(t) = timeout {
            b = b.timeout(t);
        }
        let client = b
            .build()
            .map_err(|e| HemError::new("network", format!("HTTP client: {e}")))?;
        Ok(Self { client, tag })
    }

    /// JSON in, JSON out. A non-JSON answer comes back as `Value::String`.
    /// Non-2xx answers are `HemError` `http_<status>` with the body in `data`.
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<Value> {
        let mut req = self.client.request(method.clone(), url);
        if let Some(b) = body {
            // A byte body, not .json(): reqwest then always sets Content-Length.
            let bytes = serde_json::to_vec(b)
                .map_err(|e| HemError::invalid_arg(format!("request body: {e}")))?;
            req = req.header(header::CONTENT_TYPE, "application/json").body(bytes);
        }
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }

        let res = req.send().await.map_err(|e| {
            if e.is_timeout() {
                HemError::new("timeout", format!("{} {method} {url}: timeout", self.tag))
            } else {
                HemError::new("network", format!("{} {method} {url}: {e}", self.tag))
            }
        })?;

        let status = res.status().as_u16();
        let is_json = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("json"));
        let text = res.text().await.map_err(|e| {
            HemError::new("network", format!("{} {method} {url}: reading body: {e}", self.tag))
        })?;
        let data = if is_json {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        } else {
            Value::String(text)
        };

        if !(200..300).contains(&status) {
            return Err(HemError::http(
                status,
                Some(data),
                format!("{} {method} {url} -> HTTP {status}", self.tag),
            ));
        }
        Ok(data)
    }
}
