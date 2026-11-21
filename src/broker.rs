//! The Encedo backend (api.encedo.com). Every call to it lives here, one method
//! per endpoint (hem-sdk-js `Broker`). A device behind an air gap never needs it.

use std::time::Duration;

use reqwest::Method;
use serde_json::Value;

use crate::error::Result;
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
}
