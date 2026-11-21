//! Tests against a real (or simulated) HEM. Skipped unless HEM_URL is set.
//!
//!   HEM_URL=https://ssh-agent-tester.playground.ence.do cargo test --test live
//!   + HEM_PASSWORD=...   also runs the password authorisation
//!
//! Without the variables every test returns at once, so `cargo test` stays offline.

use hem_sdk::{jwt_parse, AuthOptions, Hem, HemOptions};

fn device() -> Option<Hem> {
    let url = std::env::var("HEM_URL").ok()?;
    Some(Hem::new(&url, HemOptions::default()).unwrap())
}

#[tokio::test]
async fn version_and_status() {
    let Some(hem) = device() else { return };
    let v = hem.get_version(None).await.unwrap();
    assert!(v.get("fwv").and_then(|x| x.as_str()).is_some(), "version: {v}");
    let s = hem.get_status().await.unwrap();
    assert!(s.get("time").is_some(), "status: {s}");
}

#[tokio::test]
async fn password_token() {
    let Some(hem) = device() else { return };
    let Ok(password) = std::env::var("HEM_PASSWORD") else { return };
    let t = hem.authorize_password(Some(&password), "keymgmt:list", AuthOptions::default()).await.unwrap();
    let p = jwt_parse(&t).expect("token is a JWT");
    assert_eq!(p["scope"], "keymgmt:list");
    // The second call for the same scope comes from the cache: same token.
    let t2 = hem.authorize_password(None, "keymgmt:list", AuthOptions::default()).await.unwrap();
    assert_eq!(t, t2);
}
