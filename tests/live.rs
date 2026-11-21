//! Tests against a real (or simulated) HEM. Skipped unless HEM_URL is set.
//!
//!   HEM_URL=https://ssh-agent-tester.playground.ence.do cargo test --test live
//!   + HEM_PASSWORD=...   also runs the password authorisation
//!
//! Without the variables every test returns at once, so `cargo test` stays offline.

use hem_sdk::{
    jwt_parse, AuthOptions, CreateOptions, Hem, HemOptions, RemoteOptions, SearchOptions, SignOptions, Uv,
    VerifyOptions,
};

/// Description of the one test key; found again on every run, created only once.
const TEST_DESCR: &[u8] = b"hem-sdk-rust-test";

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

/// Needs a paired encedo-authenticator and a person to approve on the phone:
/// HEM_REMOTE=1 cargo test --test live remote -- --nocapture
#[tokio::test]
async fn remote_token() {
    let Some(hem) = device() else { return };
    if std::env::var("HEM_REMOTE").is_err() {
        return;
    }
    hem.hem_checkin().await.unwrap();
    let opts = RemoteOptions {
        require: Some(Uv::Bio),
        note: Some("hem-sdk-rust live test: approve".into()),
        ..Default::default()
    };
    eprintln!("approve the request on the phone (60 s)");
    let t = hem.authorize_remote("keymgmt:list", opts.clone()).await.unwrap();
    let p = jwt_parse(&t).expect("token is a JWT");
    assert_eq!(p["scope"], "keymgmt:list");
    eprintln!("token payload: {p}");
    // The token works, and the second call comes from the cache.
    assert!(hem.list_keys(&t, Default::default()).await.is_ok());
    assert_eq!(hem.authorize_remote("keymgmt:list", opts).await.unwrap(), t);
}

#[tokio::test]
async fn ed25519_sign_and_verify() {
    let Some(hem) = device() else { return };
    let Ok(password) = std::env::var("HEM_PASSWORD") else { return };

    // Find the test key by its description, create it on the first run only.
    let tok = hem
        .authorize_password(Some(&password), ["keymgmt:search", "keymgmt:gen"], AuthOptions::default())
        .await
        .unwrap();
    let search = SearchOptions { key_type: Some("ED25519".into()), ..Default::default() };
    let found = hem.search_keys_all(Some(&tok), TEST_DESCR, search).await.unwrap();
    let key = match found.into_iter().next() {
        Some(k) => k,
        None => {
            let opts = CreateOptions { descr: Some(TEST_DESCR.to_vec()), ..Default::default() };
            hem.create_key_pair(&tok, "hem-sdk-rust live test", "ED25519", opts).await.unwrap()
        }
    };
    assert_eq!(key.key_type, "ED25519");

    let use_tok = hem
        .authorize_password(None, format!("keymgmt:use:{}", key.kid), AuthOptions::default())
        .await
        .unwrap();
    let info = hem.get_key_public_info(&use_tok, &key.kid).await.unwrap();
    assert_eq!(info.key_type, "ED25519");
    assert_eq!(info.description.as_deref(), Some(TEST_DESCR));
    let pubkey: [u8; 32] = info.pubkey.expect("public key").try_into().expect("32 bytes");

    let msg = [0x5au8; 100];
    let sig = hem.exdsa_sign(&use_tok, &key.kid, &msg, SignOptions::default()).await.unwrap();
    assert_eq!(sig.len(), 64);

    // The device agrees, and refuses a corrupted signature.
    assert!(hem.exdsa_verify(&use_tok, &key.kid, &msg, &sig, VerifyOptions::default()).await.unwrap());
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(!hem.exdsa_verify(&use_tok, &key.kid, &msg, &bad, VerifyOptions::default()).await.unwrap());

    // Independent check, as an SSH server would do it.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).unwrap();
    let s = ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap());
    vk.verify_strict(&msg, &s).expect("signature verifies with ed25519-dalek");
}
