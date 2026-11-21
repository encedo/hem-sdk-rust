//! The Rust SDK must build the eJWT byte for byte as hem-sdk-js does.
//! Vectors: tests/vectors/password_v1.json, recorded by tests/vectors/gen.mjs.

use hem_sdk::Scope;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    password: String,
    eid: String,
    spk: String,
    jti: String,
    now: i64,
    scope: Scope,
    exp_seconds: u32,
    ctx: Option<String>,
    iss: String,
    ejwt: String,
}

#[derive(Deserialize)]
struct File {
    cases: Vec<Case>,
}

#[test]
fn password_ejwt_matches_hem_sdk_js() {
    let file: File = serde_json::from_str(include_str!("vectors/password_v1.json")).unwrap();
    assert!(!file.cases.is_empty());
    for c in &file.cases {
        let (iss, ejwt) = hem_sdk::__vectors::password_ejwt(
            &c.password, &c.eid, &c.spk, &c.jti, &c.scope, c.exp_seconds, c.ctx.as_deref(), c.now,
        )
        .unwrap();
        assert_eq!(iss, c.iss, "{}: iss (derived public key)", c.name);
        assert_eq!(ejwt, c.ejwt, "{}: eJWT", c.name);
    }
}
