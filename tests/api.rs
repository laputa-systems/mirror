use std::collections::HashMap;
use std::sync::RwLock;

use laputa_mirror::{AppState, db, packages, s3};

const TEST_USER: &str = "testuser";
const TEST_TOKEN: &str = "aaaaaabbbbbbccccccddddddeeeeeeffffffffaaaaaaabbbbbbccccccddddddee";

fn make_state() -> AppState {
    let db = laputa_mirror::db::Db::open(":memory:").expect("db");
    db.create_user("test-user-id", TEST_USER)
        .expect("create user");
    db.seed_token("test-user-id", "test", TEST_TOKEN)
        .expect("seed token");

    AppState {
        s3: s3::Storage::memory(),
        db: std::sync::Mutex::new(db),
        webauthn: webauthn_minimal::RelyingParty::new(
            "test.example.com",
            "https://test.example.com",
            "Test",
        ),
        jwks: None,
        allowed_users: vec![TEST_USER.to_string()],
        index: RwLock::new(Vec::new()),
        upload_dir: unique_upload_dir(),
        index_lock: std::sync::Mutex::new(()),
        secure_cookies: false,
        r2_public_url: None,
    }
}

fn unique_upload_dir() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "laputa-mirror-test-uploads-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    path
}

fn make_browser_session(state: &AppState) -> String {
    let session = state
        .db
        .lock()
        .unwrap()
        .create_browser_session("test-user-id")
        .expect("browser session");
    format!("laputa_mirror_session={session}")
}

fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn auth_headers() -> HashMap<String, String> {
    headers(&[("authorization", &format!("Bearer {TEST_TOKEN}"))])
}

fn body_json(resp: &packages::Response) -> serde_json::Value {
    serde_json::from_slice(&resp.body).unwrap()
}

fn sample_index() -> Vec<packages::RemotePackage> {
    vec![packages::RemotePackage {
        arch: "aarch64".to_string(),
        name: "zlib".to_string(),
        ver: "1.3.2".to_string(),
        rel: "5".to_string(),
        deps: vec!["musl".to_string()],
        mkdeps_host: vec!["cmake".to_string()],
        mkdeps_target: vec!["llvm-toolchain".to_string()],
        sha256: db::sha256_hex(b"package"),
        size: 7,
        tarball: "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz".to_string(),
        metadata: String::new(),
        source_sha256: db::sha256_hex(b"source"),
        metapackage: false,
    }]
}

fn put_index(state: &AppState, index: &[packages::RemotePackage]) -> packages::Response {
    let body = serde_json::to_vec(index).unwrap();
    packages::route("PUT", "/index.json", &auth_headers(), &body, state)
}

#[test]
fn health_returns_ok() {
    let state = make_state();
    let resp = packages::route("GET", "/health", &headers(&[]), b"", &state);
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["status"], "ok");
}

#[test]
fn public_reads_return_index_and_objects() {
    let state = make_state();
    state
        .s3
        .put(
            "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
            b"package".to_vec(),
            "application/octet-stream",
        )
        .unwrap();
    state
        .s3
        .put(
            "sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2",
            b"source".to_vec(),
            "application/octet-stream",
        )
        .unwrap();
    state
        .s3
        .put(
            "metadata/aarch64/zlib/zlib-1.3.2-5.json",
            br#"{"metadata_sha256":"abc"}"#.to_vec(),
            "application/json",
        )
        .unwrap();
    assert_eq!(put_index(&state, &sample_index()).status, 201);

    let resp = packages::route("GET", "/index.json", &headers(&[]), b"", &state);
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.extra_headers,
        vec![("Cache-Control", "no-store".to_string())]
    );
    let idx = body_json(&resp);
    assert_eq!(idx[0]["name"], "zlib");
    assert_eq!(idx[0]["mkdeps_target"], serde_json::json!(["llvm-toolchain"]));

    let resp = packages::route(
        "GET",
        "/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
        &headers(&[]),
        b"",
        &state,
    );
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"package");

    let resp = packages::route(
        "GET",
        "/sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2",
        &headers(&[]),
        b"",
        &state,
    );
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"source");

    let resp = packages::route(
        "GET",
        "/metadata/aarch64/zlib/zlib-1.3.2-5.json",
        &headers(&[]),
        b"",
        &state,
    );
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/json");
    assert_eq!(resp.body, br#"{"metadata_sha256":"abc"}"#);
}

#[test]
fn authenticated_puts_store_objects_and_index() {
    let state = make_state();
    let resp = packages::route(
        "PUT",
        "/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
        &auth_headers(),
        b"package",
        &state,
    );
    assert_eq!(resp.status, 201);
    assert_eq!(
        state
            .s3
            .get("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz")
            .unwrap(),
        b"package"
    );

    let resp = packages::route(
        "PUT",
        "/sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2",
        &auth_headers(),
        b"source",
        &state,
    );
    assert_eq!(resp.status, 201);

    let resp = packages::route(
        "PUT",
        "/metadata/aarch64/zlib/zlib-1.3.2-5.json",
        &auth_headers(),
        br#"{"metadata_sha256":"abc"}"#,
        &state,
    );
    assert_eq!(resp.status, 201);
    assert_eq!(
        state
            .s3
            .get("metadata/aarch64/zlib/zlib-1.3.2-5.json")
            .unwrap(),
        br#"{"metadata_sha256":"abc"}"#
    );

    let resp = put_index(&state, &sample_index());
    assert_eq!(resp.status, 201);
    assert_eq!(
        state.index.read().unwrap()[0].source_sha256,
        db::sha256_hex(b"source")
    );
}

#[test]
fn chunked_uploads_are_assembled_by_the_mirror() {
    let state = make_state();
    let upload_id = "test-upload";

    let resp = packages::route(
        "PUT",
        "/_uploads/test-upload/0",
        &auth_headers(),
        b"hello ",
        &state,
    );
    assert_eq!(resp.status, 201);

    let resp = packages::route(
        "PUT",
        "/_uploads/test-upload/1",
        &auth_headers(),
        b"world",
        &state,
    );
    assert_eq!(resp.status, 201);

    let body = br#"{"rel":"sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2","chunks":2}"#;
    let resp = packages::route(
        "POST",
        "/_uploads/test-upload/complete",
        &auth_headers(),
        body,
        &state,
    );
    assert_eq!(resp.status, 201);
    assert_eq!(
        state.s3.get("sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2"),
        Some(b"hello world".to_vec())
    );
    assert!(!state.upload_dir.join(upload_id).exists());
}

#[test]
fn writes_require_bearer_auth() {
    let state = make_state();
    let resp = packages::route(
        "PUT",
        "/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
        &headers(&[]),
        b"package",
        &state,
    );
    assert_eq!(resp.status, 401);

    let resp = packages::route("PUT", "/index.json", &headers(&[]), b"[]", &state);
    assert_eq!(resp.status, 401);

    let resp = packages::route(
        "PUT",
        "/index.json",
        &headers(&[("authorization", "Bearer wrong")]),
        b"[]",
        &state,
    );
    assert_eq!(resp.status, 401);
}

#[test]
fn path_traversal_is_rejected() {
    let state = make_state();
    for path in [
        "/packages/zlib/../../../etc/passwd",
        "/packages/../zlib/zlib-1.3.2-5.tar.gz",
        "/sources/zlib/zlib-1.3.2-5.tar.bz2",
    ] {
        let resp = packages::route("GET", path, &headers(&[]), b"", &state);
        assert_eq!(resp.status, 404, "GET {path}");
        let resp = packages::route("PUT", path, &auth_headers(), b"data", &state);
        assert_eq!(resp.status, 404, "PUT {path}");
    }
}

#[test]
fn r2_redirects_use_flat_object_paths() {
    let mut state = make_state();
    state.r2_public_url = Some("https://pub.example".to_string());

    let resp = packages::route(
        "GET",
        "/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
        &headers(&[]),
        b"",
        &state,
    );
    assert_eq!(resp.status, 302);
    let loc = resp
        .extra_headers
        .iter()
        .find(|(k, _)| *k == "Location")
        .map(|(_, v)| v.as_str());
    assert_eq!(
        loc,
        Some("https://pub.example/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz")
    );
}

#[test]
fn index_persists_to_storage_and_reloads() {
    let state = make_state();
    assert_eq!(put_index(&state, &sample_index()).status, 201);

    let loaded = packages::load_index(&state.s3).unwrap();
    assert_eq!(loaded[0].name, "zlib");
    assert_eq!(
        loaded[0].tarball,
        "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz"
    );
}

#[test]
fn invalid_index_is_rejected() {
    let state = make_state();
    let mut index = sample_index();
    index[0].tarball = "../zlib.tar.gz".to_string();
    let resp = put_index(&state, &index);
    assert_eq!(resp.status, 400);
}

#[test]
fn settings_page_requires_browser_session() {
    let state = make_state();
    let resp = packages::route("GET", "/auth/settings", &headers(&[]), b"", &state);
    assert_eq!(resp.status, 302);

    let cookie = make_browser_session(&state);
    let resp = packages::route(
        "GET",
        "/auth/settings",
        &headers(&[("cookie", &cookie)]),
        b"",
        &state,
    );
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains(TEST_USER));
}

#[test]
fn create_token_returns_usable_api_token() {
    let state = make_state();
    let cookie = make_browser_session(&state);
    let resp = packages::route(
        "POST",
        "/auth/tokens",
        &headers(&[("cookie", &cookie)]),
        br#"{"name":"ci","expires_days":7}"#,
        &state,
    );
    assert_eq!(resp.status, 200);
    let token = body_json(&resp)["token"].as_str().unwrap().to_string();
    let resp = packages::route(
        "PUT",
        "/index.json",
        &headers(&[("authorization", &format!("Bearer {token}"))]),
        serde_json::to_vec(&sample_index()).unwrap().as_slice(),
        &state,
    );
    assert_eq!(resp.status, 201);
}
