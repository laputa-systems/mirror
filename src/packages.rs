use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth;
use crate::s3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePackage {
    #[serde(default = "default_arch")]
    pub arch: String,
    pub name: String,
    pub ver: String,
    pub rel: String,
    pub deps: Vec<String>,
    pub mkdeps_host: Vec<String>,
    pub mkdeps_target: Vec<String>,
    pub sha256: String,
    pub size: u64,
    pub tarball: String,
    #[serde(default)]
    pub metadata: String,
    pub source_sha256: String,
    pub metapackage: bool,
}

fn default_arch() -> String {
    "aarch64".to_string()
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(&'static str, String)>,
}

impl Response {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.as_bytes().to_vec(),
            extra_headers: vec![],
        }
    }

    pub fn json_bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body,
            extra_headers: vec![],
        }
    }

    pub fn html(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body,
            extra_headers: vec![],
        }
    }

    pub fn octet(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "application/octet-stream",
            body,
            extra_headers: vec![],
        }
    }

    pub fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            content_type: "text/plain",
            body: vec![],
            extra_headers: vec![("Location", location.to_string())],
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain",
            body: b"Not Found".to_vec(),
            extra_headers: vec![],
        }
    }

    pub fn unauthorized() -> Self {
        Self::json(401, r#"{"error":"unauthorized"}"#)
    }

    pub fn bad_request(msg: &str) -> Self {
        Self::json(400, &format!(r#"{{"error":"{}"}}"#, json_escape(msg)))
    }

    pub fn error(msg: &str) -> Self {
        Self::json(500, &format!(r#"{{"error":"{}"}}"#, json_escape(msg)))
    }

    pub fn with_set_cookie(mut self, value: String) -> Self {
        self.extra_headers.push(("Set-Cookie", value));
        self
    }
}

pub fn load_index(s3: &s3::Storage) -> Option<Vec<RemotePackage>> {
    let bytes = s3.get("index.json")?;
    serde_json::from_slice(&bytes).ok()
}

pub fn route(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    state: &AppState,
) -> Response {
    if method == "GET"
        && (path.starts_with("/static/") || path.ends_with(".js") || path.ends_with(".css"))
    {
        let static_path = if path.starts_with("/static/") {
            path.strip_prefix("/static/").unwrap().to_string()
        } else {
            format!("js{}", path.strip_prefix('/').unwrap())
        };
        let full_path = format!("static/{static_path}");
        if let Ok(bytes) = std::fs::read(&full_path) {
            let content_type = if full_path.ends_with(".js") {
                "application/javascript"
            } else if full_path.ends_with(".css") {
                "text/css"
            } else {
                "application/octet-stream"
            };
            return Response {
                status: 200,
                content_type,
                body: bytes,
                extra_headers: vec![],
            };
        }
    }

    match method {
        "GET" => get(path, headers, state),
        "PUT" => put(path, headers, body, state),
        "POST" => match path {
            "/auth/register/options" => crate::webauthn_handlers::register_options(body, state),
            "/auth/register/verify" => crate::webauthn_handlers::register_verify(body, state),
            "/auth/authenticate/options" => crate::webauthn_handlers::authenticate_options(state),
            "/auth/authenticate/verify" => {
                crate::webauthn_handlers::authenticate_verify(body, state)
            }
            "/auth/tokens" => crate::webauthn_handlers::create_token_api(body, headers, state),
            "/auth/tokens/delete" => {
                crate::webauthn_handlers::delete_token_api(body, headers, state)
            }
            path if path.starts_with("/_uploads/") && path.ends_with("/complete") => {
                complete_chunked_upload(path, headers, body, state)
            }
            _ => Response::not_found(),
        },
        _ => Response::not_found(),
    }
}

pub(crate) fn session_cookie(headers: &HashMap<String, String>) -> Option<String> {
    headers.get("cookie").and_then(|h| {
        h.split(';').find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            if k.trim() == "laputa_mirror_session" {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
    })
}

fn get(path: &str, headers: &HashMap<String, String>, state: &AppState) -> Response {
    if path == "/" {
        return root_index(headers, state);
    }
    if path == "/health" {
        return Response::json(200, r#"{"status":"ok"}"#);
    }
    if path == "/index.json" {
        return get_index(state);
    }
    if path == "/auth" || path.starts_with("/auth?") {
        return crate::webauthn_handlers::auth_page();
    }
    if path.starts_with("/auth/poll") {
        let query = path.find('?').map(|i| &path[i + 1..]).unwrap_or("");
        return crate::webauthn_handlers::poll_session(query, state);
    }
    if path == "/auth/logout" {
        return crate::webauthn_handlers::logout(headers, state);
    }
    if path == "/auth/settings" {
        return crate::webauthn_handlers::settings_page(headers, state);
    }
    if let Some(key) = package_key(path) {
        return get_object(&key, state);
    }
    if let Some(key) = source_key(path) {
        return get_object(&key, state);
    }
    if let Some(key) = metadata_key(path) {
        return get_object(&key, state);
    }
    Response::not_found()
}

fn put(path: &str, headers: &HashMap<String, String>, body: &[u8], state: &AppState) -> Response {
    if !auth::authenticated(headers, state) {
        return Response::unauthorized();
    }

    if path == "/index.json" {
        return put_index(body, state);
    }

    if path.starts_with("/_uploads/") {
        return put_upload_chunk(path, body, state);
    }

    let Some(key) = package_key(path)
        .or_else(|| source_key(path))
        .or_else(|| metadata_key(path))
    else {
        return Response::not_found();
    };

    match state.s3.put(&key, body.to_vec(), content_type_for(&key)) {
        Ok(()) => Response::json(201, r#"{"ok":true}"#),
        Err(e) => {
            tracing::error!("object upload failed for {key}: {e}");
            Response::error("upload failed")
        }
    }
}

fn put_upload_chunk(path: &str, body: &[u8], state: &AppState) -> Response {
    let Some((upload_id, chunk_index)) = parse_chunk_path(path) else {
        return Response::not_found();
    };
    let dir = state.upload_dir.join(upload_id);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!("chunk upload mkdir failed: {e}");
        return Response::error("chunk upload failed");
    }
    let chunk = dir.join(format!("{chunk_index:08}"));
    match std::fs::write(&chunk, body) {
        Ok(()) => Response::json(201, r#"{"ok":true}"#),
        Err(e) => {
            tracing::error!("chunk upload write failed: {e}");
            Response::error("chunk upload failed")
        }
    }
}

fn complete_chunked_upload(
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    state: &AppState,
) -> Response {
    if !auth::authenticated(headers, state) {
        return Response::unauthorized();
    }

    let Some(upload_id) = path
        .strip_prefix("/_uploads/")
        .and_then(|p| p.strip_suffix("/complete"))
        .filter(|id| valid_upload_id(id))
    else {
        return Response::not_found();
    };

    #[derive(Deserialize)]
    struct CompleteRequest {
        rel: String,
        chunks: usize,
    }

    let req: CompleteRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => return Response::bad_request("invalid upload completion json"),
    };
    if req.chunks == 0 {
        return Response::bad_request("chunk count must be positive");
    }

    let rel_path = format!("/{}", req.rel);
    let Some(key) = package_key(&rel_path)
        .or_else(|| source_key(&rel_path))
        .or_else(|| metadata_key(&rel_path))
    else {
        return Response::bad_request("invalid upload path");
    };

    let dir = state.upload_dir.join(upload_id);
    let assembled = dir.join("assembled-object");
    let out = match File::create(&assembled) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!("chunk assembly create failed: {e}");
            return Response::error("chunk assembly failed");
        }
    };
    let mut out = BufWriter::new(out);
    for index in 0..req.chunks {
        let chunk = dir.join(format!("{index:08}"));
        let chunk_file = match File::open(&chunk) {
            Ok(file) => file,
            Err(_) => return Response::bad_request("missing upload chunk"),
        };
        let mut chunk_file = BufReader::new(chunk_file);
        if let Err(e) = std::io::copy(&mut chunk_file, &mut out) {
            tracing::error!("chunk assembly copy failed: {e}");
            return Response::error("chunk assembly failed");
        }
    }
    if let Err(e) = out.flush() {
        tracing::error!("chunk assembly flush failed: {e}");
        return Response::error("chunk assembly failed");
    }
    drop(out);

    match state.s3.put_file(&key, &assembled, content_type_for(&key)) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&dir);
            Response::json(201, r#"{"ok":true}"#)
        }
        Err(e) => {
            tracing::error!("chunked object upload failed for {key}: {e}");
            Response::error("chunked upload failed")
        }
    }
}

fn parse_chunk_path(path: &str) -> Option<(&str, usize)> {
    let rest = path.strip_prefix("/_uploads/")?;
    let (upload_id, chunk_text) = rest.split_once('/')?;
    if !valid_upload_id(upload_id) || chunk_text.contains('/') {
        return None;
    }
    let chunk_index = chunk_text.parse().ok()?;
    Some((upload_id, chunk_index))
}

fn valid_upload_id(upload_id: &str) -> bool {
    !upload_id.is_empty()
        && upload_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn get_index(state: &AppState) -> Response {
    let index = state.index.read().unwrap();
    let json = serde_json::to_vec_pretty(&*index).unwrap_or_else(|_| b"[]".to_vec());
    let mut response = Response::json_bytes(200, json);
    response
        .extra_headers
        .push(("Cache-Control", "no-store".to_string()));
    response
}

fn put_index(body: &[u8], state: &AppState) -> Response {
    let mut index: Vec<RemotePackage> = match serde_json::from_slice(body) {
        Ok(index) => index,
        Err(_) => return Response::bad_request("invalid index json"),
    };

    if let Err(msg) = validate_index(&index) {
        return Response::bad_request(&msg);
    }

    index.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.arch.cmp(&b.arch)));
    let bytes = match serde_json::to_vec_pretty(&index) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("index encode failed: {e}");
            return Response::error("index encode failed");
        }
    };

    let _index_guard = state.index_lock.lock().unwrap();
    if let Err(e) = state.s3.put("index.json", bytes, "application/json") {
        tracing::error!("index upload failed: {e}");
        return Response::error("index upload failed");
    }
    *state.index.write().unwrap() = index;
    Response::json(201, r#"{"ok":true}"#)
}

fn get_object(key: &str, state: &AppState) -> Response {
    if let Some(base) = &state.r2_public_url {
        return Response::redirect(&format!("{base}/{key}"));
    }
    if let Some(url) = state.s3.presign_get(key, 300) {
        return Response::redirect(&url);
    }
    match state.s3.get(key) {
        Some(bytes) => Response {
            status: 200,
            content_type: content_type_for(key),
            body: bytes,
            extra_headers: vec![],
        },
        None => Response::not_found(),
    }
}

fn root_index(headers: &HashMap<String, String>, state: &AppState) -> Response {
    let username = session_cookie(headers).and_then(|t| {
        state
            .db
            .lock()
            .unwrap()
            .verify_browser_session(&t)
            .ok()
            .flatten()
    });

    let userbar = match &username {
        Some(name) => format!(
            "<span class=userbar>{} <a href=\"/auth/settings\">(settings)</a> &middot; <a href=\"/auth/logout\">sign out</a></span>",
            html_escape(name),
        ),
        None => "<a href=\"/auth\" class=signin>sign in</a>".to_string(),
    };

    let mut packages = state.index.read().unwrap().clone();
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let mut html = format!(
        "<!doctype html>\
        <html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
        <title>Laputa Packages</title><link rel=\"stylesheet\" href=\"/static/css/index.css\">\
        </head><body>\
        <header><h1>Laputa Packages</h1>{userbar}</header>",
    );

    if packages.is_empty() {
        html.push_str("<p class=empty>No packages indexed yet.</p>");
    } else {
        html.push_str(&format!(
            "<p class=count>{} packages</p>\
            <table><tr><th>Package</th><th>Arch</th><th>Binary</th><th>Source</th><th>Dependencies</th><th>Host build deps</th><th>Target build deps</th></tr>",
            packages.len()
        ));

        for pkg in &packages {
            let binary = if pkg.metapackage || pkg.tarball.is_empty() {
                "<span class=dep>metapackage</span>".to_string()
            } else {
                format!(
                    "<a href=\"/{}\">{}-{}</a> <span class=dep>{}</span>",
                    html_attr(&pkg.tarball),
                    html_escape(&pkg.ver),
                    html_escape(&pkg.rel),
                    fmt_size(pkg.size),
                )
            };
            let source = if pkg.source_sha256.is_empty() {
                "<span class=dep>-</span>".to_string()
            } else {
                format!(
                    "<a href=\"/{}\">download</a>",
                    html_attr(&source_rel(pkg))
                )
            };
            html.push_str(&format!(
                "<tr><td><strong>{}</strong></td><td><span class=dep>{}</span></td><td>{binary}</td><td>{source}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&pkg.name),
                html_escape(&pkg.arch),
                deps_html(&pkg.deps),
                deps_html(&pkg.mkdeps_host),
                deps_html(&pkg.mkdeps_target),
            ));
        }

        html.push_str("</table>");
    }

    html.push_str("</body></html>");
    Response::html(html.into_bytes())
}

fn deps_html(deps: &[String]) -> String {
    if deps.is_empty() {
        return "<span class=dep>-</span>".to_string();
    }
    format!(
        "<span class=dep>{}</span>",
        deps.iter()
            .map(|d| html_escape(d))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn source_rel(pkg: &RemotePackage) -> String {
    format!(
        "sources/{}/{}-{}-{}-{}-src.tar.bz2",
        pkg.name, pkg.name, pkg.ver, pkg.rel, pkg.arch
    )
}

fn package_key(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() == 4 && parts[0] == "packages" {
        return validate_package_object_path(parts[1], parts[2], parts[3]);
    }
    if parts.len() == 3 && parts[0] == "packages" {
        return validate_object_path(parts[0], parts[1], parts[2], false);
    }
    None
}

fn source_key(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() != 3 || parts[0] != "sources" {
        return None;
    }
    validate_object_path(parts[0], parts[1], parts[2], true)
}

fn metadata_key(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() != 4 || parts[0] != "metadata" {
        return None;
    }
    validate_metadata_object_path(parts[1], parts[2], parts[3])
}

fn validate_object_path(prefix: &str, name: &str, file: &str, source: bool) -> Option<String> {
    if !valid_pkg_name(name) || !file.ends_with(if source { ".tar.bz2" } else { ".tar.gz" }) {
        return None;
    }
    if name.contains("..") || file.contains("..") || file.contains('/') || file.is_empty() {
        return None;
    }
    if !file.starts_with(&format!("{name}-")) {
        return None;
    }
    if source && !file.ends_with("-src.tar.bz2") {
        return None;
    }
    if source && !file.ends_with("-aarch64-src.tar.bz2") && !file.ends_with("-x86_64-src.tar.bz2") {
        return None;
    }
    Some(format!("{prefix}/{name}/{file}"))
}

fn validate_package_object_path(arch: &str, name: &str, file: &str) -> Option<String> {
    if !valid_arch(arch) || !valid_pkg_name(name) || !file.ends_with(".tar.gz") {
        return None;
    }
    if name.contains("..") || file.contains("..") || file.contains('/') || file.is_empty() {
        return None;
    }
    if !file.starts_with(&format!("{name}-")) {
        return None;
    }
    Some(format!("packages/{arch}/{name}/{file}"))
}

fn validate_metadata_object_path(arch: &str, name: &str, file: &str) -> Option<String> {
    if !valid_arch(arch) || !valid_pkg_name(name) || !file.ends_with(".json") {
        return None;
    }
    if name.contains("..") || file.contains("..") || file.contains('/') || file.is_empty() {
        return None;
    }
    if !file.starts_with(&format!("{name}-")) {
        return None;
    }
    Some(format!("metadata/{arch}/{name}/{file}"))
}

fn valid_arch(arch: &str) -> bool {
    matches!(arch, "aarch64" | "x86_64")
}

fn validate_index(index: &[RemotePackage]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for pkg in index {
        if !valid_arch(&pkg.arch) {
            return Err(format!("invalid arch for {}: {}", pkg.name, pkg.arch));
        }
        if !valid_pkg_name(&pkg.name) {
            return Err(format!("invalid package name: {}", pkg.name));
        }
        if !seen.insert(format!("{}/{}", pkg.arch, pkg.name)) {
            return Err(format!("duplicate package: {}/{}", pkg.arch, pkg.name));
        }
        if !pkg.sha256.is_empty() && !valid_sha256(&pkg.sha256) {
            return Err(format!("invalid sha256 for {}", pkg.name));
        }
        if !pkg.source_sha256.is_empty() && !valid_sha256(&pkg.source_sha256) {
            return Err(format!("invalid source sha256 for {}", pkg.name));
        }
        if pkg.metapackage {
            if !pkg.tarball.is_empty() || pkg.size != 0 || !pkg.sha256.is_empty() {
                return Err(format!("invalid metapackage fields for {}", pkg.name));
            }
        } else if package_key(&format!("/{}", pkg.tarball)).is_none() {
            return Err(format!("invalid tarball path for {}", pkg.name));
        } else if !tarball_matches_entry(pkg) {
            return Err(format!(
                "tarball path does not match package arch/name for {}",
                pkg.name
            ));
        }
        if !pkg.metadata.is_empty() {
            if metadata_key(&format!("/{}", pkg.metadata)).is_none() {
                return Err(format!("invalid metadata path for {}", pkg.name));
            }
            if !metadata_matches_entry(pkg) {
                return Err(format!(
                    "metadata path does not match package arch/name for {}",
                    pkg.name
                ));
            }
        }
    }
    Ok(())
}

fn tarball_matches_entry(pkg: &RemotePackage) -> bool {
    let parts: Vec<&str> = pkg.tarball.split('/').collect();
    if parts.len() == 4 {
        return parts[0] == "packages" && parts[1] == pkg.arch && parts[2] == pkg.name;
    }
    parts.len() == 3 && parts[0] == "packages" && pkg.arch == "aarch64" && parts[1] == pkg.name
}

fn metadata_matches_entry(pkg: &RemotePackage) -> bool {
    let parts: Vec<&str> = pkg.metadata.split('/').collect();
    parts.len() == 4 && parts[0] == "metadata" && parts[1] == pkg.arch && parts[2] == pkg.name
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_pkg_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
        })
        && name.as_bytes()[0].is_ascii_alphanumeric()
}

fn content_type_for(key: &str) -> &'static str {
    if key == "index.json" || key.starts_with("metadata/") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{} KB", bytes / 1024)
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html_attr(value: &str) -> String {
    html_escape(value)
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_are_flat_pm_paths() {
        assert_eq!(
            package_key("/packages/aarch64/zlib/zlib-1.3.2-5.tar.gz").as_deref(),
            Some("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz")
        );
        assert_eq!(
            package_key("/packages/zlib/zlib-1.3.2-5.tar.gz").as_deref(),
            Some("packages/zlib/zlib-1.3.2-5.tar.gz")
        );
        assert_eq!(
            source_key("/sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2").as_deref(),
            Some("sources/zlib/zlib-1.3.2-5-aarch64-src.tar.bz2")
        );
        assert_eq!(
            metadata_key("/metadata/aarch64/zlib/zlib-1.3.2-5.json").as_deref(),
            Some("metadata/aarch64/zlib/zlib-1.3.2-5.json")
        );
    }

    #[test]
    fn object_paths_reject_traversal() {
        assert!(package_key("/packages/zlib/../../../etc/passwd").is_none());
        assert!(package_key("/packages/../zlib/zlib-1.tar.gz").is_none());
        assert!(source_key("/sources/zlib/zlib-1.tar.bz2").is_none());
        assert!(metadata_key("/metadata/aarch64/zlib/../../../etc/passwd").is_none());
        assert!(metadata_key("/metadata/../zlib/zlib-1.json").is_none());
        assert!(metadata_key("/metadata/aarch64/zlib/zlib-1.tar.gz").is_none());
    }

    #[test]
    fn index_validation_checks_paths() {
        let index = vec![RemotePackage {
            arch: "aarch64".to_string(),
            name: "zlib".to_string(),
            ver: "1.3.2".to_string(),
            rel: "5".to_string(),
            deps: vec!["musl".to_string()],
            mkdeps_host: vec![],
            mkdeps_target: vec![],
            sha256: "a".repeat(64),
            size: 10,
            tarball: "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz".to_string(),
            metadata: "metadata/aarch64/zlib/zlib-1.3.2-5.json".to_string(),
            source_sha256: "b".repeat(64),
            metapackage: false,
        }];
        assert!(validate_index(&index).is_ok());
    }
}
