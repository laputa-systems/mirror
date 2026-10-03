pub mod auth;
pub mod db;
pub mod http;
pub mod jwt;
pub mod packages;
pub mod publish;
pub mod s3;
pub mod webauthn_handlers;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

pub struct AppState {
    pub s3: s3::Storage,
    pub db: Mutex<db::Db>,
    pub webauthn: webauthn_minimal::RelyingParty,
    pub jwks: Option<Mutex<jwt::JwksCache>>,
    pub allowed_users: Vec<String>,
    pub index: RwLock<Vec<packages::RemotePackage>>,
    pub upload_dir: PathBuf,
    /// Serializes index publication and the corresponding in-memory index update.
    pub index_lock: Mutex<()>,
    /// Set when RP_ORIGIN is https:// so Set-Cookie includes the Secure flag.
    pub secure_cookies: bool,
    /// If set, tarball GETs redirect here instead of proxying through the server.
    pub r2_public_url: Option<String>,
}

/// Serves requests forever, one thread per request.
pub fn serve(server: tiny_http::Server, state: Arc<AppState>) {
    for mut request in server.incoming_requests() {
        let state = state.clone();
        std::thread::spawn(move || {
            let method = request.method().as_str().to_string();
            let url = request.url().to_string();
            let headers: HashMap<String, String> = request
                .headers()
                .iter()
                .map(|h| {
                    (
                        h.field.as_str().as_str().to_lowercase(),
                        h.value.as_str().to_string(),
                    )
                })
                .collect();

            let mut body = Vec::new();
            let _ = request.as_reader().read_to_end(&mut body);

            let resp = packages::route(&method, &url, &headers, &body, &state);

            let ct =
                tiny_http::Header::from_bytes(&b"Content-Type"[..], resp.content_type.as_bytes())
                    .unwrap();

            let mut response = tiny_http::Response::from_data(resp.body)
                .with_status_code(resp.status)
                .with_header(ct);
            for (name, value) in &resp.extra_headers {
                if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                    response = response.with_header(h);
                }
            }

            let _ = request.respond(response);
        });
    }
}
