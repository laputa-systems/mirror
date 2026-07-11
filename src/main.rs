use std::collections::HashMap;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use laputa_mirror::{AppState, packages, s3};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let listen_addr = env_or("LISTEN_ADDR", "127.0.0.1:3000");

    let allowed_users: Vec<String> = env_required("ALLOWED_USERS")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let rp_id = env_required("RP_ID");
    let rp_origin = env_required("RP_ORIGIN");

    let db = laputa_mirror::db::Db::open(&env_required("DB_PATH"))
        .expect("failed to open auth database");

    let webauthn = webauthn_minimal::RelyingParty::new(&rp_id, &rp_origin, "Laputa Mirror");

    let jwks = if let Ok(jwks_url) = std::env::var("JWT_JWKS_URL") {
        let config = laputa_mirror::jwt::JwtConfig {
            jwks_url,
            issuer: env_required("JWT_ISSUER"),
            audience: env_required("JWT_AUDIENCE"),
            subject_pattern: env_required("JWT_SUBJECT_PATTERN"),
        };
        Some(std::sync::Mutex::new(laputa_mirror::jwt::JwksCache::new(
            config,
        )))
    } else {
        tracing::info!("JWT_JWKS_URL not set; JWT/OIDC auth disabled");
        None
    };

    let s3 = s3::Storage::s3(
        &env_required("S3_ENDPOINT"),
        &env_required("S3_BUCKET"),
        &env_required("S3_ACCESS_KEY_ID"),
        &env_required("S3_SECRET_ACCESS_KEY"),
        &env_or("S3_REGION", "auto"),
    );
    let index = packages::load_index(&s3).unwrap_or_default();

    let r2_public_url = std::env::var("R2_PUBLIC_URL")
        .ok()
        .map(|u| u.trim_end_matches('/').to_string());
    let upload_dir = std::env::var("UPLOAD_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/laputa-mirror/uploads"));

    let state = Arc::new(AppState {
        s3,
        db: std::sync::Mutex::new(db),
        webauthn,
        jwks,
        allowed_users,
        index: std::sync::RwLock::new(index),
        upload_dir,
        upload_lock: std::sync::Mutex::new(()),
        secure_cookies: rp_origin.starts_with("https://"),
        r2_public_url,
    });

    let server = tiny_http::Server::http(&listen_addr).expect("failed to bind");
    println!("http://{listen_addr}");
    println!("  packages: http://{listen_addr}/");
    println!("  auth:     http://{listen_addr}/auth");

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

fn env_required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
