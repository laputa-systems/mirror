//! Runs the real mirror with in-memory storage so the passkey flow can be tried in a
//! browser: register a passkey, sign in, mint an API token, then use that token.
//!
//! WebAuthn only works on `localhost` or https, and the origin must match exactly,
//! so the demo is fixed to `http://localhost:3000`. Run it from the repository root
//! (static files are read relative to the working directory).

use std::sync::{Arc, Mutex, RwLock};

use laputa_mirror::{AppState, db::Db, s3::Storage};

const PORT: u16 = 3000;
const USER: &str = "demo";

fn main() {
    let origin = format!("http://localhost:{PORT}");
    let state = Arc::new(AppState {
        s3: Storage::memory(),
        db: Mutex::new(Db::open(":memory:").expect("in-memory auth db")),
        webauthn: webauthn_minimal::RelyingParty::new("localhost", &origin, "Laputa Mirror Demo"),
        jwks: None,
        allowed_users: vec![USER.to_string()],
        index: RwLock::new(Vec::new()),
        upload_dir: std::env::temp_dir().join("laputa-mirror-demo-uploads"),
        index_lock: Mutex::new(()),
        secure_cookies: false,
        r2_public_url: None,
    });

    let server = tiny_http::Server::http(("127.0.0.1", PORT)).expect("failed to bind");
    println!("Laputa mirror demo (in-memory; everything is lost on exit)\n");
    println!("1. Open {origin}/auth");
    println!("2. Register a passkey as user `{USER}`, then sign in with it");
    println!("3. Copy the token it shows, then prove it works:\n");
    println!("   TOKEN=<paste>");
    println!("   curl -i -X PUT {origin}/index.json -d '[]'                                  # 401: no token");
    println!("   curl -i -X PUT {origin}/index.json -d '[]' -H \"Authorization: Bearer $TOKEN\"  # 201");
    laputa_mirror::serve(server, state);
}
