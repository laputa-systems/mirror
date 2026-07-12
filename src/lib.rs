pub mod auth;
pub mod db;
pub mod jwt;
pub mod packages;
pub mod publish;
pub mod s3;
pub mod webauthn_handlers;

use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

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
