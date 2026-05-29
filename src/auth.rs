use std::collections::HashMap;

use crate::AppState;

pub fn authenticated(headers: &HashMap<String, String>, state: &AppState) -> bool {
    let Some(token) = extract_bearer(headers) else {
        return false;
    };

    // 1. DB token lookup
    match state.db.lock().unwrap().verify_token(token) {
        Ok(Some(_)) => return true,
        Ok(None) => {}
        Err(e) => tracing::warn!("db token lookup: {e}"),
    }

    // 2. JWT verification (if configured)
    if let Some(jwks_mutex) = &state.jwks {
        match jwks_mutex.lock().unwrap().verify(token) {
            Ok(_) => return true,
            Err(e) => tracing::debug!("jwt: {e}"),
        }
    }

    false
}

fn extract_bearer(headers: &HashMap<String, String>) -> Option<&str> {
    headers.get("authorization")?.strip_prefix("Bearer ")
}
