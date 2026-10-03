use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;

use webauthn_minimal::{AuthChallenge, RegChallenge, RegistrationMode, StoredCredential};

use crate::AppState;
use crate::packages::{Response, session_cookie};

static AUTH_HTML: &str = include_str!("../static/auth.html");

pub fn auth_page() -> Response {
    Response::html(AUTH_HTML.as_bytes().to_vec())
}

/// Returns (username, user_id) for the authenticated browser session, or None.
fn session_user(headers: &HashMap<String, String>, state: &AppState) -> Option<(String, String)> {
    let cookie = session_cookie(headers)?;
    let db = state.db.lock().unwrap();
    let username = db.verify_browser_session(&cookie).ok()??;
    let user_id = db.get_user_by_name(&username).ok()??;
    Some((username, user_id))
}

/// POST /auth/register/options
/// Body: {"username":"josh"}
pub fn register_options(body: &[u8], state: &AppState) -> Response {
    #[derive(serde::Deserialize)]
    struct Req {
        username: String,
    }

    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Response::bad_request("invalid json"),
    };

    if !state.allowed_users.contains(&req.username) {
        return Response::json(403, r#"{"error":"username not allowed"}"#);
    }

    // Get or create the user record.
    let user_id = {
        let db = state.db.lock().unwrap();
        match db.get_user_by_name(&req.username) {
            Ok(Some(id)) => id,
            Ok(None) => {
                let id = uuid::Uuid::new_v4().to_string();
                if let Err(e) = db.create_user(&id, &req.username) {
                    return Response::error(&format!("db: {e}"));
                }
                id
            }
            Err(e) => return Response::error(&format!("db: {e}")),
        }
    };

    let (ccr, reg_state) =
        state
            .webauthn
            .start_registration(&user_id, &req.username, RegistrationMode::Passkey);

    let challenge_json = serde_json::to_string(&reg_state).unwrap();
    let session_id = {
        let db = state.db.lock().unwrap();
        match db.create_session(Some(&user_id), &challenge_json) {
            Ok(id) => id,
            Err(e) => return Response::error(&format!("db: {e}")),
        }
    };

    let body = serde_json::json!({ "session_id": session_id, "options": ccr });
    Response::json(200, &body.to_string())
}

/// POST /auth/register/verify
/// Body: {"session_id":"...","credential":{...}}
pub fn register_verify(body: &[u8], state: &AppState) -> Response {
    #[derive(serde::Deserialize)]
    struct Req {
        session_id: String,
        credential: serde_json::Value,
    }

    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Response::bad_request("invalid json"),
    };

    let (user_id, challenge_json) = {
        let db = state.db.lock().unwrap();
        let session = match db.get_session(&req.session_id) {
            Ok(Some(s)) if s.status == "pending" => s,
            Ok(_) => return Response::json(400, r#"{"error":"invalid or expired session"}"#),
            Err(e) => return Response::error(&format!("db: {e}")),
        };
        let uid = match session.user_id {
            Some(id) => id,
            None => return Response::json(400, r#"{"error":"no user in session"}"#),
        };
        let ch = match session.challenge {
            Some(c) => c,
            None => return Response::json(400, r#"{"error":"missing challenge"}"#),
        };
        (uid, ch)
    };

    let reg_state: RegChallenge = match serde_json::from_str(&challenge_json) {
        Ok(s) => s,
        Err(e) => return Response::json(400, &format!(r#"{{"error":"bad challenge: {e}"}}"#)),
    };

    let credential: webauthn_minimal::RegistrationResponse =
        match serde_json::from_value(req.credential) {
            Ok(c) => c,
            Err(e) => return Response::bad_request(&format!("invalid credential format: {e}")),
        };

    let cred = match state.webauthn.finish_registration(&credential, &reg_state) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("passkey registration failed: {e}");
            return Response::json(400, r#"{"error":"registration failed"}"#);
        }
    };

    let cred_id = crate::db::hex_encode(&cred.cred_id);
    let passkey_json = serde_json::to_string(&cred).unwrap();

    let (new_token, browser_session) = {
        let db = state.db.lock().unwrap();
        if let Err(e) = db.save_credential(&cred_id, &user_id, &passkey_json) {
            return Response::error(&format!("db: {e}"));
        }
        // Only create an API token on first registration.
        let token = if !db.has_any_token(&user_id).unwrap_or(false) {
            match db.create_token(&user_id, "cli", None) {
                Ok(t) => {
                    let _ = db.complete_session(&req.session_id, &t);
                    Some(t)
                }
                Err(e) => return Response::error(&format!("db: {e}")),
            }
        } else {
            None
        };
        let session = match db.create_browser_session(&user_id) {
            Ok(s) => s,
            Err(e) => return Response::error(&format!("db: {e}")),
        };
        (token, session)
    };

    let token_json = match &new_token {
        Some(t) => format!(r#""{t}""#),
        None => "null".to_string(),
    };
    Response::json(200, &format!(r#"{{"token":{token_json}}}"#))
        .with_set_cookie(make_session_cookie(&browser_session, state))
}

/// POST /auth/authenticate/options
pub fn authenticate_options(state: &AppState) -> Response {
    let (user_id, creds) = {
        let db = state.db.lock().unwrap();

        let username = match state.allowed_users.first() {
            Some(u) => u.clone(),
            None => return Response::error("no allowed users configured"),
        };

        let user_id = match db.get_user_by_name(&username) {
            Ok(Some(id)) => id,
            Ok(None) => return Response::json(404, r#"{"error":"no user registered"}"#),
            Err(e) => return Response::error(&format!("db: {e}")),
        };

        let rows = match db.load_passkeys(&user_id) {
            Ok(r) => r,
            Err(e) => return Response::error(&format!("db: {e}")),
        };

        let creds: Vec<StoredCredential> = rows
            .iter()
            .filter_map(|(_, json)| serde_json::from_str(json).ok())
            .collect();

        if creds.is_empty() {
            return Response::json(404, r#"{"error":"no credentials registered"}"#);
        }

        (user_id, creds)
    };

    let (rcr, auth_state) = state.webauthn.start_authentication(&creds);

    let challenge_json = serde_json::to_string(&auth_state).unwrap();
    let session_id = {
        let db = state.db.lock().unwrap();
        match db.create_session(Some(&user_id), &challenge_json) {
            Ok(id) => id,
            Err(e) => return Response::error(&format!("db: {e}")),
        }
    };

    let body = serde_json::json!({ "session_id": session_id, "options": rcr });
    Response::json(200, &body.to_string())
}

/// POST /auth/authenticate/verify
/// Body: {"session_id":"...","credential":{...}}
pub fn authenticate_verify(body: &[u8], state: &AppState) -> Response {
    #[derive(serde::Deserialize)]
    struct Req {
        session_id: String,
        credential: serde_json::Value,
    }

    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Response::bad_request("invalid json"),
    };

    let (user_id, challenge_json, passkey_rows) = {
        let db = state.db.lock().unwrap();

        let session = match db.get_session(&req.session_id) {
            Ok(Some(s)) if s.status == "pending" => s,
            Ok(_) => return Response::json(400, r#"{"error":"invalid or expired session"}"#),
            Err(e) => return Response::error(&format!("db: {e}")),
        };

        let uid = match session.user_id {
            Some(id) => id,
            None => return Response::json(400, r#"{"error":"no user in session"}"#),
        };
        let ch = match session.challenge {
            Some(c) => c,
            None => return Response::json(400, r#"{"error":"missing challenge"}"#),
        };
        let rows = match db.load_passkeys(&uid) {
            Ok(r) => r,
            Err(e) => return Response::error(&format!("db: {e}")),
        };

        (uid, ch, rows)
    };

    let auth_state: AuthChallenge = match serde_json::from_str(&challenge_json) {
        Ok(s) => s,
        Err(e) => return Response::json(400, &format!(r#"{{"error":"bad challenge: {e}"}}"#)),
    };

    let credential: webauthn_minimal::AuthenticationResponse =
        match serde_json::from_value(req.credential) {
            Ok(c) => c,
            Err(e) => return Response::bad_request(&format!("invalid credential format: {e}")),
        };

    let stored_creds: Vec<StoredCredential> = passkey_rows
        .iter()
        .filter_map(|(_, json)| serde_json::from_str(json).ok())
        .collect();

    let matched_cred = stored_creds
        .iter()
        .find(|c| {
            c.cred_id
                == Base64UrlUnpadded::decode_vec(credential.raw_id.trim_end_matches('='))
                    .unwrap_or_default()
        })
        .ok_or_else(|| Response::json(401, r#"{"error":"credential not found"}"#));

    let cred = match matched_cred {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let updated_cred = match state
        .webauthn
        .finish_authentication(&credential, &auth_state, cred)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("passkey authentication failed: {e}");
            return Response::json(401, r#"{"error":"authentication failed"}"#);
        }
    };

    let (new_token, browser_session) = {
        let db = state.db.lock().unwrap();

        // Persist updated sign counter.
        let updated_json = serde_json::to_string(&updated_cred).unwrap();
        let cred_id_hex = crate::db::hex_encode(&updated_cred.cred_id);
        let _ = db.update_passkey(&cred_id_hex, &updated_json);

        // Only create an API token if user has none yet.
        let token = if !db.has_any_token(&user_id).unwrap_or(false) {
            match db.create_token(&user_id, "cli", None) {
                Ok(t) => {
                    let _ = db.complete_session(&req.session_id, &t);
                    Some(t)
                }
                Err(e) => return Response::error(&format!("db: {e}")),
            }
        } else {
            None
        };
        let session = match db.create_browser_session(&user_id) {
            Ok(s) => s,
            Err(e) => return Response::error(&format!("db: {e}")),
        };
        (token, session)
    };

    let token_json = match &new_token {
        Some(t) => format!(r#""{t}""#),
        None => "null".to_string(),
    };
    Response::json(200, &format!(r#"{{"token":{token_json}}}"#))
        .with_set_cookie(make_session_cookie(&browser_session, state))
}

/// GET /auth/poll?session={id}
/// Returns token once (status 200), then 202 while pending, 404 if not found.
pub fn poll_session(query: &str, state: &AppState) -> Response {
    let session_id = query
        .split('&')
        .find_map(|p| p.strip_prefix("session="))
        .unwrap_or("");

    if session_id.is_empty() {
        return Response::bad_request("missing session");
    }

    let db = state.db.lock().unwrap();
    match db.consume_session_token(session_id) {
        Ok(Some(token)) => Response::json(200, &format!(r#"{{"token":"{token}"}}"#)),
        Ok(None) => {
            // Check if session exists at all (might be pending or expired)
            match db.get_session(session_id) {
                Ok(Some(_)) => Response::json(202, r#"{"status":"pending"}"#),
                _ => Response::not_found(),
            }
        }
        Err(e) => Response::error(&format!("db: {e}")),
    }
}

/// GET /auth/logout invalidates browser session, clears cookie, redirects to /.
pub fn logout(headers: &HashMap<String, String>, state: &AppState) -> Response {
    if let Some(cookie) = session_cookie(headers) {
        let _ = state.db.lock().unwrap().invalidate_browser_session(&cookie);
    }
    Response::redirect("/").with_set_cookie(clear_session_cookie(state))
}

/// GET /auth/settings token management page; requires browser session.
pub fn settings_page(headers: &HashMap<String, String>, state: &AppState) -> Response {
    let (username, user_id) = match session_user(headers, state) {
        Some(u) => u,
        None => return Response::redirect("/auth"),
    };

    let tokens = state
        .db
        .lock()
        .unwrap()
        .list_tokens(&user_id)
        .unwrap_or_default();

    let token_rows: String = if tokens.is_empty() {
        "<tr><td colspan=5 class=empty>No tokens yet.</td></tr>".to_string()
    } else {
        tokens
            .iter()
            .map(|t| {
                let last_used = t
                    .last_used
                    .as_deref()
                    .map(|s| &s[..16.min(s.len())])
                    .unwrap_or("\u{2014}");
                let expires = t
                    .expires_at
                    .as_deref()
                    .map(|s| &s[..16.min(s.len())])
                    .unwrap_or("never");
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{last_used}</td><td>{expires}</td>\
                <td><button class=del-btn data-id=\"{}\">Delete</button></td></tr>",
                    html_escape(&t.name),
                    &t.created_at[..16.min(t.created_at.len())],
                    html_escape(&t.id),
                )
            })
            .collect()
    };

    let html = format!(
        "<!doctype html><html lang=en><head>\
        <meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
        <title>Laputa Mirror Settings</title><style>\
        *{{margin:0;padding:0;box-sizing:border-box}}\
        body{{font-family:system-ui,sans-serif;max-width:720px;margin:0 auto;padding:2rem 1rem;\
        color:#e0e0e0;background:#1a1a1a}}\
        header{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:2rem}}\
        h1{{font-size:1.2rem;color:#fff}}h1 a{{color:inherit;text-decoration:none}}\
        .userbar{{font-size:.8rem;color:#888}}.userbar a{{color:#888;text-decoration:none}}\
        .userbar a:hover{{text-decoration:underline}}\
        h2{{font-size:1rem;font-weight:600;margin:1.5rem 0 .75rem;color:#ccc}}\
        table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:1.5rem}}\
        th{{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #333;color:#888;font-weight:normal}}\
        td{{padding:.4rem .5rem;border-bottom:1px solid #222}}\
        a{{color:#6ba3f7;text-decoration:none}}a:hover{{text-decoration:underline}}\
        .empty{{color:#666;padding:.5rem 0}}\
        .del-btn{{background:none;border:1px solid #555;color:#888;padding:.2rem .6rem;\
        border-radius:4px;cursor:pointer;font-size:.8rem}}\
        .del-btn:hover{{border-color:#f87171;color:#f87171}}\
        .row{{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin-bottom:.5rem}}\
        input{{padding:.5rem .7rem;border:1px solid #444;border-radius:6px;background:#111;\
        color:#e0e0e0;font-size:.9rem;font-family:inherit}}\
        input:focus{{outline:none;border-color:#4c8cf8}}\
        select{{padding:.5rem .7rem;border:1px solid #444;border-radius:6px;background:#111;\
        color:#e0e0e0;font-size:.9rem;font-family:inherit}}\
        .btn{{padding:.5rem 1rem;border:none;border-radius:6px;background:#4c8cf8;color:#fff;\
        font-size:.9rem;cursor:pointer;font-family:inherit}}\
        .btn:hover{{opacity:.85}}.btn:disabled{{opacity:.4;cursor:default}}\
        .msg{{font-size:.85rem;color:#888;margin-top:.5rem}}.err{{color:#f87171}}\
        .token-box{{margin-top:.75rem;padding:.75rem;background:#111;border:1px solid #333;\
        border-radius:6px;font-family:monospace;font-size:.8rem;word-break:break-all;color:#a3e635;user-select:all}}\
        .copy-btn{{margin-top:.4rem;padding:.3rem .7rem;font-size:.8rem;background:#222;\
        color:#ccc;border:1px solid #444;border-radius:4px;cursor:pointer}}\
        .copy-btn:hover{{background:#333}}\
        @media(prefers-color-scheme:light){{body{{color:#222;background:#fff}}\
        h1 a{{color:#000}}.userbar,.userbar a{{color:#aaa}}\
        h2{{color:#333}}th{{color:#666;border-color:#ddd}}td{{border-color:#eee}}\
        input,select{{background:#fff;border-color:#ccc;color:#222}}\
        .token-box{{background:#f9f9f9;border-color:#ddd;color:#166534}}\
        .copy-btn{{background:#eee;color:#444;border-color:#ccc}}}}\
        </style></head><body>\
        <header>\
          <h1><a href=\"/\">Laputa Packages</a></h1>\
          <span class=userbar>{username} \u{00b7} <a href=\"/auth/logout\">sign out</a></span>\
        </header>\
        <h2>API Tokens</h2>\
        <table><tr><th>Name</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr>\
        {token_rows}\
        </table>\
        <h2>Create Token</h2>\
        <div id=create-section>\
          <div class=row>\
            <input type=text id=name-input placeholder=\"Name (e.g. laptop, ci)\" style=width:200px>\
            <select id=ttl-select>\
              <option value=\"\">Never expires</option>\
              <option value=\"1\">24 hours</option>\
              <option value=\"7\">7 days</option>\
              <option value=\"30\">30 days</option>\
              <option value=\"90\">90 days</option>\
              <option value=\"365\">1 year</option>\
            </select>\
            <button class=btn id=create-btn>Create</button>\
          </div>\
          <div class=msg id=create-msg></div>\
        </div>\
        <div id=new-token-section hidden>\
          <div class=msg style=\"color:#a3e635;margin-bottom:.4rem\">Token created \u{2014} shown once, store it securely.</div>\
          <div class=token-box id=new-token-value></div>\
          <button class=copy-btn id=copy-btn>Copy</button>\
          <div class=msg style=margin-top:.75rem>\
            <a href=\"/auth/settings\">Done</a>\
          </div>\
        </div>\
        <script src=\"/static/js/settings.js\"></script>\
        </body></html>"
    );

    Response::html(html.into_bytes())
}

/// POST /auth/tokens creates a named API token.
pub fn create_token_api(
    body: &[u8],
    headers: &HashMap<String, String>,
    state: &AppState,
) -> Response {
    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        expires_days: Option<u64>,
    }

    let (_, user_id) = match session_user(headers, state) {
        Some(u) => u,
        None => return Response::json(401, r#"{"error":"not authenticated"}"#),
    };

    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Response::bad_request("invalid json"),
    };

    if req.name.is_empty() || req.name.len() > 64 {
        return Response::bad_request("name must be 1-64 characters");
    }

    let token = match state
        .db
        .lock()
        .unwrap()
        .create_token(&user_id, &req.name, req.expires_days)
    {
        Ok(t) => t,
        Err(e) => return Response::error(&format!("db: {e}")),
    };

    Response::json(200, &format!(r#"{{"token":"{token}"}}"#))
}

/// POST /auth/tokens/delete deletes a token by id.
pub fn delete_token_api(
    body: &[u8],
    headers: &HashMap<String, String>,
    state: &AppState,
) -> Response {
    #[derive(serde::Deserialize)]
    struct Req {
        id: String,
    }

    let (_, user_id) = match session_user(headers, state) {
        Some(u) => u,
        None => return Response::json(401, r#"{"error":"not authenticated"}"#),
    };

    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Response::bad_request("invalid json"),
    };

    if let Err(e) = state.db.lock().unwrap().delete_token(&req.id, &user_id) {
        return Response::error(&format!("db: {e}"));
    }

    Response::json(200, r#"{"ok":true}"#)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn make_session_cookie(value: &str, state: &AppState) -> String {
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    format!("laputa_mirror_session={value}; HttpOnly; SameSite=Strict; Path=/{secure}")
}

fn clear_session_cookie(state: &AppState) -> String {
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    format!("laputa_mirror_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
}
