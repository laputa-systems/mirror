use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};
use uuid::Uuid;
use webauthn_minimal::{
    AuthChallenge, AuthenticationResponse, RegChallenge, RelyingParty, StoredCredential,
};

static AUTH_HTML: &str = include_str!("frontend/index.html");
static AUTH_JS: &str = include_str!("frontend/dist/bundle.js");
static AUTH_CSS: &str = include_str!("frontend/src/style.css");

struct Db {
    users: HashMap<String, String>,
    credentials: HashMap<String, Vec<StoredCredential>>,
    sessions: HashMap<String, (Option<String>, String)>,
}

impl Db {
    fn find_credential(&self, uid: &str, cred_id_b64: &str) -> Option<StoredCredential> {
        if !uid.is_empty() {
            self.credentials.get(uid).and_then(|creds| {
                creds
                    .iter()
                    .find(|c| Base64UrlUnpadded::encode_string(&c.cred_id) == cred_id_b64)
                    .cloned()
            })
        } else {
            self.credentials
                .values()
                .flat_map(|creds| creds.iter())
                .find(|c| Base64UrlUnpadded::encode_string(&c.cred_id) == cred_id_b64)
                .cloned()
        }
    }
}

struct AppState {
    db: Mutex<Db>,
    webauthn: RelyingParty,
}

fn json(status: u16, body: impl serde::Serialize) -> Response<std::io::Cursor<Vec<u8>>> {
    let s = serde_json::to_string(&body).unwrap();
    Response::from_string(s)
        .with_status_code(status)
        .with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
}

fn html(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(Header::from_bytes(b"Content-Type", b"text/html").unwrap())
}

fn main() {
    let server = Server::http("0.0.0.0:8080").expect("failed to bind to port 8080");
    println!("Demo server running at http://localhost:8080");

    let state = Arc::new(AppState {
        db: Mutex::new(Db {
            users: HashMap::new(),
            credentials: HashMap::new(),
            sessions: HashMap::new(),
        }),
        webauthn: RelyingParty::new("localhost", "http://localhost:8080", "WebAuthn Demo"),
    });

    for mut request in server.incoming_requests() {
        let state = Arc::clone(&state);
        let url = request.url().to_string();
        let method = request.method();

        let response = match (method, url.as_str()) {
            (&Method::Get, "/") | (&Method::Get, "/auth") => html(AUTH_HTML),
            (&Method::Get, "/style.css") => Response::from_string(AUTH_CSS)
                .with_header(Header::from_bytes(b"Content-Type", b"text/css").unwrap()),
            (&Method::Get, "/bundle.js") => Response::from_string(AUTH_JS).with_header(
                Header::from_bytes(b"Content-Type", b"application/javascript").unwrap(),
            ),
            (&Method::Post, "/auth/register/options") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let username = req["username"].as_str().unwrap_or("");
                let mode = match req["mode"].as_str() {
                    Some("hardware") => webauthn_minimal::RegistrationMode::HardwareKey,
                    _ => webauthn_minimal::RegistrationMode::Passkey,
                };

                if username.is_empty() {
                    json(400, serde_json::json!({"error":"username required"}))
                } else {
                    let user_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.users.insert(username.to_string(), user_id.clone());
                    }
                    let (options, reg_state) =
                        state.webauthn.start_registration(&user_id, username, mode);
                    let session_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.sessions.insert(
                            session_id.clone(),
                            (Some(user_id), serde_json::to_string(&reg_state).unwrap()),
                        );
                    }
                    json(
                        200,
                        serde_json::json!({ "session_id": session_id, "options": options }),
                    )
                }
            }
            (&Method::Post, "/auth/register/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let session_id = req["session_id"].as_str().unwrap_or("");

                let res = {
                    let db = state.db.lock().unwrap();
                    db.sessions.get(session_id).cloned()
                };

                if let Some((Some(uid), ch)) = res {
                    let reg_state: RegChallenge = serde_json::from_str(&ch).unwrap();
                    match serde_json::from_value(req["credential"].clone()) {
                        Ok(credential) => {
                            match state.webauthn.finish_registration(&credential, &reg_state) {
                                Ok(cred) => {
                                    {
                                        let mut db = state.db.lock().unwrap();
                                        db.credentials.entry(uid.clone()).or_default().push(cred);
                                        db.sessions.remove(session_id);
                                    }
                                    json(200, serde_json::json!({"token":"demo-token-123"}))
                                }
                                Err(e) => json(400, serde_json::json!({"error": e.to_string()})),
                            }
                        }
                        Err(e) => {
                            let msg = format!("invalid credential: {e}");
                            json(400, serde_json::json!({ "error": msg }))
                        }
                    }
                } else {
                    json(400, serde_json::json!({"error":"invalid session"}))
                }
            }
            (&Method::Post, "/auth/authenticate/options") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let username = req["username"].as_str().unwrap_or("");

                let (user_id, creds) = if username.is_empty() {
                    // Passkey mode: empty credentials list
                    ("".to_string(), Vec::new())
                } else {
                    // Hardware key mode: lookup user credentials
                    let db = state.db.lock().unwrap();
                    let uid = db.users.get(username).cloned().unwrap_or_default();
                    let creds = db.credentials.get(&uid).cloned().unwrap_or_default();
                    (uid, creds)
                };

                let (options, auth_state) = state.webauthn.start_authentication(&creds);
                let session_id = Uuid::new_v4().to_string();
                {
                    let mut db = state.db.lock().unwrap();
                    db.sessions.insert(
                        session_id.clone(),
                        (Some(user_id), serde_json::to_string(&auth_state).unwrap()),
                    );
                }
                json(
                    200,
                    serde_json::json!({ "session_id": session_id, "options": options }),
                )
            }
            (&Method::Post, "/auth/authenticate/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let session_id = req["session_id"].as_str().unwrap_or("");

                let res = {
                    let db = state.db.lock().unwrap();
                    db.sessions.get(session_id).cloned()
                };

                if let Some((Some(uid), ch)) = res {
                    let auth_state: AuthChallenge = serde_json::from_str(&ch).unwrap();
                    match serde_json::from_value::<AuthenticationResponse>(
                        req["credential"].clone(),
                    ) {
                        Ok(credential) => {
                            let found_cred = {
                                let db = state.db.lock().unwrap();
                                db.find_credential(&uid, &credential.id)
                            };

                            match found_cred {
                                Some(cred) => match state.webauthn.finish_authentication(
                                    &credential,
                                    &auth_state,
                                    &cred,
                                ) {
                                    Ok(_) => {
                                        {
                                            let mut db = state.db.lock().unwrap();
                                            db.sessions.remove(session_id);
                                        }
                                        json(200, serde_json::json!({"token":"demo-token-123"}))
                                    }
                                    Err(e) => {
                                        json(401, serde_json::json!({"error": e.to_string()}))
                                    }
                                },
                                None => {
                                    json(401, serde_json::json!({"error":"credential not found"}))
                                }
                            }
                        }
                        Err(e) => {
                            let msg = format!("invalid credential: {e}");
                            json(400, serde_json::json!({ "error": msg }))
                        }
                    }
                } else {
                    json(400, serde_json::json!({"error":"invalid session"}))
                }
            }
            _ => Response::from_string("Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_credential() {
        let mut db = Db {
            users: HashMap::new(),
            credentials: HashMap::new(),
            sessions: HashMap::new(),
        };

        let uid = "user-123".to_string();
        let cred_id = vec![1, 2, 3, 4];
        let cred_id_b64 = Base64UrlUnpadded::encode_string(&cred_id);

        let cred = StoredCredential {
            cred_id: cred_id.clone(),
            aaguid: [0; 16],
            x: [0; 32],
            y: [0; 32],
            sign_count: 0,
        };

        db.credentials.insert(uid.clone(), vec![cred.clone()]);

        // Test 1: Find with correct UID
        assert!(db.find_credential(&uid, &cred_id_b64).is_some());

        // Test 2: Find with empty UID (passkey mode)
        assert!(db.find_credential("", &cred_id_b64).is_some());

        // Test 3: Not found with wrong UID
        assert!(db.find_credential("wrong-uid", &cred_id_b64).is_none());

        // Test 4: Not found with wrong CredID
        assert!(db.find_credential(&uid, "wrong-id").is_none());
        assert!(db.find_credential("", "wrong-id").is_none());
    }
}
