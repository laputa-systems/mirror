//! Outbound blocking HTTP(S) shared by S3, JWKS fetches, and publishing.
//!
//! Every status is returned to the caller: unlike `ureq`, a 4xx/5xx is not an
//! error here, because the S3 paths treat 404 and friends as ordinary answers.

use std::error::Error as _;
use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;

use h12tiny_client_sync::Client;
use http::Request;

pub struct Reply {
    pub status: u16,
    pub content_length: Option<u64>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as lossy text, for including a server's error message.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One client owns one TLS configuration; building it loads the root store.
fn client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(Client::new)
}

/// Send a request with an in-memory body.
pub fn send(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<Reply, String> {
    let request = build(method, url, headers, body)?;
    let response = client()
        .request(request)
        .map_err(|e| describe(method, url, &e))?;
    read_reply(method, url, response)
}

/// Send a request whose body is streamed from `file`, which must hold exactly
/// `length` bytes; the whole file is never held in memory.
pub fn send_file(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    file: File,
    length: u64,
) -> Result<Reply, String> {
    let request = build(method, url, headers, file)?;
    let response = client()
        .request_streaming(request, length, None)
        .map_err(|e| describe(method, url, &e))?;
    read_reply(method, url, response)
}

fn build<B>(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: B,
) -> Result<Request<B>, String> {
    let mut builder = Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body)
        .map_err(|e| format!("{method} {url}: invalid request: {e}"))
}

fn read_reply(
    method: &str,
    url: &str,
    mut response: http::Response<h12tiny_client_sync::ResponseBody>,
) -> Result<Reply, String> {
    let status = response.status().as_u16();
    let content_length = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let mut body = Vec::new();
    response
        .body_mut()
        .read_to_end(&mut body)
        .map_err(|e| format!("{method} {url}: read body: {e}"))?;
    Ok(Reply {
        status,
        content_length,
        body,
    })
}

/// The client's `Display` names only the failing stage; the cause is its source.
fn describe(method: &str, url: &str, error: &h12tiny_client_sync::Error) -> String {
    match error.source() {
        Some(source) => format!("{method} {url}: {error}: {source}"),
        None => format!("{method} {url}: {error}"),
    }
}
