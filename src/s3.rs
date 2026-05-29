use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::RwLock;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(h.finalize().as_slice())
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_encode(h.finalize().as_slice()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
        s
    })
}

/// UTC date/time from system clock. Returns (YYYYMMDD, YYYYMMDDTHHmmSSZ).
fn utc_now() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Howard Hinnant's civil_from_days.
    let z = (secs / 86400) as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };

    let date = format!("{yr:04}{mo:02}{d:02}");
    let datetime = format!("{yr:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z");
    (date, datetime)
}

fn sigv4_signature(
    method: &str,
    path: &str,
    query: &str,
    headers_sorted: &[(&str, &str)],
    body_hash: &str,
    secret_key: &str,
    region: &str,
    date: &str,
    datetime: &str,
) -> String {
    let signed_headers: Vec<&str> = headers_sorted.iter().map(|(k, _)| *k).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers_sorted
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();

    let canonical = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers_str}\n{body_hash}"
    );
    let canonical_hash = sha256_hex(canonical.as_bytes());

    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{datetime}\n{scope}\n{canonical_hash}");

    let dk = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let rk = hmac_sha256(&dk, region.as_bytes());
    let sk = hmac_sha256(&rk, b"s3");
    let signing_key = hmac_sha256(&sk, b"aws4_request");
    hex_encode(&hmac_sha256(&signing_key, to_sign.as_bytes()))
}

fn sigv4_auth(
    method: &str,
    path: &str,
    query: &str,
    headers_sorted: &[(&str, &str)],
    body_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    date: &str,
    datetime: &str,
) -> String {
    let signed_headers: Vec<&str> = headers_sorted.iter().map(|(k, _)| *k).collect();
    let signed_headers_str = signed_headers.join(";");
    let scope = format!("{date}/{region}/s3/aws4_request");
    let sig = sigv4_signature(
        method,
        path,
        query,
        headers_sorted,
        body_hash,
        secret_key,
        region,
        date,
        datetime,
    );
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers_str}, Signature={sig}"
    )
}

/// Storage backend: S3 via ureq or in-memory for tests.
pub enum Storage {
    S3 {
        endpoint: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    Memory(RwLock<HashMap<String, Vec<u8>>>),
}

impl Storage {
    pub fn s3(
        endpoint: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) -> Self {
        Self::S3 {
            endpoint: endpoint.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            region: region.into(),
        }
    }

    pub fn memory() -> Self {
        Self::Memory(RwLock::new(HashMap::new()))
    }

    /// Return the stored size of an object via HEAD, without downloading it.
    pub fn object_size(&self, key: &str) -> Option<u64> {
        match self {
            Self::Memory(map) => map.read().unwrap().get(key).map(|b| b.len() as u64),
            Self::S3 {
                endpoint,
                bucket,
                access_key,
                secret_key,
                region,
            } => {
                let url = format!("{endpoint}/{bucket}/{key}");
                let host = url
                    .strip_prefix("https://")
                    .or_else(|| url.strip_prefix("http://"))
                    .and_then(|r| r.split('/').next())
                    .unwrap_or("")
                    .to_string();
                let path = format!("/{bucket}/{key}");
                let body_hash = sha256_hex(b"");
                let (date, datetime) = utc_now();
                let hdr = [
                    ("host", host.as_str()),
                    ("x-amz-content-sha256", body_hash.as_str()),
                    ("x-amz-date", datetime.as_str()),
                ];
                let auth = sigv4_auth(
                    "HEAD", &path, "", &hdr, &body_hash, access_key, secret_key, region, &date,
                    &datetime,
                );
                let result = ureq::Agent::new_with_defaults()
                    .head(&url)
                    .header("Authorization", &auth)
                    .header("X-Amz-Content-Sha256", &body_hash)
                    .header("X-Amz-Date", &datetime)
                    .call();
                match result {
                    Ok(resp) => resp
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok()),
                    Err(_) => None,
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        match self {
            Self::S3 { .. } => {
                let (status, body) = self.s3_request("GET", key, &[], "").ok()?;
                if status == 200 { Some(body) } else { None }
            }
            Self::Memory(map) => map.read().unwrap().get(key).cloned(),
        }
    }

    pub fn put(&self, key: &str, body: Vec<u8>, content_type: &str) -> Result<(), String> {
        match self {
            Self::S3 { .. } => {
                let (status, _) = self.s3_request("PUT", key, &body, content_type)?;
                if (200..300).contains(&status) {
                    Ok(())
                } else {
                    Err(format!("S3 PUT returned {status}"))
                }
            }
            Self::Memory(map) => {
                map.write().unwrap().insert(key.to_string(), body);
                Ok(())
            }
        }
    }

    pub fn put_file(&self, key: &str, path: &Path, content_type: &str) -> Result<(), String> {
        match self {
            Self::S3 { .. } => self.s3_put_file(key, path, content_type),
            Self::Memory(_) => {
                let body =
                    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
                self.put(key, body, content_type)
            }
        }
    }

    /// Generate a presigned GET URL valid for `expires_secs` seconds.
    pub fn presign_get(&self, key: &str, expires_secs: u64) -> Option<String> {
        self.presign_url("GET", key, expires_secs)
    }

    /// Generate a presigned PUT URL valid for `expires_secs` seconds.
    /// The caller may PUT any body to this URL without auth headers.
    /// Body hash is UNSIGNED-PAYLOAD so the size need not be known in advance.
    pub fn presign_put(&self, key: &str, expires_secs: u64) -> Option<String> {
        self.presign_url("PUT", key, expires_secs)
    }

    fn presign_url(&self, method: &str, key: &str, expires_secs: u64) -> Option<String> {
        let Self::S3 {
            endpoint,
            bucket,
            access_key,
            secret_key,
            region,
        } = self
        else {
            return None;
        };
        let (date, datetime) = utc_now();
        let scope = format!("{date}/{region}/s3/aws4_request");
        // Percent-encode '/' in credential for the query string.
        let credential = format!("{access_key}/{scope}").replace('/', "%2F");
        // Query parameters must be sorted alphabetically.
        let query = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256\
            &X-Amz-Credential={credential}\
            &X-Amz-Date={datetime}\
            &X-Amz-Expires={expires_secs}\
            &X-Amz-SignedHeaders=host"
        );
        let url = format!("{endpoint}/{bucket}/{key}");
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|r| r.split('/').next())
            .unwrap_or("");
        let path = format!("/{bucket}/{key}");
        let headers_sorted = vec![("host", host)];
        let sig = sigv4_signature(
            method,
            &path,
            &query,
            &headers_sorted,
            "UNSIGNED-PAYLOAD",
            secret_key,
            region,
            &date,
            &datetime,
        );
        Some(format!("{url}?{query}&X-Amz-Signature={sig}"))
    }

    fn s3_put_file(&self, key: &str, path: &Path, content_type: &str) -> Result<(), String> {
        let Self::S3 {
            endpoint,
            bucket,
            access_key,
            secret_key,
            region,
        } = self
        else {
            return Err("not S3".into());
        };

        let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let body_hash = sha256_file_hex(path)?;
        let content_length = file
            .metadata()
            .map_err(|e| format!("metadata {}: {e}", path.display()))?
            .len()
            .to_string();
        let url = format!("{endpoint}/{bucket}/{key}");
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|r| r.split('/').next())
            .unwrap_or("");
        let path = format!("/{bucket}/{key}");
        let (date, datetime) = utc_now();
        let ct = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let mut hdr = vec![
            ("content-length", content_length.as_str()),
            ("content-type", ct),
            ("host", host),
            ("x-amz-content-sha256", body_hash.as_str()),
            ("x-amz-date", datetime.as_str()),
        ];
        hdr.sort_by_key(|(k, _)| *k);
        let auth = sigv4_auth(
            "PUT", &path, "", &hdr, &body_hash, access_key, secret_key, region, &date, &datetime,
        );

        let response = ureq::Agent::new_with_defaults()
            .put(&url)
            .header("Authorization", &auth)
            .header("Content-Length", &content_length)
            .header("Content-Type", ct)
            .header("X-Amz-Content-Sha256", &body_hash)
            .header("X-Amz-Date", &datetime)
            .send(file);

        match response {
            Ok(resp) if (200..300).contains(&u16::from(resp.status())) => Ok(()),
            Ok(resp) => Err(format!("S3 PUT returned {}", resp.status())),
            Err(ureq::Error::StatusCode(status)) => Err(format!("S3 PUT returned {status}")),
            Err(e) => Err(format!("S3 PUT failed: {e}")),
        }
    }

    fn s3_request(
        &self,
        method: &str,
        key: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<(u16, Vec<u8>), String> {
        let Self::S3 {
            endpoint,
            bucket,
            access_key,
            secret_key,
            region,
        } = self
        else {
            return Err("not S3".into());
        };

        let url = format!("{endpoint}/{bucket}/{key}");
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|r| r.split('/').next())
            .unwrap_or("");
        let path = format!("/{bucket}/{key}");

        let body_hash = sha256_hex(body);
        let (date, datetime) = utc_now();
        let content_length = body.len().to_string();
        let is_put = method == "PUT";

        let ct = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let mut hdr = vec![
            ("host", host),
            ("x-amz-content-sha256", &body_hash),
            ("x-amz-date", &datetime),
        ];
        // Only include content-type and content-length in signed headers for PUT.
        if is_put {
            hdr.push(("content-length", content_length.as_str()));
            hdr.push(("content-type", ct));
        }
        hdr.sort_by_key(|(k, _)| *k);

        let auth = sigv4_auth(
            method, &path, "", &hdr, &body_hash, access_key, secret_key, region, &date, &datetime,
        );

        let agent = ureq::Agent::new_with_defaults();

        let result = match &*method {
            "GET" => agent
                .get(&url)
                .header("Authorization", &auth)
                .header("Content-Type", ct)
                .header("X-Amz-Content-Sha256", &body_hash)
                .header("X-Amz-Date", &datetime)
                .call(),
            "HEAD" => agent
                .head(&url)
                .header("Authorization", &auth)
                .header("Content-Type", ct)
                .header("X-Amz-Content-Sha256", &body_hash)
                .header("X-Amz-Date", &datetime)
                .call(),
            "PUT" => agent
                .put(&url)
                .header("Authorization", &auth)
                .header("Content-Length", &content_length)
                .header("Content-Type", ct)
                .header("X-Amz-Content-Sha256", &body_hash)
                .header("X-Amz-Date", &datetime)
                .send(body),
            _ => return Err(format!("unsupported method: {method}")),
        };

        match result {
            Ok(mut resp) => {
                let status = resp.status();
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut resp.body_mut().as_reader(), &mut bytes)
                    .unwrap_or_default();
                Ok((status.into(), bytes))
            }
            Err(ureq::Error::StatusCode(status)) => Ok((status, vec![])),
            Err(e) => Err(format!("S3 request failed: {e}")),
        }
    }
}
