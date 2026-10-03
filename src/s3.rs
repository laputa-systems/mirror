use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::RwLock;

use graviola::hashing::hmac::Hmac;
use graviola::hashing::{Hash, HashContext, Sha256};

use crate::db::{hex_encode, sha256_hex};

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
    Ok(hex_encode(h.finish().as_ref()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new(key);
    mac.update(data);
    mac.finish().as_ref().to_vec()
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

/// Storage backend: S3 or in-memory for tests.
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
                let reply = crate::http::send(
                    "HEAD",
                    &url,
                    &[
                        ("Authorization", &auth),
                        ("X-Amz-Content-Sha256", &body_hash),
                        ("X-Amz-Date", &datetime),
                    ],
                    Vec::new(),
                )
                .ok()?;
                if reply.is_success() {
                    reply.content_length
                } else {
                    None
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
            ..
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
        let length = file
            .metadata()
            .map_err(|e| format!("metadata {}: {e}", path.display()))?
            .len();
        let content_length = length.to_string();
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

        let reply = crate::http::send_file(
            "PUT",
            &url,
            &[
                ("Authorization", &auth),
                ("Content-Type", ct),
                ("X-Amz-Content-Sha256", &body_hash),
                ("X-Amz-Date", &datetime),
            ],
            file,
            length,
        )
        .map_err(|e| format!("S3 PUT failed: {e}"))?;
        if reply.is_success() {
            Ok(())
        } else {
            Err(format!("S3 PUT returned {}", reply.status))
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

        if !matches!(method, "GET" | "HEAD" | "PUT") {
            return Err(format!("unsupported method: {method}"));
        }
        let headers = [
            ("Authorization", auth.as_str()),
            ("Content-Type", ct),
            ("X-Amz-Content-Sha256", body_hash.as_str()),
            ("X-Amz-Date", datetime.as_str()),
        ];
        let reply = crate::http::send(method, &url, &headers, body.to_vec())
            .map_err(|e| format!("S3 request failed: {e}"))?;
        Ok((reply.status, reply.body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_digest() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The key-derivation example from the AWS SigV4 documentation.
    #[test]
    fn sigv4_signing_key_matches_aws_documented_example() {
        let dk = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let rk = hmac_sha256(&dk, b"us-east-1");
        let sk = hmac_sha256(&rk, b"iam");
        let signing_key = hmac_sha256(&sk, b"aws4_request");
        assert_eq!(
            hex_encode(&signing_key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
