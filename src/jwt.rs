use base64ct::{Base64UrlUnpadded, Encoding};
use graviola::signing::rsa::VerifyingKey;
use serde::Deserialize;

#[derive(Clone)]
pub struct JwtConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
    pub subject_pattern: String,
}

pub struct JwksCache {
    config: JwtConfig,
    keys: Vec<JwkKey>,
    fetched_at: std::time::Instant,
}

#[derive(Clone, Deserialize)]
struct JwkKey {
    kty: String,
    kid: Option<String>,
    // RSA fields
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    // aud can be a string or array in practice
    aud: serde_json::Value,
    exp: u64,
    /// Not valid before this time; absent in tokens that do not restrict it.
    #[serde(default)]
    nbf: Option<u64>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

/// How far a token's `nbf` may lie in the future, to absorb clock skew with the issuer.
const NBF_SKEW_SECS: u64 = 60;

// Refresh keys at most once per hour.
const TTL_SECS: u64 = 3600;

impl JwksCache {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            keys: vec![],
            fetched_at: std::time::Instant::now(),
        }
    }

    fn needs_refresh(&self) -> bool {
        self.keys.is_empty() || self.fetched_at.elapsed().as_secs() >= TTL_SECS
    }

    fn refresh(&mut self) -> Result<(), String> {
        let reply = crate::http::send("GET", &self.config.jwks_url, &[], &[])
            .map_err(|e| format!("jwks fetch: {e}"))?;
        if !reply.is_success() {
            return Err(format!("jwks fetch: HTTP {}", reply.status));
        }
        let parsed: JwksResponse =
            serde_json::from_slice(&reply.body).map_err(|e| format!("jwks parse: {e}"))?;
        self.keys = parsed.keys;
        self.fetched_at = std::time::Instant::now();
        tracing::info!("refreshed JWKS ({} keys)", self.keys.len());
        Ok(())
    }

    /// Verify a JWT token against the cached JWKS, refreshing if stale.
    pub fn verify(&mut self, token: &str) -> Result<(), String> {
        if self.needs_refresh() {
            self.refresh()?;
        }

        let (signed, signature) = token.rsplit_once('.').ok_or("jwt: malformed token")?;
        let (header_b64, claims_b64) = signed.split_once('.').ok_or("jwt: malformed token")?;
        let header: JwtHeader = decode_json(header_b64).map_err(|e| format!("jwt header: {e}"))?;
        // Only RS256 is accepted, so the token cannot pick a weaker algorithm.
        if header.alg != "RS256" {
            return Err(format!("unsupported jwt alg: {}", header.alg));
        }

        let key = self
            .keys
            .iter()
            .find(|k| match (&header.kid, &k.kid) {
                (Some(want), Some(have)) => want == have,
                (None, _) => true,
                _ => false,
            })
            .ok_or_else(|| "no matching jwk for kid".to_string())?;

        if key.kty != "RSA" {
            return Err(format!("unsupported key type: {}", key.kty));
        }
        let n = key.n.as_deref().ok_or("missing RSA n")?;
        let e = key.e.as_deref().ok_or("missing RSA e")?;
        let verifying_key = VerifyingKey::from_pkcs1_der(&rsa_public_key_der(n, e)?)
            .map_err(|e| format!("invalid RSA key: {e}"))?;

        let signature = Base64UrlUnpadded::decode_vec(signature)
            .map_err(|e| format!("jwt signature: {e}"))?;
        verifying_key
            .verify_pkcs1_sha256(&signature, signed.as_bytes())
            .map_err(|e| format!("jwt validation: signature: {e}"))?;

        // Claims are only trusted after the signature has been checked.
        let claims: Claims = decode_json(claims_b64).map_err(|e| format!("jwt claims: {e}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock: {e}"))?
            .as_secs();
        if claims.exp <= now {
            return Err("jwt validation: token expired".into());
        }
        if claims.nbf.is_some_and(|nbf| nbf > now + NBF_SKEW_SECS) {
            return Err("jwt validation: token not yet valid".into());
        }
        if claims.iss != self.config.issuer {
            return Err(format!("jwt validation: unexpected issuer '{}'", claims.iss));
        }
        let audience_matches = match &claims.aud {
            serde_json::Value::String(aud) => *aud == self.config.audience,
            serde_json::Value::Array(auds) => {
                auds.iter().any(|a| a.as_str() == Some(&self.config.audience))
            }
            _ => false,
        };
        if !audience_matches {
            return Err("jwt validation: audience mismatch".into());
        }

        if !matches_glob(&self.config.subject_pattern, &claims.sub) {
            return Err(format!(
                "sub '{}' does not match '{}'",
                claims.sub, self.config.subject_pattern
            ));
        }

        Ok(())
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, String> {
    let bytes = Base64UrlUnpadded::decode_vec(segment).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Encode a JWK's base64url modulus and exponent as a DER PKCS#1 `RSAPublicKey`.
fn rsa_public_key_der(n_b64: &str, e_b64: &str) -> Result<Vec<u8>, String> {
    let n = Base64UrlUnpadded::decode_vec(n_b64).map_err(|e| format!("RSA n: {e}"))?;
    let e = Base64UrlUnpadded::decode_vec(e_b64).map_err(|e| format!("RSA e: {e}"))?;
    let mut body = Vec::new();
    der_unsigned_integer(&mut body, &n)?;
    der_unsigned_integer(&mut body, &e)?;
    let mut der = vec![0x30];
    der_length(&mut der, body.len());
    der.extend_from_slice(&body);
    Ok(der)
}

/// Append a DER INTEGER holding the big-endian unsigned `value`.
fn der_unsigned_integer(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let start = value.iter().position(|&b| b != 0).ok_or("zero RSA integer")?;
    let value = &value[start..];
    // A leading 0x00 keeps the integer non-negative when the top bit is set.
    let pad = usize::from(value[0] & 0x80 != 0);
    out.push(0x02);
    der_length(out, value.len() + pad);
    out.extend(std::iter::repeat_n(0, pad));
    out.extend_from_slice(value);
    Ok(())
}

fn der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Matches a pattern where a trailing `*` means "any suffix".
fn matches_glob(pattern: &str, s: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => pattern == s,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    // RS256 tokens signed offline with the private half of MODULUS, kid "test-key",
    // issuer https://issuer.test, audience laputa-mirror. VALID expires in 2100.
    const MODULUS: &str = "r4Z1tMkvXnNCE4c4JkzlQ0hjg7gcMa-LVL402qbkG_xPNeNKRJ7_LVSyytnG40eoxzyK9MFpOLky2BaS2h8rUaREJyxE1UGPhbASdrhA1tyNbmU2wbHYEwPVzgHuchBHG0ZjN_KWFGjYnEFE1IkyQb4fADVowyAbph85QhGg3H_wzSa5gUMZYoNFertCNCDProxB9x_OqakkT1C3mYb0SqqO_eTPexs0eO79QD_ZQGFoQbOu_JYFSbyH3UxUEMA9EvPr4w27VhGxB492nwjKzzxasLrJ4W6vTQsl5cwo8G1hukuBgqP9FhslaIuQsw1sUGGd1qsZLe6M25RufP7oXw";
    const VALID: &str = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAidGVzdC1rZXkifQ.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdCIsICJzdWIiOiAicmVwbzpqb3NoL21pcnJvciIsICJhdWQiOiAibGFwdXRhLW1pcnJvciIsICJleHAiOiA0MTAyNDQ0ODAwfQ.f7Tokgt9SXBCNBZywFSoCx4DOAGr-RYplZKgzZ9S2w-RdwJSoBRjwOr0XlvYP8Q5tivpaP0hntm9o3j8dmN9ug6MUKDxnA7bgUgGPshKSIvVf3gbxFVoYm3ixahPV-KX8jHVMH7UBsY8fvIaV0LHzvJ0oLj1HZjN93ZGW8dVyAQuDAvG_WDE5nmNhLA2r1RV3KKIr8uAj4VyEMe3pMxbGIBqWe0KrjPF14vOVOcmsm28Htifts6OqiEwG1lScDpqpuyQN_ms1QuUWKmQ0TlB5oqep9_NpB163ZiCvF08cEv-RCGWDiUAazB0VOPci0Vx-RTiYrMZ8GP5rMMDo2z_WQ";
    const EXPIRED: &str = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAidGVzdC1rZXkifQ.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdCIsICJzdWIiOiAicmVwbzpqb3NoL21pcnJvciIsICJhdWQiOiAibGFwdXRhLW1pcnJvciIsICJleHAiOiAxMDAwMDAwMDAwfQ.AAlDVioYakVa4qjxzs_lWvulY_T1oNhBUIetkcCcsGWgAJpqaghqs5BSuQSQ2B15Mq0F2f6XidBgNV68jSv1W2_fMqUNkEHLvkojfgF-5q2Ecz5E70I2zevoCJgppanI_8ei4n_ctIl_BlEhjDaD1mm2ISZQUGb7GG5Bw12KPnXnm4YWi1OsIjp4Q11eFclQ-MEFBOkrfUMssY-F9rjK88P20amBxAGsdJx3kfixjDLv5P_KeIRYh0usGlIFMZDNO76q2a7GDY9YggFj5f5pvBF6t5sHzEsfdLsq0wO8mEzaHlFuHfJSv3q9abBN56OcyG2QgwCcz68QNfzzE3RA5g";
    const OTHER_SUBJECT: &str = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAidGVzdC1rZXkifQ.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdCIsICJzdWIiOiAicmVwbzpldmlsL3giLCAiYXVkIjogImxhcHV0YS1taXJyb3IiLCAiZXhwIjogNDEwMjQ0NDgwMH0.FepaOQyfCJyo46uVJ3m3UCYnZbEGvxSl14W0TFt3paFTR7EXhfaGHFlBWEkRKI8hoTlxtcKUbAKQVSKQ6NmRO49p5K6n5jb_U9mOUVYVu1iDv0MUoxifp9HSQp3FAwsdSsTlUBmuuMf1ByMepgnilruMGKqsp_Lt1-kO-NGEZs0S_nx2lOC1Wa63iV6qs_T0jZM8pvzR7b9B23TfQx_CUW8IV6qhNWjnGc-oy6LDVyL6qVXc7gNFOzMbKRrDdbjFS1kQlHXnvxQFtPWmEuiOrHgGNFYpiyvzRupoe6dhzxQdmv_vu8q22Nx4j8HfUaLG6z_lzXZ6EJPTSG8BHKqLYQ";

    /// Serves one JWKS document over plain HTTP, once per connection, for `connections` connections.
    fn serve_jwks(connections: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","n":"{MODULUS}","e":"AQAB"}}]}}"#
        );
        std::thread::spawn(move || {
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().unwrap();
                // The client writes the request head in several pieces; reply only after
                // all of it is read, or closing with unread bytes resets the connection.
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut piece = [0_u8; 1024];
                    let read = stream.read(&mut piece).unwrap();
                    request.extend_from_slice(&piece[..read]);
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        url
    }

    fn cache(jwks_url: String) -> JwksCache {
        JwksCache::new(JwtConfig {
            jwks_url,
            issuer: "https://issuer.test".into(),
            audience: "laputa-mirror".into(),
            subject_pattern: "repo:josh/*".into(),
        })
    }

    #[test]
    fn accepts_a_valid_token_from_a_fetched_jwks() {
        cache(serve_jwks(1)).verify(VALID).unwrap();
    }

    #[test]
    fn rejects_expired_tokens() {
        let error = cache(serve_jwks(1)).verify(EXPIRED).unwrap_err();
        assert!(error.starts_with("jwt validation:"), "{error}");
    }

    #[test]
    fn rejects_subjects_outside_the_pattern() {
        let error = cache(serve_jwks(1)).verify(OTHER_SUBJECT).unwrap_err();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn rejects_algorithms_other_than_rs256() {
        // An unsigned `alg: none` token carrying otherwise acceptable claims.
        let (_, claims, _) = {
            let mut parts = VALID.split('.');
            (parts.next(), parts.next().unwrap(), parts.next())
        };
        let header = Base64UrlUnpadded::encode_string(br#"{"alg":"none","kid":"test-key"}"#);
        let error = cache(serve_jwks(1))
            .verify(&format!("{header}.{claims}."))
            .unwrap_err();
        assert!(error.contains("unsupported jwt alg"), "{error}");
    }

    #[test]
    fn rejects_other_audiences_and_issuers() {
        let mut other_audience = cache(serve_jwks(1));
        other_audience.config.audience = "someone-else".into();
        let error = other_audience.verify(VALID).unwrap_err();
        assert!(error.contains("audience"), "{error}");

        let mut other_issuer = cache(serve_jwks(1));
        other_issuer.config.issuer = "https://elsewhere.test".into();
        let error = other_issuer.verify(VALID).unwrap_err();
        assert!(error.contains("issuer"), "{error}");
    }

    #[test]
    fn rejects_a_token_with_a_corrupted_signature() {
        // Alter a character well inside the signature; the final base64 character
        // carries padding bits that a decoder may ignore.
        let (payload, signature) = VALID.rsplit_once('.').unwrap();
        let flipped = if signature.starts_with('A') { 'B' } else { 'A' };
        let token = format!("{payload}.{flipped}{}", &signature[1..]);
        let error = cache(serve_jwks(1)).verify(&token).unwrap_err();
        assert!(error.starts_with("jwt validation:"), "{error}");
    }
}
