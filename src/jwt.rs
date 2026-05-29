use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    // aud can be a string or array in practice
    pub aud: serde_json::Value,
    pub exp: u64,
}

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
        let agent = ureq::Agent::new_with_defaults();
        let mut resp = agent
            .get(&self.config.jwks_url)
            .call()
            .map_err(|e| format!("jwks fetch: {e}"))?;
        let mut body = String::new();
        std::io::Read::read_to_string(&mut resp.body_mut().as_reader(), &mut body)
            .map_err(|e| format!("jwks read: {e}"))?;
        let parsed: JwksResponse =
            serde_json::from_str(&body).map_err(|e| format!("jwks parse: {e}"))?;
        self.keys = parsed.keys;
        self.fetched_at = std::time::Instant::now();
        tracing::info!("refreshed JWKS ({} keys)", self.keys.len());
        Ok(())
    }

    /// Verify a JWT token against the cached JWKS, refreshing if stale.
    pub fn verify(&mut self, token: &str) -> Result<Claims, String> {
        if self.needs_refresh() {
            self.refresh()?;
        }

        let header = jsonwebtoken::decode_header(token).map_err(|e| format!("jwt header: {e}"))?;

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
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
            .map_err(|e| format!("invalid RSA key: {e}"))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| format!("jwt validation: {e}"))?;

        if !matches_glob(&self.config.subject_pattern, &data.claims.sub) {
            return Err(format!(
                "sub '{}' does not match '{}'",
                data.claims.sub, self.config.subject_pattern
            ));
        }

        Ok(data.claims)
    }
}

/// Matches a pattern where a trailing `*` means "any suffix".
fn matches_glob(pattern: &str, s: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => pattern == s,
    }
}
