//! Pure-Rust WebAuthn relying-party implementation.
//! Supports passkeys (discoverable credentials) with P-256/ES256 only.
//! Accepts any attestation format but does not verify attestation statements;
//! only the credential data from authData is extracted and used.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::{EncodedPoint, FieldBytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
#[cfg(feature = "ts")]
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    InvalidClientData(String),
    ChallengeMismatch,
    OriginMismatch(String),
    InvalidAttestation(String),
    InvalidAuthData(String),
    CredentialNotFound,
    InvalidSignature,
    InvalidPublicKey(String),
    InvalidCoseKey(String),
    DecodeError(String),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClientData(e) => write!(f, "invalid client data: {e}"),
            Self::ChallengeMismatch => write!(f, "challenge mismatch"),
            Self::OriginMismatch(o) => write!(f, "origin mismatch: {o}"),
            Self::InvalidAttestation(e) => write!(f, "invalid attestation: {e}"),
            Self::InvalidAuthData(e) => write!(f, "invalid auth data: {e}"),
            Self::CredentialNotFound => write!(f, "credential not found"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::InvalidPublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::InvalidCoseKey(e) => write!(f, "invalid COSE key: {e}"),
            Self::DecodeError(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for WebAuthnError {}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct RPInfo {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    pub resident_key: String,
    pub require_resident_key: bool,
    pub user_verification: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RPInfo,
    pub user: UserInfo,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u32,
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    pub user_verification: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: RegistrationResponseData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseData {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: AuthenticationResponseData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "ts", derive(TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponseData {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Passkey,     // Resident key required
    HardwareKey, // Resident key discouraged
}

pub struct RelyingParty {
    rp_id: String,
    rp_origin: String,
    rp_name: String,
}

/// Challenge state stored in the session DB during a registration ceremony.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegChallenge {
    pub challenge: String, // base64url-encoded random bytes
    pub user_id: String,
    pub username: String,
}

/// Challenge state stored in the session DB during an authentication ceremony.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthChallenge {
    pub challenge: String, // base64url-encoded random bytes
}

/// A registered passkey credential persisted in the database.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredCredential {
    pub cred_id: Vec<u8>,
    pub aaguid: [u8; 16],
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub sign_count: u32,
}

impl RelyingParty {
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
            rp_name: rp_name.to_string(),
        }
    }

    /// Begin a registration ceremony.
    /// Returns (PublicKeyCredentialCreationOptions, challenge state to store in session).
    pub fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        mode: RegistrationMode,
    ) -> (PublicKeyCredentialCreationOptions, RegChallenge) {
        let challenge_bytes = random_bytes(32);
        let challenge = Base64UrlUnpadded::encode_string(&challenge_bytes);
        let user_id_b64 = Base64UrlUnpadded::encode_string(user_id.as_bytes());

        let (res_key, req_res) = match mode {
            RegistrationMode::Passkey => ("required", true),
            RegistrationMode::HardwareKey => ("discouraged", false),
        };

        let options = PublicKeyCredentialCreationOptions {
            rp: RPInfo {
                id: self.rp_id.clone(),
                name: self.rp_name.clone(),
            },
            user: UserInfo {
                id: user_id_b64,
                name: username.to_string(),
                display_name: username.to_string(),
            },
            challenge: challenge.clone(),
            pub_key_cred_params: vec![PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: -7,
            }],
            timeout: 60000,
            authenticator_selection: AuthenticatorSelection {
                resident_key: res_key.into(),
                require_resident_key: req_res,
                user_verification: "preferred".into(),
            },
            attestation: "none".into(),
        };

        let reg_challenge = RegChallenge {
            challenge,
            user_id: user_id.to_string(),
            username: username.to_string(),
        };

        (options, reg_challenge)
    }

    /// Finish a registration ceremony. Returns the credential to store.
    pub fn finish_registration(
        &self,
        response: &RegistrationResponse,
        state: &RegChallenge,
    ) -> Result<StoredCredential, WebAuthnError> {
        let cdj_bytes = b64url_decode(&response.response.client_data_json)?;
        let cdj: serde_json::Value = serde_json::from_slice(&cdj_bytes)
            .map_err(|e| WebAuthnError::InvalidClientData(format!("clientDataJSON: {e}")))?;

        if cdj["type"].as_str() != Some("webauthn.create") {
            return Err(WebAuthnError::InvalidClientData(
                "wrong clientData type".into(),
            ));
        }
        let got = cdj["challenge"].as_str().ok_or_else(|| {
            WebAuthnError::InvalidClientData("missing challenge in clientData".into())
        })?;
        if !ct_eq(got.as_bytes(), state.challenge.as_bytes()) {
            return Err(WebAuthnError::ChallengeMismatch);
        }
        if cdj["origin"].as_str() != Some(&self.rp_origin) {
            return Err(WebAuthnError::OriginMismatch(format!(
                "{:?}",
                cdj["origin"]
            )));
        }

        let attest_bytes = b64url_decode(&response.response.attestation_object)?;
        let attest: ciborium::value::Value = ciborium::de::from_reader(attest_bytes.as_slice())
            .map_err(|e| {
                WebAuthnError::InvalidAttestation(format!("attestationObject CBOR: {e}"))
            })?;

        let fmt = cbor_get_text(&attest, "fmt").ok_or_else(|| {
            WebAuthnError::InvalidAttestation("missing fmt in attestationObject".into())
        })?;

        let auth_data = cbor_get_bytes(&attest, "authData").ok_or_else(|| {
            WebAuthnError::InvalidAttestation("missing authData in attestationObject".into())
        })?;

        if fmt != "none" {
            verify_attestation_statement(&fmt, &attest, &auth_data, &cdj_bytes)?;
        }

        parse_auth_data_registration(&self.rp_id, &auth_data)
    }

    /// Begin an authentication ceremony.
    /// Returns (PublicKeyCredentialRequestOptions, challenge state to store in session).
    pub fn start_authentication(
        &self,
        credentials: &[StoredCredential],
    ) -> (PublicKeyCredentialRequestOptions, AuthChallenge) {
        let challenge_bytes = random_bytes(32);
        let challenge = Base64UrlUnpadded::encode_string(&challenge_bytes);

        let allow_credentials = credentials
            .iter()
            .map(|c| {
                let id_b64 = Base64UrlUnpadded::encode_string(&c.cred_id);
                AllowCredential {
                    cred_type: "public-key".into(),
                    id: id_b64,
                }
            })
            .collect();

        let options = PublicKeyCredentialRequestOptions {
            challenge: challenge.clone(),
            timeout: 60000,
            rp_id: self.rp_id.clone(),
            allow_credentials,
            user_verification: "preferred".into(),
        };

        let auth_challenge = AuthChallenge { challenge };

        (options, auth_challenge)
    }

    #[allow(deprecated)]
    /// Finish an authentication ceremony.
    /// Returns the matched credential with its sign_count updated to the new value.
    pub fn finish_authentication(
        &self,
        response: &AuthenticationResponse,
        state: &AuthChallenge,
        cred: &StoredCredential,
    ) -> Result<StoredCredential, WebAuthnError> {
        let cdj_bytes = b64url_decode(&response.response.client_data_json)?;
        let cdj: serde_json::Value = serde_json::from_slice(&cdj_bytes)
            .map_err(|e| WebAuthnError::InvalidClientData(format!("clientDataJSON: {e}")))?;

        if cdj["type"].as_str() != Some("webauthn.get") {
            return Err(WebAuthnError::InvalidClientData(
                "wrong clientData type".into(),
            ));
        }
        let got = cdj["challenge"].as_str().ok_or_else(|| {
            WebAuthnError::InvalidClientData("missing challenge in clientData".into())
        })?;
        if !ct_eq(got.as_bytes(), state.challenge.as_bytes()) {
            return Err(WebAuthnError::ChallengeMismatch);
        }
        if cdj["origin"].as_str() != Some(&self.rp_origin) {
            return Err(WebAuthnError::OriginMismatch(format!(
                "{:?}",
                cdj["origin"]
            )));
        }

        let auth_data = b64url_decode(&response.response.authenticator_data)?;
        if auth_data.len() < 37 {
            return Err(WebAuthnError::InvalidAuthData(
                "authenticatorData too short".into(),
            ));
        }
        let rp_id_hash: [u8; 32] = Sha256::digest(self.rp_id.as_bytes()).into();
        if auth_data[..32] != rp_id_hash {
            return Err(WebAuthnError::InvalidAuthData("rpIdHash mismatch".into()));
        }
        if auth_data[32] & 0x01 == 0 {
            return Err(WebAuthnError::InvalidAuthData("user not present".into()));
        }
        let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

        // Verify ES256 signature over authData || SHA-256(clientDataJSON).
        let cdj_hash: [u8; 32] = Sha256::digest(&cdj_bytes).into();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&cdj_hash);

        let sig_bytes = b64url_decode(&response.response.signature)?;
        let point = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&cred.x),
            FieldBytes::from_slice(&cred.y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&point)
            .map_err(|e| WebAuthnError::InvalidPublicKey(format!("invalid public key: {e}")))?;

        let sig = if sig_bytes.len() == 64 {
            Signature::from_slice(&sig_bytes)
                .map_err(|e| WebAuthnError::DecodeError(format!("invalid raw signature: {e}")))?
        } else {
            Signature::from_der(&sig_bytes)
                .map_err(|e| WebAuthnError::DecodeError(format!("invalid DER signature: {e}")))?
        };
        vk.verify(&signed, &sig)
            .map_err(|_| WebAuthnError::InvalidSignature)?;

        // Warn on sign_count regression — indicates possible authenticator cloning.
        // Don't hard-fail: many platform authenticators always return 0.
        if cred.sign_count > 0 && sign_count <= cred.sign_count {
            tracing::warn!(
                cred_id = %hex_encode(&cred.cred_id),
                stored = cred.sign_count,
                received = sign_count,
                "sign_count did not increase — possible authenticator clone"
            );
        }

        Ok(StoredCredential {
            cred_id: cred.cred_id.clone(),
            aaguid: cred.aaguid,
            x: cred.x,
            y: cred.y,
            sign_count,
        })
    }
}

/// Parse authenticatorData during registration, extract credential ID and P-256 public key.
fn parse_auth_data_registration(
    rp_id: &str,
    auth_data: &[u8],
) -> Result<StoredCredential, WebAuthnError> {
    // Layout: [32 rpIdHash][1 flags][4 signCount][attested cred data when AT flag set]
    if auth_data.len() < 37 {
        return Err(WebAuthnError::InvalidAuthData("authData too short".into()));
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth_data[..32] != rp_id_hash {
        return Err(WebAuthnError::InvalidAuthData("rpIdHash mismatch".into()));
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(WebAuthnError::InvalidAuthData("user not present".into()));
    }
    if flags & 0x40 == 0 {
        return Err(WebAuthnError::InvalidAuthData(
            "no attested credential data present".into(),
        ));
    }
    let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

    // Attested credential data: [16 AAGUID][2 credIdLen][N credId][CBOR coseKey]
    let att = &auth_data[37..];
    if att.len() < 18 {
        return Err(WebAuthnError::InvalidAuthData(
            "attested credential data too short".into(),
        ));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&att[..16]);
    let cred_id_len = u16::from_be_bytes([att[16], att[17]]) as usize;
    if att.len() < 18 + cred_id_len {
        return Err(WebAuthnError::InvalidAuthData(
            "credentialId truncated".into(),
        ));
    }
    let cred_id = att[18..18 + cred_id_len].to_vec();

    let cose_bytes = &att[18 + cred_id_len..];
    let (x, y) = parse_cose_p256(cose_bytes)?;

    Ok(StoredCredential {
        cred_id,
        aaguid,
        x,
        y,
        sign_count,
    })
}

/// Parse a COSE_Key map for an EC2/P-256 key (alg=-7), returning (x, y) as 32-byte arrays.
fn parse_cose_p256(data: &[u8]) -> Result<([u8; 32], [u8; 32]), WebAuthnError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(data)
        .map_err(|e| WebAuthnError::InvalidCoseKey(format!("COSE key CBOR: {e}")))?;
    let map = match value {
        ciborium::value::Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidCoseKey(
                "COSE key is not a CBOR map".into(),
            ));
        }
    };

    let mut kty: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x_bytes: Option<Vec<u8>> = None;
    let mut y_bytes: Option<Vec<u8>> = None;

    for (k, v) in map {
        let key_i = match k {
            ciborium::value::Value::Integer(i) => i64::try_from(i).ok(),
            _ => None,
        };
        match key_i {
            Some(1) => {
                kty = if let ciborium::value::Value::Integer(i) = v {
                    i64::try_from(i).ok()
                } else {
                    None
                }
            }
            Some(-1) => {
                crv = if let ciborium::value::Value::Integer(i) = v {
                    i64::try_from(i).ok()
                } else {
                    None
                }
            }
            Some(-2) => {
                if let ciborium::value::Value::Bytes(b) = v {
                    x_bytes = Some(b);
                }
            }
            Some(-3) => {
                if let ciborium::value::Value::Bytes(b) = v {
                    y_bytes = Some(b);
                }
            }
            _ => {}
        }
    }

    if kty != Some(2) {
        return Err(WebAuthnError::InvalidCoseKey(format!(
            "unsupported COSE key type: {kty:?} (expected 2/EC2)"
        )));
    }
    if crv != Some(1) {
        return Err(WebAuthnError::InvalidCoseKey(format!(
            "unsupported COSE curve: {crv:?} (expected 1/P-256)"
        )));
    }

    let x = x_bytes
        .ok_or_else(|| WebAuthnError::InvalidCoseKey("COSE key missing x coordinate".into()))?;
    let y = y_bytes
        .ok_or_else(|| WebAuthnError::InvalidCoseKey("COSE key missing y coordinate".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(WebAuthnError::InvalidCoseKey(format!(
            "unexpected coordinate length: x={}, y={}",
            x.len(),
            y.len()
        )));
    }
    let mut xa = [0u8; 32];
    let mut ya = [0u8; 32];
    xa.copy_from_slice(&x);
    ya.copy_from_slice(&y);
    Ok((xa, ya))
}

/// Extract a text value from a CBOR text-keyed map.
fn cbor_get_text(value: &ciborium::value::Value, key: &str) -> Option<String> {
    let ciborium::value::Value::Map(m) = value else {
        return None;
    };
    for (k, v) in m {
        if matches!(k, ciborium::value::Value::Text(t) if t == key)
            && let ciborium::value::Value::Text(t) = v
        {
            return Some(t.clone());
        }
    }
    None
}

fn verify_attestation_statement(
    fmt: &str,
    attest: &ciborium::value::Value,
    _auth_data: &[u8],
    _cdj_bytes: &[u8],
) -> Result<(), WebAuthnError> {
    let stmt_val = match attest {
        ciborium::value::Value::Map(m) => m
            .iter()
            .find(|(k, _)| matches!(k, ciborium::value::Value::Text(t) if t == "attStmt"))
            .map(|(_, v)| v)
            .ok_or_else(|| WebAuthnError::InvalidAttestation("missing attStmt".into()))?,
        _ => {
            return Err(WebAuthnError::InvalidAttestation(
                "attestationObject is not a map".into(),
            ));
        }
    };

    match fmt {
        "none" => Ok(()),
        "packed" => {
            if let ciborium::value::Value::Map(_) = stmt_val {
                Ok(())
            } else {
                Err(WebAuthnError::InvalidAttestation(
                    "packed attStmt must be a map".into(),
                ))
            }
        }
        _ => Err(WebAuthnError::InvalidAttestation(format!(
            "unsupported attestation format: {fmt}"
        ))),
    }
}

/// Extract a byte-string value from a CBOR text-keyed map.
fn cbor_get_bytes(value: &ciborium::value::Value, key: &str) -> Option<Vec<u8>> {
    let ciborium::value::Value::Map(m) = value else {
        return None;
    };
    for (k, v) in m {
        if matches!(k, ciborium::value::Value::Text(t) if t == key)
            && let ciborium::value::Value::Bytes(b) = v
        {
            return Some(b.clone());
        }
    }
    None
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, WebAuthnError> {
    // Strip any trailing padding — WebAuthn uses unpadded base64url but be permissive.
    Base64UrlUnpadded::decode_vec(s.trim_end_matches('='))
        .map_err(|e| WebAuthnError::DecodeError(format!("base64url decode: {e}")))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    std::io::Read::read_exact(&mut f, &mut buf).expect("read /dev/urandom");
    buf
}

// Constant-time byte slice comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    fn make_rp() -> RelyingParty {
        RelyingParty::new("example.com", "https://example.com", "Example")
    }

    /// A minimal software authenticator backed by a fixed P-256 key.
    struct SoftAuthenticator {
        signing_key: SigningKey,
        cred_id: Vec<u8>,
    }

    impl SoftAuthenticator {
        fn new() -> Self {
            // Scalar value 7 — arbitrary non-zero value well below the P-256 group order.
            let mut key_bytes = [0u8; 32];
            key_bytes[31] = 7;
            Self {
                signing_key: SigningKey::from(SecretKey::from_slice(&key_bytes).unwrap()),
                cred_id: (1u8..=16).collect(),
            }
        }

        fn cred_id_b64(&self) -> String {
            Base64UrlUnpadded::encode_string(&self.cred_id)
        }

        fn make_cose_key(&self) -> Vec<u8> {
            let point = self.signing_key.verifying_key().to_encoded_point(false);
            let x = point.x().unwrap().to_vec();
            let y = point.y().unwrap().to_vec();
            let mut cbor = Vec::new();
            ciborium::ser::into_writer(
                &ciborium::value::Value::Map(vec![
                    (cbor_int(1), cbor_int(2)),  // kty: EC2
                    (cbor_int(3), cbor_int(-7)), // alg: ES256
                    (cbor_int(-1), cbor_int(1)), // crv: P-256,
                    (cbor_int(-2), ciborium::value::Value::Bytes(x)),
                    (cbor_int(-3), ciborium::value::Value::Bytes(y)),
                ]),
                &mut cbor,
            )
            .unwrap();
            cbor
        }

        fn make_auth_data_with_cred(&self, rp_id: &str) -> Vec<u8> {
            let rp_id_hash: [u8; 32] = sha2::Sha256::digest(rp_id.as_bytes()).into();
            let cose_key = self.make_cose_key();
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(0x41); // UP + AT flags
            auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign_count
            auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
            auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&self.cred_id);
            auth_data.extend_from_slice(&cose_key);
            auth_data
        }

        fn registration_response(
            &self,
            rp_id: &str,
            origin: &str,
            challenge: &str,
        ) -> serde_json::Value {
            let auth_data = self.make_auth_data_with_cred(rp_id);

            let mut attest_obj = Vec::new();
            ciborium::ser::into_writer(
                &ciborium::value::Value::Map(vec![
                    (cbor_text("fmt"), cbor_text("none")),
                    (cbor_text("attStmt"), ciborium::value::Value::Map(vec![])),
                    (
                        cbor_text("authData"),
                        ciborium::value::Value::Bytes(auth_data),
                    ),
                ]),
                &mut attest_obj,
            )
            .unwrap();

            let cdj = serde_json::json!({"type": "webauthn.create", "challenge": challenge, "origin": origin});
            let cdj_bytes = serde_json::to_vec(&cdj).unwrap();

            serde_json::json!({
                "id": self.cred_id_b64(),
                "rawId": self.cred_id_b64(),
                "type": "public-key",
                "response": {
                    "clientDataJson": Base64UrlUnpadded::encode_string(&cdj_bytes),
                    "attestationObject": Base64UrlUnpadded::encode_string(&attest_obj),
                }
            })
        }

        fn authentication_response(
            &self,
            rp_id: &str,
            origin: &str,
            challenge: &str,
            sign_count: u32,
        ) -> serde_json::Value {
            let rp_id_hash: [u8; 32] = sha2::Sha256::digest(rp_id.as_bytes()).into();
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(0x05); // UP + UV flags
            auth_data.extend_from_slice(&sign_count.to_be_bytes());

            let cdj = serde_json::json!({"type": "webauthn.get", "challenge": challenge, "origin": origin});
            let cdj_bytes = serde_json::to_vec(&cdj).unwrap();
            let cdj_hash: [u8; 32] = Sha256::digest(&cdj_bytes).into();

            let mut signed = auth_data.clone();
            signed.extend_from_slice(&cdj_hash);

            let sig: Signature = self.signing_key.sign(&signed);
            let sig_der = sig.to_der();

            serde_json::json!({
                "id": self.cred_id_b64(),
                "rawId": self.cred_id_b64(),
                "type": "public-key",
                "response": {
                    "clientDataJson": Base64UrlUnpadded::encode_string(&cdj_bytes),
                    "authenticatorData": Base64UrlUnpadded::encode_string(&auth_data),
                    "signature": Base64UrlUnpadded::encode_string(sig_der.as_bytes()),
                    "userHandle": serde_json::Value::Null,
                }
            })
        }
    }

    fn cbor_int(i: i64) -> ciborium::value::Value {
        ciborium::value::Value::Integer(i.into())
    }

    fn cbor_text(s: &str) -> ciborium::value::Value {
        ciborium::value::Value::Text(s.to_string())
    }

    fn do_register(rp: &RelyingParty, authn: &SoftAuthenticator) -> StoredCredential {
        let (opts, reg_state) = rp.start_registration("uid-1", "alice", RegistrationMode::Passkey);
        let challenge = opts.challenge.clone();
        let response_val =
            authn.registration_response("example.com", "https://example.com", &challenge);
        let response: RegistrationResponse = serde_json::from_value(response_val).unwrap();
        rp.finish_registration(&response, &reg_state).unwrap()
    }

    #[test]
    fn round_trip_registration_then_authentication() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();

        let cred = do_register(&rp, &authn);
        assert_eq!(cred.cred_id, authn.cred_id);
        assert_eq!(cred.sign_count, 0);

        let (auth_opts, auth_state) = rp.start_authentication(std::slice::from_ref(&cred));
        let challenge = auth_opts.challenge.clone();
        let response_val =
            authn.authentication_response("example.com", "https://example.com", &challenge, 1);
        let response: AuthenticationResponse = serde_json::from_value(response_val).unwrap();
        let updated = rp
            .finish_authentication(&response, &auth_state, &cred)
            .unwrap();

        assert_eq!(updated.sign_count, 1);
    }

    #[test]
    fn wrong_challenge_rejected_at_registration() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();
        let (_, reg_state) = rp.start_registration("uid-1", "alice", RegistrationMode::Passkey);
        let response_val =
            authn.registration_response("example.com", "https://example.com", "wrong-challenge");
        let response: RegistrationResponse = serde_json::from_value(response_val).unwrap();
        assert!(rp.finish_registration(&response, &reg_state).is_err());
    }

    #[test]
    fn wrong_challenge_rejected_at_authentication() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();
        let cred = do_register(&rp, &authn);
        let (_, auth_state) = rp.start_authentication(std::slice::from_ref(&cred));
        let response_val = authn.authentication_response(
            "example.com",
            "https://example.com",
            "wrong-challenge",
            1,
        );
        let response: AuthenticationResponse = serde_json::from_value(response_val).unwrap();
        assert!(
            rp.finish_authentication(&response, &auth_state, &cred)
                .is_err()
        );
    }

    #[test]
    fn wrong_origin_rejected() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();
        let (opts, reg_state) = rp.start_registration("uid-1", "alice", RegistrationMode::Passkey);
        let challenge = opts.challenge.clone();
        let response_val =
            authn.registration_response("example.com", "https://evil.example.com", &challenge);
        let response: RegistrationResponse = serde_json::from_value(response_val).unwrap();
        assert!(rp.finish_registration(&response, &reg_state).is_err());
    }

    #[test]
    fn bad_signature_rejected() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();
        let cred = do_register(&rp, &authn);

        // Different key, same cred_id — simulates a forged assertion.
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 99;
        let imposter = SoftAuthenticator {
            signing_key: SigningKey::from(SecretKey::from_slice(&key_bytes).unwrap()),
            cred_id: authn.cred_id.clone(),
        };

        let (auth_opts, auth_state) = rp.start_authentication(std::slice::from_ref(&cred));
        let challenge = auth_opts.challenge.clone();
        let response_val =
            imposter.authentication_response("example.com", "https://example.com", &challenge, 1);
        let response: AuthenticationResponse = serde_json::from_value(response_val).unwrap();
        assert!(
            rp.finish_authentication(&response, &auth_state, &cred)
                .is_err()
        );
    }

    #[test]
    fn wrong_rp_id_rejected() {
        let rp = make_rp();
        let authn = SoftAuthenticator::new();
        let (opts, reg_state) = rp.start_registration("uid-1", "alice", RegistrationMode::Passkey);
        let challenge = opts.challenge.clone();
        // Authenticator hashes a different rp_id into authData.
        let response_val =
            authn.registration_response("attacker.com", "https://example.com", &challenge);
        let response: RegistrationResponse = serde_json::from_value(response_val).unwrap();
        assert!(rp.finish_registration(&response, &reg_state).is_err());
    }
}
