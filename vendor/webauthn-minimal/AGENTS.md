# WebAuthn-Minimal

`webauthn-minimal` is a lightweight, pure-Rust implementation of a WebAuthn Relying Party (RP). It is designed for simplicity and ease of integration, focusing on modern passkey support using the P-256/ES256 algorithm.

## Features

- **Passkey Support**: Fully supports discoverable credentials (passkeys).
- **P-256 / ES256 Only**: Focused implementation of the most widely used algorithm for modern authenticators.
- **Flexible Signature Encoding**: Supports both DER-encoded and raw (concatenated R+S) signatures for maximum compatibility with various hardware and platform authenticators.
- **Lightweight Attestation**: 
    - Explicitly supports the `none` attestation format (standard for passkeys).
    - Provides basic structure validation for the `packed` attestation format.
- **AAGUID Tracking**: Extracts and returns the Authenticator Attestation GUID (AAGUID) during registration.
- **Type Safety**: Uses strongly typed request and response structures for registration and authentication ceremonies.
- **TypeScript Integration**: Optional feature for generating TypeScript definitions for the public API.

## Architecture

The crate centers around the `RelyingParty` struct, which manages the configuration and verification logic.

### Core Components

- **`RelyingParty`**: The main entry point. It handles the generation of options for the browser and the verification of the authenticator's responses.
- **`StoredCredential`**: The data structure used to persist a user's public key, credential ID, AAGUID, and signature counter.
- **Challenge State (`RegChallenge`, `AuthChallenge`)**: Minimal state objects designed to be stored in a session or database between the "start" and "finish" phases of a ceremony.

### Demo Frontend Architecture

The `examples/demo` provides a reference implementation using a modern frontend stack:
- **Framework**: Preact (TSX) for a declarative, type-safe UI.
- **Bundler**: esbuild for fast transpilation and minification.
- **Type Sync**: Types are automatically generated from Rust structs using `ts-rs` (via `make types`), ensuring the frontend and backend stay in sync.
- **Deployment**: The Rust server embeds the compiled JS and CSS assets using `include_str!`, allowing the demo to be distributed as a single binary.

### Registration Flow

1. **Start**: `start_registration` generates `PublicKeyCredentialCreationOptions` and a `RegChallenge`.
2. **Client Interaction**: The server sends these options to the client's browser via the WebAuthn API.
3. **Finish**: `finish_registration` receives a `RegistrationResponse`. It:
    - Verifies the `clientDataJSON` (challenge and origin).
    - Parses the `attestationObject` (CBOR).
    - Validates the attestation format (skips for `none`, basic check for `packed`).
    - Parses `authData` to extract the `credId` and P-256 public key.
    - Returns a `StoredCredential` for persistence.

### Authentication Flow

1. **Start**: `start_authentication` generates `PublicKeyCredentialRequestOptions` and an `AuthChallenge`.
2. **Client Interaction**: The server sends these options to the browser.
3. **Finish**: `finish_authentication` receives an `AuthenticationResponse` and the previously `StoredCredential`. It:
    - Verifies the `clientDataJSON` (challenge and origin).
    - Parses `authData` to verify the `rpIdHash` and user presence.
    - Verifies the ES256 signature over `authData || SHA-256(clientDataJSON)`.
    - Handles both DER and raw signature encodings.
    - Checks for signature counter regressions (logging a warning if detected).
    - Returns an updated `StoredCredential` with the new signature counter.

## Design Decisions & Simplifications

- **Algorithm Limitation**: Only ES256 (P-256) is supported. This significantly reduces complexity while remaining compatible with almost all modern passkey authenticators.
- **Minimal Attestation**: Attestation verification is intentionally minimal. While it allows the server to accept any valid credential, it provides the hooks to implement stricter hardware enforcement (e.g., verifying the AAGUID or the attestation statement).
- **Statelessness**: The `RelyingParty` does not manage storage. It provides the data needed to be stored and expects the caller to manage the persistence of challenges and credentials.
- **Constant-Time Comparisons**: Uses constant-time equality checks for challenges to mitigate timing attacks.

## Security Considerations

- **Challenge Management**: Challenges are generated as 32-byte random values.
- **Origin Validation**: Strict validation of the origin in `clientDataJSON` to prevent phishing.
- **Counter Tracking**: Monitors the signature counter to detect possible authenticator cloning.
