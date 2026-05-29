use std::fs::File;
use std::io::Write;
use ts_rs::{Config, TS};
use webauthn_minimal::*;

fn main() {
    let output_path =
        std::env::var("TS_OUTPUT_PATH").unwrap_or_else(|_| "examples/demo/ts/types.ts".to_string());
    let mut output = File::create(&output_path).expect("failed to create types file");
    let cfg = Config::default();

    let content = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        RPInfo::export_to_string(&cfg).expect("failed to export RPInfo"),
        UserInfo::export_to_string(&cfg).expect("failed to export UserInfo"),
        PubKeyCredParam::export_to_string(&cfg).expect("failed to export PubKeyCredParam"),
        AuthenticatorSelection::export_to_string(&cfg)
            .expect("failed to export AuthenticatorSelection"),
        PublicKeyCredentialCreationOptions::export_to_string(&cfg)
            .expect("failed to export PublicKeyCredentialCreationOptions"),
        AllowCredential::export_to_string(&cfg).expect("failed to export AllowCredential"),
        PublicKeyCredentialRequestOptions::export_to_string(&cfg)
            .expect("failed to export PublicKeyCredentialRequestOptions"),
    );

    // Remove imports because we are concatenating everything into a single file
    let filtered_content: String = content
        .lines()
        .filter(|line| !line.trim().starts_with("import type"))
        .collect::<Vec<_>>()
        .join("\n");

    output
        .write_all(filtered_content.as_bytes())
        .expect("failed to write types");
}
