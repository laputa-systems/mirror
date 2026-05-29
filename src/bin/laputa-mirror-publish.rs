use std::path::PathBuf;

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let repo_dir = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: laputa-mirror-publish REPO_DIR".to_string())?;
    if args.next().is_some() {
        return Err("usage: laputa-mirror-publish REPO_DIR".to_string());
    }

    let mirror_url = env_required("LAPUTA_MIRROR_URL")?;
    let token = env_required("LAPUTA_MIRROR_TOKEN")?;
    laputa_mirror::publish::publish_repo(&repo_dir, &mirror_url, &token)
}

fn env_required(key: &str) -> Result<String, String> {
    let value = std::env::var(key).map_err(|_| format!("{key} must be set"))?;
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    Ok(trimmed)
}
