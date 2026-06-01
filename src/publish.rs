use std::path::{Path, PathBuf};

use crate::packages::RemotePackage;
use crate::s3;

const CHUNK_SIZE: usize = 25 * 1024 * 1024;
const CHUNK_UPLOAD_THRESHOLD: u64 = 50 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishUpload {
    pub rel: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PublishPlan {
    pub uploads: Vec<PublishUpload>,
    pub index_json: Vec<u8>,
    pub index: Vec<RemotePackage>,
}

impl PublishPlan {
    pub fn upload_order(&self) -> Vec<String> {
        let mut order: Vec<String> = self.uploads.iter().map(|u| u.rel.clone()).collect();
        order.push("index.json".to_string());
        order
    }
}

pub fn prepare_publish(repo_dir: &Path) -> Result<PublishPlan, String> {
    let index_path = repo_dir.join("index.json");
    let index_bytes =
        std::fs::read(&index_path).map_err(|e| format!("read {}: {e}", index_path.display()))?;
    let mut index: Vec<RemotePackage> = serde_json::from_slice(&index_bytes)
        .map_err(|e| format!("parse {}: {e}", index_path.display()))?;

    let mut uploads = Vec::new();
    for entry in &mut index {
        if !entry.metapackage {
            if entry.tarball.is_empty() {
                return Err(format!("{} has no tarball path", entry.name));
            }
            let tarball = repo_dir.join(&entry.tarball);
            let bytes =
                std::fs::read(&tarball).map_err(|e| format!("read {}: {e}", tarball.display()))?;
            entry.sha256 = s3::sha256_hex(&bytes);
            entry.size = bytes.len() as u64;
            uploads.push(PublishUpload {
                rel: entry.tarball.clone(),
                path: tarball,
            });

            let default_metadata = format!(
                "metadata/{}/{}/{}-{}-{}.json",
                entry.arch, entry.name, entry.name, entry.ver, entry.rel
            );
            if entry.metadata.is_empty() && repo_dir.join(&default_metadata).exists() {
                entry.metadata = default_metadata;
            }
            if !entry.metadata.is_empty() {
                let metadata = repo_dir.join(&entry.metadata);
                std::fs::read(&metadata)
                    .map_err(|e| format!("read {}: {e}", metadata.display()))?;
                uploads.push(PublishUpload {
                    rel: entry.metadata.clone(),
                    path: metadata,
                });
            }
        }

        let mirror = repo_dir
            .join(".out")
            .join("source-mirrors")
            .join(format!("{}-{}-{}.tar.gz", entry.name, entry.ver, entry.rel));
        if mirror.exists() {
            let bytes =
                std::fs::read(&mirror).map_err(|e| format!("read {}: {e}", mirror.display()))?;
            let rel = format!(
                "sources/{}/{}-{}-{}-src.tar.gz",
                entry.name, entry.name, entry.ver, entry.rel
            );
            entry.source_sha256 = s3::sha256_hex(&bytes);
            entry.source_tarball = rel.clone();
            uploads.push(PublishUpload { rel, path: mirror });
        }
    }

    index.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.arch.cmp(&b.arch)));
    let index_json = serde_json::to_vec_pretty(&index).map_err(|e| format!("encode index: {e}"))?;

    Ok(PublishPlan {
        uploads,
        index_json,
        index,
    })
}

pub fn publish_repo(repo_dir: &Path, mirror_url: &str, token: &str) -> Result<(), String> {
    let plan = prepare_publish(repo_dir)?;
    for upload in &plan.uploads {
        put_file(mirror_url, token, &upload.rel, &upload.path)?;
    }
    put_bytes(mirror_url, token, "index.json", &plan.index_json)?;
    Ok(())
}

fn put_file(mirror_url: &str, token: &str, rel: &str, path: &Path) -> Result<(), String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if size > CHUNK_UPLOAD_THRESHOLD && !mirror_url.starts_with("file://") {
        return put_file_chunked(mirror_url, token, rel, path);
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    put_bytes(mirror_url, token, rel, &bytes)
}

fn put_file_chunked(mirror_url: &str, token: &str, rel: &str, path: &Path) -> Result<(), String> {
    let upload_id = uuid::Uuid::new_v4().to_string();
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunks = 0usize;

    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        put_bytes(
            mirror_url,
            token,
            &format!("_uploads/{upload_id}/{chunks}"),
            &buffer[..read],
        )?;
        chunks += 1;
    }

    let body = serde_json::json!({
        "rel": rel,
        "chunks": chunks,
    })
    .to_string();
    post_bytes(
        mirror_url,
        token,
        &format!("_uploads/{upload_id}/complete"),
        body.as_bytes(),
    )
}

fn put_bytes(mirror_url: &str, token: &str, rel: &str, bytes: &[u8]) -> Result<(), String> {
    if let Some(root) = mirror_url.strip_prefix("file://") {
        let dest = Path::new(root).join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
        return Ok(());
    }

    let url = format!("{}/{}", mirror_url.trim_end_matches('/'), rel);
    let mut response = ureq::Agent::new_with_defaults()
        .put(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send(bytes)
        .map_err(|e| format!("PUT {url}: {e}"))?;
    let status: u16 = response.status().into();
    if !(200..300).contains(&status) {
        let mut message = String::new();
        let _ = std::io::Read::read_to_string(&mut response.body_mut().as_reader(), &mut message);
        return Err(format!("PUT {url}: HTTP {status} {message}"));
    }
    Ok(())
}

fn post_bytes(mirror_url: &str, token: &str, rel: &str, bytes: &[u8]) -> Result<(), String> {
    let url = format!("{}/{}", mirror_url.trim_end_matches('/'), rel);
    let mut response = ureq::Agent::new_with_defaults()
        .post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(bytes)
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status: u16 = response.status().into();
    if !(200..300).contains(&status) {
        let mut message = String::new();
        let _ = std::io::Read::read_to_string(&mut response.body_mut().as_reader(), &mut message);
        return Err(format!("POST {url}: HTTP {status} {message}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "laputa-mirror-test-{name}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn write(&self, rel: &str, bytes: &[u8]) {
            let path = self.path.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn sample_entry() -> RemotePackage {
        RemotePackage {
            arch: "aarch64".to_string(),
            name: "zlib".to_string(),
            ver: "1.3.2".to_string(),
            rel: "5".to_string(),
            deps: vec!["musl".to_string()],
            mkdeps: vec!["cmake".to_string()],
            sha256: String::new(),
            size: 0,
            tarball: "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz".to_string(),
            metadata: String::new(),
            source_sha256: String::new(),
            source_tarball: String::new(),
            metapackage: false,
        }
    }

    #[test]
    fn source_mirror_maps_to_pm_source_path() {
        let dir = TestDir::new("source-map");
        dir.write("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz", b"pkg");
        dir.write(".out/source-mirrors/zlib-1.3.2-5.tar.gz", b"src");
        dir.write(
            "index.json",
            serde_json::to_vec(&vec![sample_entry()])
                .unwrap()
                .as_slice(),
        );

        let plan = prepare_publish(&dir.path).unwrap();
        assert_eq!(
            plan.index[0].source_tarball,
            "sources/zlib/zlib-1.3.2-5-src.tar.gz"
        );
        assert_eq!(plan.index[0].source_sha256, s3::sha256_hex(b"src"));
    }

    #[test]
    fn package_checksum_and_size_are_refreshed() {
        let dir = TestDir::new("checksum");
        dir.write(
            "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
            b"package bytes",
        );
        dir.write(
            "index.json",
            serde_json::to_vec(&vec![sample_entry()])
                .unwrap()
                .as_slice(),
        );

        let plan = prepare_publish(&dir.path).unwrap();
        assert_eq!(plan.index[0].sha256, s3::sha256_hex(b"package bytes"));
        assert_eq!(plan.index[0].size, 13);
    }

    #[test]
    fn upload_order_puts_index_last() {
        let dir = TestDir::new("order");
        dir.write("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz", b"pkg");
        dir.write("metadata/aarch64/zlib/zlib-1.3.2-5.json", b"{}");
        dir.write(".out/source-mirrors/zlib-1.3.2-5.tar.gz", b"src");
        dir.write(
            "index.json",
            serde_json::to_vec(&vec![sample_entry()])
                .unwrap()
                .as_slice(),
        );

        let plan = prepare_publish(&dir.path).unwrap();
        assert_eq!(
            plan.upload_order(),
            vec![
                "packages/aarch64/zlib/zlib-1.3.2-5.tar.gz",
                "metadata/aarch64/zlib/zlib-1.3.2-5.json",
                "sources/zlib/zlib-1.3.2-5-src.tar.gz",
                "index.json",
            ]
        );

        let out = TestDir::new("published");
        publish_repo(
            &dir.path,
            &format!("file://{}", out.path.display()),
            "unused",
        )
        .unwrap();

        assert!(
            out.path
                .join("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz")
                .exists()
        );
        assert!(
            out.path
                .join("metadata/aarch64/zlib/zlib-1.3.2-5.json")
                .exists()
        );
        assert!(
            out.path
                .join("sources/zlib/zlib-1.3.2-5-src.tar.gz")
                .exists()
        );
        assert!(out.path.join("index.json").exists());
    }

    #[test]
    fn missing_package_artifact_fails() {
        let dir = TestDir::new("missing");
        dir.write(
            "index.json",
            serde_json::to_vec(&vec![sample_entry()])
                .unwrap()
                .as_slice(),
        );

        let err = prepare_publish(&dir.path).unwrap_err();
        assert!(err.contains("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz"));
    }

    #[test]
    fn missing_declared_metadata_fails() {
        let dir = TestDir::new("missing-metadata");
        dir.write("packages/aarch64/zlib/zlib-1.3.2-5.tar.gz", b"pkg");
        let mut entry = sample_entry();
        entry.metadata = "metadata/aarch64/zlib/zlib-1.3.2-5.json".to_string();
        dir.write(
            "index.json",
            serde_json::to_vec(&vec![entry]).unwrap().as_slice(),
        );

        let err = prepare_publish(&dir.path).unwrap_err();
        assert!(err.contains("metadata/aarch64/zlib/zlib-1.3.2-5.json"));
    }
}
