use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake2b_ref::Blake2bBuilder;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn root(override_root: Option<&Path>) -> Result<PathBuf> {
    let root =
        override_root.map(Path::to_path_buf).unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf());
    fs::canonicalize(&root).with_context(|| format!("failed to resolve NovaSeal root {}", root.display()))
}

pub fn package_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join("v0-mvp-skeleton").join(path)
    }
}

pub fn json_text(value: &Value, pretty: bool) -> Result<String> {
    let mut text = if pretty { serde_json::to_string_pretty(value)? } else { serde_json::to_string(value)? };
    text.push('\n');
    Ok(text)
}

pub fn print_artifact_identity(path: &Path) -> Result<i32> {
    let payload = fs::read(path).with_context(|| format!("failed to read artifact {}", path.display()))?;
    let mut data_hash = [0_u8; 32];
    let mut hasher = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    hasher.update(&payload);
    hasher.finalize(&mut data_hash);
    println!("artifact={}", path.display());
    println!("size_bytes={}", payload.len());
    println!("sha256={}", hex::encode(Sha256::digest(&payload)));
    println!("ckb_data_hash=0x{}", hex::encode(data_hash));
    Ok(0)
}
