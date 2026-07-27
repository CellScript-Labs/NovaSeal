use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

const IPC_MAGIC: &[u8; 8] = b"NSBV0IPC";
const IPC_BLOB_LEN: usize = 144;

fn fixed_hex(value: Option<&Value>, length: usize, context: &str) -> Result<Vec<u8>> {
    let text = value.and_then(Value::as_str).with_context(|| format!("{context} must be hex"))?;
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))?;
    if bytes.len() != length {
        bail!("expected {length} bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

fn build_blob(case: &Map<String, Value>) -> Result<Vec<u8>> {
    let mut blob = Vec::with_capacity(IPC_BLOB_LEN);
    blob.extend_from_slice(IPC_MAGIC);
    blob.extend_from_slice(&0_u16.to_le_bytes());
    blob.extend_from_slice(&1_u16.to_le_bytes());
    blob.extend_from_slice(&0_u32.to_le_bytes());
    blob.extend_from_slice(&fixed_hex(case.get("message32"), 32, "message32")?);
    blob.extend_from_slice(&fixed_hex(case.get("xonly_pubkey"), 32, "xonly_pubkey")?);
    blob.extend_from_slice(&fixed_hex(case.get("signature64"), 64, "signature64")?);
    if blob.len() != IPC_BLOB_LEN {
        bail!("internal IPC blob size mismatch: {}", blob.len());
    }
    Ok(blob)
}

fn vector(case: &Map<String, Value>) -> Result<Value> {
    let blob = build_blob(case)?;
    Ok(json!({
        "id": case.get("id").cloned().unwrap_or(Value::Null),
        "fixture": case.get("fixture").cloned().unwrap_or(Value::Null),
        "source_case": case.get("case").cloned().unwrap_or(Value::Null),
        "expected": case.get("expected").cloned().unwrap_or(Value::Null),
        "ipc_blob": format!("0x{}", hex::encode(&blob)),
        "ipc_blob_len": blob.len(),
        "message32": case.get("message32").cloned().unwrap_or(Value::Null),
        "xonly_pubkey": case.get("xonly_pubkey").cloned().unwrap_or(Value::Null),
        "signature64": case.get("signature64").cloned().unwrap_or(Value::Null)
    }))
}

fn malformed(seed: &[u8]) -> Vec<Value> {
    let mut wrong_magic = seed.to_vec();
    wrong_magic[0] ^= 1;
    let mut wrong_version = seed.to_vec();
    wrong_version[8..10].copy_from_slice(&1_u16.to_le_bytes());
    let mut wrong_scheme = seed.to_vec();
    wrong_scheme[10..12].copy_from_slice(&2_u16.to_le_bytes());
    let mut nonzero_flags = seed.to_vec();
    nonzero_flags[12..16].copy_from_slice(&1_u32.to_le_bytes());
    let truncated = seed[..seed.len() - 1].to_vec();
    let mut trailing = seed.to_vec();
    trailing.extend_from_slice(b"NSBVTW00");
    [
        ("malformed:wrong_magic", "first magic byte flipped", wrong_magic),
        ("malformed:unsupported_version", "version set to 1", wrong_version),
        ("malformed:unsupported_scheme", "scheme set to 2", wrong_scheme),
        ("malformed:nonzero_flags", "flags set to 1", nonzero_flags),
        ("malformed:truncated", "final byte removed", truncated),
        ("malformed:trailing_word", "one complete trailing u64 word appended after the fixed IPC envelope", trailing),
    ]
    .into_iter()
    .map(|(id, mutation, blob)| {
        json!({
            "id": id,
            "mutation": mutation,
            "expected": "reject",
            "ipc_blob": format!("0x{}", hex::encode(&blob)),
            "ipc_blob_len": blob.len()
        })
    })
    .collect()
}

fn build(source_path: &Path, display_path: &Path) -> Result<Value> {
    let source: Value = serde_json::from_slice(&fs::read(source_path)?)?;
    let positive = source.get("positive").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let negative = source.get("negative").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let mut vectors = Vec::new();
    for case in positive.iter().chain(negative) {
        vectors.push(vector(case.as_object().context("BTC verifier vector must be an object")?)?);
    }
    if vectors.is_empty() {
        bail!("source BTC verifier vector report contains no vectors");
    }
    let seed = fixed_hex(vectors[0].get("ipc_blob"), IPC_BLOB_LEN, "ipc_blob")?;
    let malformed = malformed(&seed);
    let expected_accept = vectors.iter().filter(|case| case.get("expected").and_then(Value::as_str) == Some("accept")).count();
    let expected_reject =
        vectors.iter().chain(&malformed).filter(|case| case.get("expected").and_then(Value::as_str) == Some("reject")).count();
    Ok(json!({
        "schema": "novaseal-btc-verifier-ipc-vectors-v0.1",
        "source_vector_report": display_path.to_string_lossy().replace('\\', "/"),
        "ipc_contract": {
            "magic_ascii": "NSBV0IPC",
            "version": 0,
            "scheme_bip340": 1,
            "flags": 0,
            "endianness": "little",
            "blob_len": IPC_BLOB_LEN,
            "layout": [
                {"field": "magic", "offset": 0, "size": 8},
                {"field": "version_u16_le", "offset": 8, "size": 2},
                {"field": "scheme_u16_le", "offset": 10, "size": 2},
                {"field": "flags_u32_le", "offset": 12, "size": 4},
                {"field": "message32", "offset": 16, "size": 32},
                {"field": "xonly_pubkey", "offset": 48, "size": 32},
                {"field": "signature64", "offset": 80, "size": 64}
            ]
        },
        "vectors": vectors,
        "malformed": malformed,
        "summary": {
            "source_positive": positive.len(),
            "source_negative": negative.len(),
            "ipc_vectors": vectors.len(),
            "malformed_vectors": malformed.len(),
            "total_vectors": vectors.len() + malformed.len(),
            "expected_accept": expected_accept,
            "expected_reject": expected_reject,
            "classification": "fixed_ipc_envelope_vectors"
        },
        "limits": [
            "Host-verifier IPC evidence only; no CKB spawn execution.",
            "No RISC-V verifier binary is built by this script.",
            "The .cell lock now constructs this blob for the RISC-V BIP340 shell; this script still does not execute CKB spawn."
        ]
    }))
}

pub fn run(root: &Path, source: Option<&Path>, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let source_display = source.unwrap_or(Path::new("target/novaseal-btc-verifier-vectors.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-btc-verifier-ipc-vectors.json"));
    let report = build(&package_path(root, source_display), source_display)?;
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(&output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: ipc_vectors={} malformed={} total={} expected_accept={} expected_reject={}",
        summary["ipc_vectors"],
        summary["malformed_vectors"],
        summary["total_vectors"],
        summary["expected_accept"],
        summary["expected_reject"]
    );
    Ok(0)
}
