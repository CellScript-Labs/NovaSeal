use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

const IPC_BLOB_LEN: usize = 144;
const IPC_WORD_COUNT: usize = 18;

fn decode(case: &Map<String, Value>) -> Result<Vec<u8>> {
    let text = case.get("ipc_blob").and_then(Value::as_str).context("ipc_blob must be hex")?;
    Ok(hex::decode(text.strip_prefix("0x").unwrap_or(text))?)
}

fn parse(blob: &[u8]) -> (bool, Option<&'static str>) {
    if blob.len() != IPC_BLOB_LEN {
        return (false, Some("blob_length"));
    }
    if &blob[..8] != b"NSBV0IPC" {
        return (false, Some("magic"));
    }
    if u16::from_le_bytes([blob[8], blob[9]]) != 0 {
        return (false, Some("version"));
    }
    if u16::from_le_bytes([blob[10], blob[11]]) != 1 {
        return (false, Some("scheme"));
    }
    if u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) != 0 {
        return (false, Some("flags"));
    }
    (true, None)
}

fn verify(blob: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&blob[48..80]) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(&blob[80..144]) else {
        return false;
    };
    key.verify_prehash(&blob[16..48], &signature).is_ok()
}

fn decision(case: &Map<String, Value>) -> Result<Value> {
    let blob = decode(case)?;
    let words = blob.chunks_exact(8).map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap())).collect::<Vec<_>>();
    let partial = blob.len() % 8;
    let canonical = words.len() == IPC_WORD_COUNT && partial == 0;
    let roundtrip = canonical && words.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<_>>() == blob;
    let expected = case.get("expected").cloned().unwrap_or(Value::Null);
    let expected_accept = expected.as_str() == Some("accept");
    let id = case.get("id").cloned().unwrap_or(Value::Null);
    if !canonical {
        return Ok(json!({
            "id": id,
            "parsed": false,
            "accepted": false,
            "expected": expected,
            "matched_expected": !expected_accept,
            "exit_code": 11,
            "spawn_words_representable": partial == 0,
            "spawn_word_count": words.len(),
            "partial_tail_bytes": partial,
            "spawn_word_roundtrip": roundtrip,
            "spawn_entry_exit_code": 11,
            "reason": if partial > 0 { "partial_tail" } else { "word_count" }
        }));
    }
    let (parsed, failure) = parse(&blob);
    if parsed {
        let accepted = verify(&blob);
        let exit_code = if accepted { 0 } else { 12 };
        return Ok(json!({
            "id": id,
            "parsed": true,
            "accepted": accepted,
            "expected": expected,
            "matched_expected": accepted == expected_accept,
            "exit_code": exit_code,
            "spawn_words_representable": true,
            "spawn_word_count": words.len(),
            "partial_tail_bytes": partial,
            "spawn_word_roundtrip": roundtrip,
            "spawn_entry_exit_code": exit_code,
            "reason": if accepted { "accepted" } else { "crypto_reject" }
        }));
    }
    Ok(json!({
        "id": id,
        "parsed": false,
        "accepted": false,
        "expected": expected,
        "matched_expected": !expected_accept,
        "exit_code": 10,
        "spawn_words_representable": true,
        "spawn_word_count": words.len(),
        "partial_tail_bytes": partial,
        "spawn_word_roundtrip": roundtrip,
        "spawn_entry_exit_code": 10,
        "reason": failure
    }))
}

fn count(decisions: &[Value], predicate: impl Fn(&Value) -> bool) -> usize {
    decisions.iter().filter(|decision| predicate(decision)).count()
}

fn build(source_path: &Path, display_path: &Path) -> Result<Value> {
    let source: Value = serde_json::from_slice(&fs::read(source_path)?)?;
    let normal = source.get("vectors").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let malformed = source.get("malformed").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let decisions = normal
        .iter()
        .chain(malformed)
        .map(|case| decision(case.as_object().context("IPC vector must be an object")?))
        .collect::<Result<Vec<_>>>()?;
    let parsed = count(&decisions, |value| value["parsed"] == true);
    let parse_rejected = decisions.len() - parsed;
    let accepted = count(&decisions, |value| value["accepted"] == true);
    let crypto_rejects = count(&decisions, |value| value["reason"] == "crypto_reject");
    let representable = count(&decisions, |value| value["spawn_words_representable"] == true);
    let roundtrip = count(&decisions, |value| value["spawn_word_roundtrip"] == true);
    let spawn_io_rejects = count(&decisions, |value| value["spawn_entry_exit_code"] == 11);
    let matched = count(&decisions, |value| value["matched_expected"] == true);
    let expected_accept = count(&decisions, |value| value["expected"] == "accept");
    let expected_reject = count(&decisions, |value| value["expected"] == "reject");
    Ok(json!({
        "schema": "novaseal-btc-verifier-shell-report-v0.2",
        "shell_crate": "verifier/novaseal_btc_verifier_riscv",
        "source_ipc_vectors": display_path.to_string_lossy().replace('\\', "/"),
        "classification": "spawn_word_input_bip340_riscv_shell_evidence",
        "spawn_input": {"fd_index": 0, "word_count": 18, "word_width_bytes": 8, "blob_len": 144, "endianness": "little"},
        "exit_codes": {"accept": 0, "reject_envelope": 10, "reject_spawn_io": 11, "reject_crypto": 12},
        "summary": {
            "total_vectors": decisions.len(),
            "well_formed_vectors": normal.len(),
            "malformed_vectors": malformed.len(),
            "expected_accept": expected_accept,
            "expected_reject": expected_reject,
            "parse_ok": parsed,
            "parse_rejected": parse_rejected,
            "accepted": accepted,
            "rejected": decisions.len() - accepted,
            "crypto_rejects": crypto_rejects,
            "spawn_word_representable": representable,
            "spawn_word_roundtrip": roundtrip,
            "spawn_io_rejects": spawn_io_rejects,
            "matched_expected": matched,
            "all_expected_matched": matched == decisions.len()
        },
        "decisions": decisions,
        "limits": [
            "Model-level shell report; it mirrors the no-std shell policy and the fixed u64 spawn-word adapter.",
            "The RISC-V entry requires inherited fd index 0 to contain exactly 18 little-endian u64 words, but this report does not execute CKB VM spawn.",
            "This report does not produce cycle, binary-size, or child-verifier CKB VM evidence; use the RISC-V artifact and ckb-vm harness reports for that."
        ]
    }))
}

pub fn run(root: &Path, source: Option<&Path>, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let source_display = source.unwrap_or(Path::new("target/novaseal-btc-verifier-ipc-vectors.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-btc-verifier-shell-report.json"));
    let report = build(&package_path(root, source_display), source_display)?;
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(&output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    let matched_text = if summary["all_expected_matched"] == true { "True" } else { "False" };
    println!(
        "summary: total={} parse_ok={} parse_rejected={} accepted={} rejected={} matched_expected={} spawn_word_roundtrip={} all_expected_matched={}",
        summary["total_vectors"],
        summary["parse_ok"],
        summary["parse_rejected"],
        summary["accepted"],
        summary["rejected"],
        summary["matched_expected"],
        summary["spawn_word_roundtrip"],
        matched_text
    );
    Ok(if summary["all_expected_matched"] == true { 0 } else { 1 })
}
