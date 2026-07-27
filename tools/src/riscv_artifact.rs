use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::shared::{json_text, package_path};

fn compact(value: &Value, keys: &[&str]) -> Value {
    let mut result = Map::new();
    if let Some(source) = value.as_object() {
        for key in keys {
            if let Some(value) = source.get(*key) {
                result.insert((*key).to_owned(), value.clone());
            }
        }
    }
    Value::Object(result)
}

fn file_info(path: &Path, display: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("missing ELF input: {}", display.display()))?;
    Ok(json!({
        "path": display.to_string_lossy().replace('\\', "/"),
        "size_bytes": bytes.len(),
        "sha256": hex::encode(Sha256::digest(bytes))
    }))
}

fn spawn_records(audit: &Value) -> Value {
    let mut plans = Vec::new();
    for record in audit.get("proof_plan").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let haystack = serde_json::to_string(record).unwrap_or_default();
        if haystack.contains("spawn") || haystack.contains("btc-verifier") || haystack.contains("bip340") {
            plans.push(compact(
                record,
                &["origin", "category", "feature", "status", "codegen_coverage_status", "on_chain_checked", "detail"],
            ));
        }
    }
    let mut accesses = Vec::new();
    for section in ["actions", "locks"] {
        for entry in audit.get(section).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            for access in entry.get("runtime_accesses").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
                let haystack = serde_json::to_string(access).unwrap_or_default();
                if haystack.contains("spawn") || haystack.contains("pipe") || haystack.contains("wait") {
                    let mut row = access.as_object().cloned().unwrap_or_default();
                    row.insert("entry_section".into(), json!(section));
                    row.insert("entry_name".into(), entry.get("name").cloned().unwrap_or(Value::Null));
                    accesses.push(Value::Object(row));
                }
            }
        }
    }
    json!({
        "generated_spawn_or_crypto_proof_plan_records": plans,
        "generated_spawn_or_pipe_runtime_accesses": accesses,
        "proof_plan_record_count": plans.len(),
        "runtime_access_count": accesses.len()
    })
}

fn shell_summary(report: &Value) -> Value {
    json!({
        "classification": report.get("classification").cloned().unwrap_or(Value::Null),
        "summary": compact(
            report.get("summary").unwrap_or(&Value::Null),
            &[
                "total_vectors", "parse_ok", "parse_rejected", "spawn_word_representable", "spawn_word_roundtrip",
                "spawn_io_rejects", "accepted", "rejected", "expected_accept", "expected_reject", "matched_expected",
                "all_expected_matched"
            ]
        ),
        "spawn_input": compact(
            report.get("spawn_input").unwrap_or(&Value::Null),
            &["fd_index", "word_count", "word_width_bytes", "blob_len", "endianness"]
        ),
        "exit_codes": compact(
            report.get("exit_codes").unwrap_or(&Value::Null),
            &["accept", "reject_crypto", "reject_envelope", "reject_spawn_io"]
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    root: &Path,
    release: Option<&Path>,
    staged: Option<&Path>,
    staged_sha: Option<&Path>,
    shell: Option<&Path>,
    audit: Option<&Path>,
    output: Option<&Path>,
    sync: bool,
    pretty: bool,
) -> Result<i32> {
    let release_display = release.unwrap_or(Path::new(
        "verifier/novaseal_btc_verifier_riscv/target/riscv64imac-unknown-none-elf/release/novaseal_btc_verifier_riscv",
    ));
    let staged_display = staged.unwrap_or(Path::new("target/novaseal-btc-verifier-riscv-shell-release.elf"));
    let staged_sha_display = staged_sha.unwrap_or(Path::new("target/novaseal-btc-verifier-riscv-shell-release.elf.sha256"));
    let shell_display = shell.unwrap_or(Path::new("target/novaseal-btc-verifier-shell-report.json"));
    let audit_display = audit.unwrap_or(Path::new("target/novaseal-audit-surface.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-riscv-shell-artifact.json"));
    let release_path = package_path(root, release_display);
    let staged_path = package_path(root, staged_display);
    let staged_sha_path = package_path(root, staged_sha_display);
    if sync {
        fs::create_dir_all(staged_path.parent().context("staged ELF path has no parent")?)?;
        fs::copy(&release_path, &staged_path)?;
    }
    let release_info = file_info(&release_path, release_display)?;
    let staged_info = file_info(&staged_path, staged_display)?;
    let matches = release_info["size_bytes"] == staged_info["size_bytes"] && release_info["sha256"] == staged_info["sha256"];
    if sync {
        fs::write(&staged_sha_path, format!("{}  {}\n", staged_info["sha256"].as_str().unwrap(), staged_display.display()))?;
    }
    let shell_report: Value = serde_json::from_slice(&fs::read(package_path(root, shell_display))?)?;
    let audit_surface: Value = serde_json::from_slice(&fs::read(package_path(root, audit_display))?)?;
    let shell_summary = shell_summary(&shell_report);
    let vectors_match = shell_summary.pointer("/summary/all_expected_matched") == Some(&json!(true))
        && shell_summary.pointer("/summary/accepted") == shell_summary.pointer("/summary/expected_accept");
    let spawn = spawn_records(&audit_surface);
    let strict_clean = spawn["generated_spawn_or_crypto_proof_plan_records"].as_array().unwrap().iter().all(|record| {
        record.get("status").and_then(Value::as_str) != Some("runtime-required")
            && !record.get("codegen_coverage_status").and_then(Value::as_str).unwrap_or_default().starts_with("gap:")
    });
    let visible =
        spawn["proof_plan_record_count"].as_u64().unwrap_or(0) > 0 && spawn["runtime_access_count"].as_u64().unwrap_or(0) > 0;
    let mut audit_report = Map::new();
    audit_report.insert("source".into(), json!(audit_display.to_string_lossy().replace('\\', "/")));
    audit_report.insert(
        "summary".into(),
        compact(
            audit_surface.get("summary").unwrap_or(&Value::Null),
            &["actions", "locks", "proof_plan_records", "runtime_gaps", "strict_prediction_errors"],
        ),
    );
    audit_report.insert("strict_surface_scope".into(), json!("generated spawn and BIP340 ProofPlan records"));
    audit_report.insert("strict_surface_clean".into(), json!(strict_clean));
    audit_report.insert("generated_spawn_visible".into(), json!(visible));
    for (key, value) in spawn.as_object().unwrap() {
        audit_report.insert(key.clone(), value.clone());
    }
    let report = json!({
        "schema": "novaseal-riscv-shell-artifact-v0.1",
        "classification": "riscv_shell_artifact_preflight",
        "source_release_elf": release_info,
        "staged_release_elf": staged_info,
        "staged_sha256_file": staged_sha_display.to_string_lossy().replace('\\', "/"),
        "staged_matches_release": matches,
        "shell_report": shell_summary,
        "audit_surface": Value::Object(audit_report),
        "status": {
            "preflight_passed": matches && vectors_match && strict_clean && visible,
            "lock_wiring_status": "wired_to_bip340_shell",
            "ready_for_ckb_vm_dry_run": matches && vectors_match && visible,
            "production_ready": false
        },
        "limits": [
            "The staged ELF matches BIP340 IPC vectors at model/unit-test level, not through a CKB VM transaction.",
            "The generated CellScript audit surface has lock spawn/pipe/wait records, but this artifact preflight is not parent-lock CKB VM execution evidence.",
            "This artifact preflight does not execute the staged ELF through inherited fd/pipe IPC; use harness/ckb_vm for child-verifier VM evidence.",
            "No occupied capacity or tx-size evidence is produced by this artifact preflight."
        ]
    });
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    println!("wrote {}", output_display.display());
    println!(
        "summary: preflight_passed={} staged_matches_release={} size={} sha256={} generated_spawn_visible={}",
        if report["status"]["preflight_passed"] == true { "True" } else { "False" },
        if matches { "True" } else { "False" },
        report["staged_release_elf"]["size_bytes"],
        report["staged_release_elf"]["sha256"].as_str().unwrap(),
        if visible { "True" } else { "False" }
    );
    Ok(0)
}
