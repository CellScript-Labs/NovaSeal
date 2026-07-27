use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tempfile::TempDir;

use crate::shared::{json_text, package_path};

const PROBE_SOURCE: &str = r#"module novaseal::spawn_backend_probe

action probe(message: Hash, witness pubkey: [u8; 32], witness signature: [u8; 64]) -> u64 {
    verification
    verifier::btc::bip340::require_signature(message, pubkey, signature)
    return 0
}
"#;

const BOUND_CELL_TOML: &str = r#"[package]
name = "novaseal_spawn_bound_probe"
version = "0.0.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[[deploy.ckb.cell_deps]]
name = "cellscript_btc_bip340_verifier_riscv"
role = "runtime_verifier"
verifier_id = "btc.bip340"
ipc_abi = "cellscript.verifier.btc.bip340.v0"
out_point = "0x4444444444444444444444444444444444444444444444444444444444444444:0"
dep_type = "code"
hash_type = "data1"
data_hash = "0x5555555555555555555555555555555555555555555555555555555555555555"
artifact_hash = "0x6666666666666666666666666666666666666666666666666666666666666666"
"#;

fn execute(cellc: &Path, args: &[&str], cwd: &Path) -> Result<Output> {
    Command::new(cellc).args(args).current_dir(cwd).output().with_context(|| format!("failed to execute {}", cellc.display()))
}

fn success(output: &Output) -> bool {
    output.status.success()
}

fn return_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn combined_text(output: &Output) -> String {
    format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

fn first_lines(output: &Output) -> Vec<String> {
    combined_text(output).lines().map(str::trim).filter(|line| !line.is_empty()).take(12).map(str::to_owned).collect()
}

fn object_or_empty(value: Option<&Value>) -> &serde_json::Map<String, Value> {
    value.and_then(Value::as_object).unwrap_or_else(|| {
        static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> = std::sync::OnceLock::new();
        EMPTY.get_or_init(serde_json::Map::new)
    })
}

fn load_optional(path: &Path) -> Value {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn audit_surface_status(path: &Path, display_path: &Path) -> Value {
    let surface = load_optional(path);
    let proof_plan = surface.get("proof_plan").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let receipt_output_materialised = proof_plan.iter().any(|record| {
        record.get("feature").and_then(Value::as_str).is_some_and(|value| value.starts_with("create-output:ProofReceiptV0"))
            && record["status"] == "checked-runtime"
            && record["on_chain_checked"] == true
    });
    let measurement = object_or_empty(surface.get("transaction_measurement_evidence"));
    let combined = object_or_empty(measurement.get("combined_tx_report"));
    json!({
        "source": display_path.display().to_string(), "present": surface.as_object().is_some_and(|value| !value.is_empty()),
        "receipt_output_materialised": receipt_output_materialised,
        "transaction_measurement_present": measurement.get("measured") == Some(&json!(true)),
        "measurement_layer": measurement.get("measurement_layer").cloned().unwrap_or(Value::Null),
        "node_verification_stack_verified": measurement.get("node_verification_stack_verified") == Some(&json!(true)),
        "ckb_node_verification_stack_executed": combined.get("ckb_node_verification_stack_executed") == Some(&json!(true)),
        "node_stack_matched_expected": combined.get("node_stack_matched_expected").cloned().unwrap_or(Value::Null),
        "node_stack_mismatched": combined.get("node_stack_mismatched").cloned().unwrap_or(Value::Null),
    })
}

fn helper_body<'a>(assembly: &'a str, label: &str) -> &'a str {
    let marker = format!("{label}:");
    let Some((_, tail)) = assembly.split_once(&marker) else { return "" };
    tail.split_once("\n.global ").map_or(tail, |(body, _)| body)
}

fn analyse_assembly(path: &Path) -> Result<Value> {
    let assembly = fs::read_to_string(path)?;
    let spawn = helper_body(&assembly, "__ckb_spawn");
    let spawn_fd = helper_body(&assembly, "__ckb_spawn_with_fd1");
    let contains_ecall = |body: &str| body.lines().any(|line| line.trim() == "ecall");
    let markers = assembly.matches("# cellscript abi: novaseal bip340 ipc word ").count();
    let writes = assembly.matches("\n    call __ckb_pipe_write").count();
    let last = assembly.contains("# cellscript abi: novaseal bip340 ipc word 17");
    Ok(json!({
        "assembly_path": "<temporary>/spawn_backend_probe.s",
        "calls": {
            "pipe": assembly.contains("call __ckb_pipe"), "pipe_write": assembly.contains("call __ckb_pipe_write"),
            "spawn": assembly.contains("call __ckb_spawn"), "spawn_with_fd": assembly.contains("call __ckb_spawn_with_fd1"),
            "wait": assembly.contains("call __ckb_wait"), "close": assembly.contains("call __ckb_close")
        },
        "fixed_word_envelope": {"ipc_word_markers": markers, "pipe_write_instruction_count": writes, "contains_last_signature_word": last},
        "generic_verifier_surface": {
            "source_uses_btc_bip340_helper": PROBE_SOURCE.contains("verifier::btc::bip340::require_signature"),
            "lowers_to_spawn_with_fd": assembly.contains("call __ckb_spawn_with_fd1"),
            "lowers_to_fixed_18_word_envelope": markers == 18 && writes == 18 && last
        },
        "spawn_helper": {
            "present": !spawn.is_empty(), "contains_withheld_raw_syscall_2601": spawn.contains("withheld raw syscall 2601"),
            "contains_ecall_instruction": contains_ecall(spawn),
            "contains_status_return_path": spawn.contains("li a1,") && spawn.contains("ret"),
            "contains_static_cell_dep0_no_inherited_fds": spawn.contains("CellDep#0 with no argv and no inherited fds")
        },
        "spawn_with_fd_helper": {
            "present": !spawn_fd.is_empty(), "contains_withheld_raw_syscall_2601": spawn_fd.contains("withheld raw syscall 2601"),
            "contains_ecall_instruction": contains_ecall(spawn_fd),
            "contains_status_return_path": spawn_fd.contains("li a1,") && spawn_fd.contains("ret"),
            "contains_static_cell_dep0_one_inherited_fd": spawn_fd.contains("one inherited fd from a1"),
            "stores_fd_at_inherited_fds_zero": spawn_fd.contains("sd a1, 8(sp)"),
            "terminates_inherited_fds": spawn_fd.contains("sd zero, 16(sp)")
        }
    }))
}

fn strict_summary(output: &Output) -> Value {
    let text = combined_text(output);
    json!({
        "passed": success(output), "returncode": return_code(output), "mentions_pp0150": text.contains("PP0150"),
        "mentions_spawn_target": text.contains("spawn-target"), "first_lines": first_lines(output)
    })
}

fn spawn_entries(path: &Path) -> Vec<Value> {
    let bundle = load_optional(path);
    bundle
        .get("actions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|action| action.get("proof_plan_source_mappings").and_then(Value::as_array).into_iter().flatten())
        .filter(|mapping| mapping.get("feature").and_then(Value::as_str).is_some_and(|value| value.starts_with("spawn-target:")))
        .map(|mapping| {
            json!({
                "origin": mapping.get("origin").cloned().unwrap_or(Value::Null),
                "feature": mapping.get("feature").cloned().unwrap_or(Value::Null),
                "codegen_coverage_status": mapping.get("codegen_coverage_status").cloned().unwrap_or(Value::Null)
            })
        })
        .collect()
}

fn manifest_probe(cellc: &Path, temp: &Path) -> Result<Value> {
    let package = temp.join("manifest_bound_spawn_probe");
    fs::create_dir_all(package.join("src"))?;
    fs::write(package.join("Cell.toml"), BOUND_CELL_TOML)?;
    fs::write(package.join("src/main.cell"), PROBE_SOURCE)?;
    let strict = execute(cellc, &["check", "--target-profile", "ckb", "--primitive-strict", "0.16"], &package)?;
    let bundle = execute(cellc, &["audit-bundle", "--target-profile", "ckb", "--json"], &package)?;
    let text = combined_text(&strict);
    Ok(json!({
        "passed": success(&strict), "returncode": return_code(&strict),
        "audit_bundle_passed": success(&bundle), "audit_bundle_returncode": return_code(&bundle),
        "mentions_pp0150": text.contains("PP0150"),
        "spawn_plan_entries": spawn_entries(&package.join("target/cellscript-audit-bundle/audit-bundle.json")),
        "first_lines": first_lines(&strict)
    }))
}

fn python_scalar(value: &Value) -> String {
    match value {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => other.to_string(),
    }
}

pub fn run(root: &Path, cellc: Option<&Path>, output: Option<&Path>, audit_surface: Option<&Path>, pretty: bool) -> Result<i32> {
    let cellc = cellc.map(Path::to_path_buf).unwrap_or_else(|| root.parent().unwrap().parent().unwrap().join("target/debug/cellc"));
    let output_display = output.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("target/novaseal-spawn-backend-probe.json"));
    let surface_display = audit_surface.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("target/novaseal-audit-surface.json"));
    let output = package_path(root, &output_display);
    let surface_path = package_path(root, &surface_display);
    let temp = TempDir::with_prefix("novaseal-spawn-probe-")?;
    let source = temp.path().join("spawn_backend_probe.cell");
    fs::write(&source, PROBE_SOURCE)?;
    let source_arg = source.to_string_lossy();
    let compile = execute(&cellc, &[&source_arg, "--target-profile", "ckb"], temp.path())?;
    let assembly_path = source.with_extension("s");
    let assembly = if assembly_path.exists() { analyse_assembly(&assembly_path)? } else { json!({}) };
    let strict = execute(&cellc, &[&source_arg, "--target-profile", "ckb", "--primitive-strict", "0.16"], temp.path())?;
    let manifest = manifest_probe(&cellc, temp.path())?;
    let spawn = object_or_empty(assembly.get("spawn_helper"));
    let spawn_fd = object_or_empty(assembly.get("spawn_with_fd_helper"));
    let calls = object_or_empty(assembly.get("calls"));
    let status_true = |object: &serde_json::Map<String, Value>, key: &str| object.get(key) == Some(&json!(true));
    let backend = status_true(spawn_fd, "contains_ecall_instruction") && !status_true(spawn_fd, "contains_withheld_raw_syscall_2601");
    let all_calls = ["pipe", "pipe_write", "spawn_with_fd", "wait", "close"].iter().all(|key| status_true(calls, key));
    let envelope = object_or_empty(assembly.get("fixed_word_envelope"));
    let envelope_lowered = envelope.get("ipc_word_markers") == Some(&json!(18))
        && envelope.get("pipe_write_instruction_count") == Some(&json!(18))
        && envelope.get("contains_last_signature_word") == Some(&json!(true));
    let strict_report = strict_summary(&strict);
    let strict_rejects =
        !success(&strict) && strict_report["mentions_pp0150"] == true && strict_report["mentions_spawn_target"] == true;
    let entries = manifest.get("spawn_plan_entries").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let manifest_builder = entries.iter().any(|entry| entry["codegen_coverage_status"] == "builder-required");
    let static_one_fd = status_true(spawn_fd, "contains_static_cell_dep0_one_inherited_fd");
    let generic = object_or_empty(assembly.get("generic_verifier_surface"));
    let generic_lowered = ["source_uses_btc_bip340_helper", "lowers_to_spawn_with_fd", "lowers_to_fixed_18_word_envelope"]
        .iter()
        .all(|key| status_true(generic, key));
    let surface = audit_surface_status(&surface_path, &surface_display);
    let mut blockers = Vec::new();
    if surface["receipt_output_materialised"] != true {
        blockers.push("proof_receipt_v0_output_materialisation_missing");
    }
    if surface["transaction_measurement_present"] != true {
        blockers.push("production_cycle_capacity_tx_size_measurement_missing");
    }
    if surface["node_verification_stack_verified"] != true {
        blockers.push("ckb_node_verification_stack_missing");
    }
    let report = json!({
        "schema": "novaseal-spawn-backend-probe-v0.1",
        "classification": if backend && envelope_lowered { "cellscript_btc_bip340_verifier_surface_ready_for_lock_wiring" } else { "cellscript_btc_bip340_verifier_surface_compiler_blocker" },
        "cellc": cellc.display().to_string(), "probe_source": PROBE_SOURCE,
        "compile": {"passed": success(&compile), "returncode": return_code(&compile)}, "assembly": assembly,
        "strict_0_16": strict_report, "manifest_bound_strict_0_16": manifest, "novaseal_audit_surface": surface,
        "status": {
            "all_spawn_ipc_calls_lowered": all_calls, "backend_ecall_boundary_closed": backend,
            "spawn_with_fd_helper_executable": backend,
            "spawn_helper_fail_closed_stub": status_true(spawn, "contains_withheld_raw_syscall_2601") && !status_true(spawn, "contains_ecall_instruction"),
            "spawn_with_fd_helper_fail_closed_stub": status_true(spawn_fd, "contains_withheld_raw_syscall_2601") && !status_true(spawn_fd, "contains_ecall_instruction"),
            "spawn_with_fd_helper_uses_static_cell_dep0_with_one_inherited_fd": static_one_fd,
            "fixed_word_envelope_lowered": envelope_lowered, "generic_btc_bip340_helper_lowered": generic_lowered,
            "strict_rejects_spawn_target": strict_rejects,
            "manifest_bound_spawn_target_strict_passes": manifest["passed"] == true,
            "manifest_bound_spawn_target_builder_required": manifest_builder,
            "ready_for_novaseal_lock_spawn_wiring": backend && envelope_lowered && static_one_fd && manifest["passed"] == true && manifest_builder,
            "ready_for_parent_child_ckb_vm_dry_run": false,
            "combined_ckb_node_verification_stack_verified": surface["node_verification_stack_verified"]
        },
        "remaining_runtime_evidence_blockers": blockers,
        "limits": [
            "This is a compiler/backend probe, not a NovaSeal lock implementation.",
            "A source-level spawn_with_fd call plus a generic fixed-word envelope is not CKB VM transaction execution evidence.",
            "The current compiler wrapper resolves the static spawn target to CellDep#0 with no argv and exactly one inherited fd.",
            "Strict mode must continue to reject unmanifested, nonzero-index, and dep-group spawn targets; first-CellDep code targets are represented as builder-required obligations."
        ]
    });
    fs::create_dir_all(output.parent().context("output path has no parent")?)?;
    fs::write(&output, json_text(&report, pretty)?)?;
    println!("wrote {}", output_display.display());
    println!(
        "summary: compile_passed={} all_calls_lowered={} generic_btc_bip340_helper_lowered={} spawn_with_fd_helper_executable={} fail_closed_stub={} strict_rejects_spawn_target={} manifest_bound_strict_passes={}",
        python_scalar(&report["compile"]["passed"]), python_scalar(&report["status"]["all_spawn_ipc_calls_lowered"]),
        python_scalar(&report["status"]["generic_btc_bip340_helper_lowered"]),
        python_scalar(&report["status"]["spawn_with_fd_helper_executable"]),
        python_scalar(&report["status"]["spawn_with_fd_helper_fail_closed_stub"]),
        python_scalar(&report["status"]["strict_rejects_spawn_target"]),
        python_scalar(&report["status"]["manifest_bound_spawn_target_strict_passes"])
    );
    Ok(0)
}
