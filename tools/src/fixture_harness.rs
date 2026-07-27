use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::canonical_vectors::{model_result, normalize};
use crate::shared::{json_text, package_path};

const REQUIRED_SOURCE_SNIPPETS: &[&str] = &[
    "let intent_core_hash = hash_blake2b_packed(intent.core)",
    "let signed_intent_hash = hash_blake2b_packed(intent)",
    "let materialized_receipt_hash = hash_blake2b_packed(receipt_commitment)",
    "require intent.core.old_cell.tx_hash == actual_old_tx_hash",
    "require intent.core.old_cell.index == actual_old_index",
    "require intent.core.old_state_hash == old_cell.state_hash",
    "require actual_state_hash_commitment == state_hash_commitment",
    "require intent.core.policy_hash == old_cell.policy_hash",
    "require sig.pubkey == old_cell.btc_authority_hash.0",
    "require intent.core.new_nonce == old_cell.nonce + 1",
    "require old_cell.nonce < U64_MAX",
    "require now <= intent.core.expiry",
    "require intent.expected_receipt_hash == materialized_receipt_hash",
    "verifier::btc::bip340::require_signature(signed_intent_hash, sig.pubkey, sig.signature)",
    "require sig.pubkey == cell.btc_authority_hash.0",
];

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("missing JSON file: {}", path.display()))?)
        .with_context(|| format!("invalid JSON in {}", path.display()))
}

fn optional_json(path: &Path) -> Result<Option<Value>> {
    path.exists().then(|| read_json(path)).transpose()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}

fn field(value: &Value, name: &str) -> Value {
    value.get(name).cloned().unwrap_or(Value::Null)
}

fn python_scalar(value: &Value) -> String {
    match value {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

fn report_projection(path: &Path, display_path: &Path, fields: &[&str]) -> Result<Value> {
    let Some(report) = optional_json(path)? else {
        let mut row = Map::new();
        row.insert("artifact".into(), json!(display_path.display().to_string()));
        row.insert("available".into(), json!(false));
        for field_name in fields {
            row.insert((*field_name).into(), Value::Null);
        }
        return Ok(Value::Object(row));
    };
    let mut row = Map::new();
    row.insert("artifact".into(), json!(display_path.display().to_string()));
    row.insert("available".into(), json!(true));
    for field_name in fields {
        row.insert((*field_name).into(), field(&report, field_name));
    }
    Ok(Value::Object(row))
}

fn run_fixture(path: &Path) -> Result<Value> {
    let fixture = read_json(path)?;
    let actual = model_result(&normalize(&fixture));
    let expected = fixture.get("expected").and_then(Value::as_object);
    let expected_result = expected.and_then(|value| value.get("result")).cloned().unwrap_or(Value::Null);
    let expected_failure = expected.and_then(|value| value.get("failure_mode")).cloned().unwrap_or(Value::Null);
    let matched =
        actual["result"] == expected_result && (actual["result"] == "accepted" || actual["failure_mode"] == expected_failure);
    let file_name = path.file_name().context("fixture has no file name")?.to_string_lossy();
    let stem = path.file_stem().context("fixture has no stem")?.to_string_lossy();
    Ok(json!({
        "fixture": file_name,
        "name": fixture.get("name").cloned().unwrap_or_else(|| json!(stem)),
        "category": field(&fixture, "category"),
        "criteria": fixture.get("acceptance_criteria_covered").cloned().unwrap_or_else(|| json!([])),
        "expected": {"result": expected_result, "failure_mode": expected_failure},
        "actual": actual,
        "matched": matched,
    }))
}

fn object_or_empty(value: Option<&Value>) -> &Map<String, Value> {
    value.and_then(Value::as_object).unwrap_or_else(|| {
        static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
        EMPTY.get_or_init(Map::new)
    })
}

fn array_or_empty(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn artifact_checks(surface: &Value) -> Value {
    let summary = object_or_empty(surface.get("summary"));
    let actions = array_or_empty(surface.get("actions"));
    let gaps = array_or_empty(surface.get("runtime_gaps"));
    let accesses =
        actions.first().and_then(|action| action.get("runtime_accesses")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let has = |operation: &str, binding: &str| {
        accesses.iter().any(|access| access["operation"] == operation && access["binding"] == binding)
    };
    json!({
        "execution_level": "source_model_plus_audit_surface",
        "is_ckb_vm_execution": false,
        "actions": summary.get("actions").cloned().unwrap_or(Value::Null),
        "locks": summary.get("locks").cloned().unwrap_or(Value::Null),
        "runtime_gaps": gaps.iter().map(|gap| field(gap, "feature")).collect::<Vec<_>>(),
        "consume_old_cell_visible": has("consume", "old_cell"),
        "create_new_cell_visible": has("output", "new_cell"),
        "authority_lock_generated_visible": summary.get("locks").is_some_and(|value| !value.is_null() && value != 0),
    })
}

fn source_guard_checks(source: &str) -> Value {
    let missing = REQUIRED_SOURCE_SNIPPETS.iter().filter(|snippet| !source.contains(**snippet)).copied().collect::<Vec<_>>();
    json!({
        "required_snippets": REQUIRED_SOURCE_SNIPPETS,
        "missing_snippets": missing,
        "all_present": missing.is_empty(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    root: &Path,
    fixtures: Option<&Path>,
    source: Option<&Path>,
    audit_surface: Option<&Path>,
    canonical_vectors: Option<&Path>,
    btc_verifier_vectors: Option<&Path>,
    wallet_signing_alignment_report: Option<&Path>,
    btc_verifier_ipc_vectors: Option<&Path>,
    btc_verifier_shell_report: Option<&Path>,
    ckb_vm_child_verifier_report: Option<&Path>,
    parent_lock_abi_preflight_report: Option<&Path>,
    parent_lock_ckb_vm_report: Option<&Path>,
    state_type_ckb_vm_report: Option<&Path>,
    combined_tx_report: Option<&Path>,
    output: Option<&Path>,
    pretty: bool,
) -> Result<i32> {
    let logical = |candidate: Option<&Path>, default: &str| candidate.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(default));
    let fixtures_display = logical(fixtures, "fixtures");
    let source_display = logical(source, "src/nova_state_type.cell");
    let audit_surface_display = logical(audit_surface, "target/novaseal-audit-surface.json");
    let canonical_vectors_display = logical(canonical_vectors, "target/novaseal-canonical-vectors.json");
    let btc_verifier_vectors_display = logical(btc_verifier_vectors, "target/novaseal-btc-verifier-vectors.json");
    let wallet_alignment_display = logical(wallet_signing_alignment_report, "target/novaseal-wallet-signing-alignment.json");
    let ipc_vectors_display = logical(btc_verifier_ipc_vectors, "target/novaseal-btc-verifier-ipc-vectors.json");
    let shell_report_display = logical(btc_verifier_shell_report, "target/novaseal-btc-verifier-shell-report.json");
    let child_report_display = logical(ckb_vm_child_verifier_report, "target/novaseal-ckb-vm-child-verifier-report.json");
    let preflight_report_display = logical(parent_lock_abi_preflight_report, "target/novaseal-parent-lock-abi-preflight.json");
    let parent_report_display = logical(parent_lock_ckb_vm_report, "target/novaseal-parent-lock-ckb-vm-report.json");
    let state_report_display = logical(state_type_ckb_vm_report, "target/novaseal-state-type-ckb-vm-report.json");
    let combined_report_display = logical(combined_tx_report, "target/novaseal-combined-tx-report.json");
    let output_display = logical(output, "target/novaseal-fixture-report.json");
    let fixtures = package_path(root, &fixtures_display);
    let source = package_path(root, &source_display);
    let audit_surface = package_path(root, &audit_surface_display);
    let canonical_vectors = package_path(root, &canonical_vectors_display);
    let btc_verifier_vectors = package_path(root, &btc_verifier_vectors_display);
    let wallet_alignment = package_path(root, &wallet_alignment_display);
    let ipc_vectors = package_path(root, &ipc_vectors_display);
    let shell_report = package_path(root, &shell_report_display);
    let child_report = package_path(root, &child_report_display);
    let preflight_report = package_path(root, &preflight_report_display);
    let parent_report = package_path(root, &parent_report_display);
    let state_report = package_path(root, &state_report_display);
    let combined_report = package_path(root, &combined_report_display);
    let output = package_path(root, &output_display);

    let source_text = fs::read_to_string(&source).with_context(|| format!("missing source file: {}", source.display()))?;
    let surface = read_json(&audit_surface)?;
    let mut fixture_paths = fs::read_dir(&fixtures)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect::<Vec<_>>();
    fixture_paths.sort();
    let results = fixture_paths.iter().map(|path| run_fixture(path)).collect::<Result<Vec<_>>>()?;
    let matched = results.iter().filter(|result| result["matched"] == true).count();
    let criteria =
        results.iter().flat_map(|result| array_or_empty(result.get("criteria"))).filter_map(Value::as_u64).collect::<BTreeSet<_>>();

    let canonical_checks =
        report_projection(&canonical_vectors, &canonical_vectors_display, &["summary", "receipt_commitment_status"])?;
    let canonical_checks = if canonical_checks["available"] == true {
        let vectors = read_json(&canonical_vectors)?;
        json!({
            "artifact": canonical_vectors_display.display().to_string(), "available": true,
            "summary": field(&vectors, "summary"),
            "receipt_commitment_status": vectors.pointer("/receipt_commitment_analysis/status").cloned().unwrap_or(Value::Null)
        })
    } else {
        canonical_checks
    };
    let btc_checks = report_projection(&btc_verifier_vectors, &btc_verifier_vectors_display, &["summary", "scheme"])?;
    let wallet_checks =
        report_projection(&wallet_alignment, &wallet_alignment_display, &["summary", "classification", "message_rules"])?;
    let ipc_checks = report_projection(&ipc_vectors, &ipc_vectors_display, &["summary", "ipc_contract"])?;
    let shell_checks = report_projection(&shell_report, &shell_report_display, &["summary", "classification"])?;
    let child_checks = report_projection(&child_report, &child_report_display, &["summary", "classification", "elf"])?;
    let preflight_checks = report_projection(&preflight_report, &preflight_report_display, &["classification", "status", "checks"])?;
    let parent_checks =
        report_projection(&parent_report, &parent_report_display, &["summary", "classification", "parent_elf", "child_elf", "cases"])?;
    let state_checks = report_projection(&state_report, &state_report_display, &["summary", "classification", "action_elf", "cases"])?;
    let combined_checks = report_projection(
        &combined_report,
        &combined_report_display,
        &["summary", "classification", "parent_elf", "type_elf", "child_elf", "cases"],
    )?;

    let child_summary = object_or_empty(child_checks.get("summary"));
    let preflight_status = object_or_empty(preflight_checks.get("status"));
    let parent_summary = object_or_empty(parent_checks.get("summary"));
    let state_summary = object_or_empty(state_checks.get("summary"));
    let combined_summary = object_or_empty(combined_checks.get("summary"));
    let wallet_summary = object_or_empty(wallet_checks.get("summary"));
    let parent_sizes = array_or_empty(parent_checks.get("cases"))
        .iter()
        .filter_map(|case| case.pointer("/transaction_shape/witness_size_bytes").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();
    let state_sizes = array_or_empty(state_checks.get("cases"))
        .iter()
        .filter_map(|case| case.get("witness_size_bytes").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();
    let shared_size = parent_sizes.intersection(&state_sizes).next().copied();
    let equal_if_present =
        |summary: &Map<String, Value>, left: &str, right: &str| !summary.is_empty() && summary.get(left) == summary.get(right);
    let get = |summary: &Map<String, Value>, name: &str| summary.get(name).cloned().unwrap_or(Value::Null);
    let summary = json!({
        "fixtures": results.len(), "matched": matched, "mismatched": results.len() - matched,
        "criteria_seen": criteria, "ckb_vm_executed": false,
        "child_verifier_ckb_vm_executed": truthy(child_summary.get("child_verifier_ckb_vm_executed")),
        "parent_lock_abi_preflight_passed": truthy(preflight_status.get("preflight_passed")),
        "parent_lock_ckb_vm_executed": truthy(parent_summary.get("parent_lock_ckb_vm_executed")),
        "parent_lock_spawn_executed": truthy(parent_summary.get("parent_spawn_executed")),
        "parent_lock_transaction_shape_constructed": truthy(parent_summary.get("transaction_shape_constructed")),
        "parent_lock_consensus_packed_tx_constructed": truthy(parent_summary.get("consensus_packed_tx_constructed")),
        "parent_lock_resolved_transaction_constructed": truthy(parent_summary.get("resolved_transaction_constructed")),
        "parent_lock_resolved_script_verifier_executed": truthy(parent_summary.get("resolved_script_verifier_executed")),
        "parent_lock_resolved_script_verifier_matched_expected": truthy(parent_summary.get("resolved_script_verifier_matched_expected")),
        "parent_lock_resolved_script_verifier_max_cycles": get(parent_summary, "resolved_script_verifier_max_cycles"),
        "parent_lock_full_transaction_executed": truthy(parent_summary.get("full_transaction_executed")),
        "parent_lock_full_transaction_verifier_matched_expected": truthy(parent_summary.get("full_transaction_verifier_matched_expected")),
        "parent_lock_full_transaction_verifier_max_cycles": get(parent_summary, "full_transaction_verifier_max_cycles"),
        "parent_lock_max_consensus_tx_size_bytes": get(parent_summary, "max_consensus_tx_size_bytes"),
        "parent_lock_max_output_occupied_capacity_shannons": get(parent_summary, "max_output_occupied_capacity_shannons"),
        "parent_lock_capacity_shape_checks_passed": truthy(parent_summary.get("capacity_shape_checks_passed")),
        "parent_lock_under_capacity_shape_rejects": truthy(parent_summary.get("under_capacity_shape_rejects")),
        "parent_child_ckb_vm_matched_expected": equal_if_present(parent_summary, "matched_expected", "total_cases"),
        "state_type_action_ckb_vm_executed": truthy(state_summary.get("state_type_action_ckb_vm_executed")),
        "state_type_action_matched_expected": equal_if_present(state_summary, "state_type_matched_expected", "total_cases"),
        "state_type_source_fixture_matched_by_state_type_only": get(state_summary, "source_fixture_matched_by_state_type_only"),
        "state_type_source_fixture_requires_lock_or_external_context": get(state_summary, "source_fixture_requires_lock_or_external_context"),
        "state_type_schema_cell_intent_mismatch_detected": truthy(state_summary.get("schema_cell_intent_mismatch_detected")),
        "state_type_schema_cell_intent_aligned": truthy(state_summary.get("schema_cell_intent_aligned")),
        "shared_lock_type_witness_abi": "CSARGv1:NovaSealSignedIntentV0,state_hash_commitment,SignaturePayload",
        "shared_lock_type_witness_abi_aligned": shared_size.is_some(), "shared_lock_type_witness_size_bytes": shared_size,
        "combined_full_transaction_executed": truthy(combined_summary.get("combined_full_transaction_executed")),
        "combined_full_transaction_matched_expected": equal_if_present(combined_summary, "matched_expected", "total_cases"),
        "combined_full_transaction_total_cases": get(combined_summary, "total_cases"),
        "combined_full_transaction_accepted": get(combined_summary, "accepted"),
        "combined_full_transaction_rejected": get(combined_summary, "rejected"),
        "combined_lock_and_type_script_groups_present": truthy(combined_summary.get("lock_and_type_script_groups_present")),
        "combined_shared_witness_abi_aligned": truthy(combined_summary.get("shared_witness_abi_aligned")),
        "combined_builder_shape_checks_passed": truthy(combined_summary.get("builder_shape_checks_passed")),
        "combined_fee_shape_checks_passed": truthy(combined_summary.get("fee_shape_checks_passed")),
        "combined_under_capacity_shape_rejects": truthy(combined_summary.get("under_capacity_shape_rejects")),
        "combined_min_fee_shannons": get(combined_summary, "min_fee_shannons"), "combined_max_fee_shannons": get(combined_summary, "max_fee_shannons"),
        "combined_full_transaction_max_cycles": get(combined_summary, "max_full_transaction_cycles"),
        "combined_max_consensus_tx_size_bytes": get(combined_summary, "max_consensus_tx_size_bytes"),
        "combined_max_output_occupied_capacity_shannons": get(combined_summary, "max_output_occupied_capacity_shannons"),
        "wallet_signing_alignment_report_available": truthy(wallet_checks.get("available")),
        "wallet_lock_alignment_ready": truthy(wallet_summary.get("wallet_lock_alignment_ready")),
        "wallet_current_lock_digest_matches_canonical": get(wallet_summary, "current_lock_digest_matches_canonical"),
        "wallet_current_lock_digest_mismatches": get(wallet_summary, "current_lock_digest_mismatches"),
        "classification": "model_level_fixture_evidence",
    });

    let report = json!({
        "schema": "novaseal-fixture-harness-report-v0.1", "fixture_dir": fixtures_display.display().to_string(),
        "source": source_display.display().to_string(), "audit_surface": audit_surface_display.display().to_string(), "summary": summary,
        "artifact_checks": artifact_checks(&surface), "canonical_vector_checks": canonical_checks,
        "btc_verifier_vector_checks": btc_checks, "wallet_signing_alignment_checks": wallet_checks,
        "btc_verifier_ipc_vector_checks": ipc_checks, "btc_verifier_shell_checks": shell_checks,
        "ckb_vm_child_verifier_checks": child_checks, "parent_lock_abi_preflight_checks": preflight_checks,
        "parent_lock_ckb_vm_checks": parent_checks, "state_type_ckb_vm_checks": state_checks,
        "combined_tx_checks": combined_checks, "source_guard_checks": source_guard_checks(&source_text), "results": results,
        "limitations": [
            "The source-model portion of this fixture harness does not execute the parent lock in CKB VM or construct a transaction.",
            "BTC signature verification in the source-model portion is represented by fixture-declared delegate success/failure.",
            "Child-verifier CKB VM evidence is attached separately when target/novaseal-ckb-vm-child-verifier-report.json exists; it is not per-fixture parent-lock execution.",
            "Parent-lock ELF/ASM ABI preflight is attached separately when target/novaseal-parent-lock-abi-preflight.json exists; it is not parent-lock CKB VM execution.",
            "Parent-lock CKB VM evidence is attached separately when target/novaseal-parent-lock-ckb-vm-report.json exists; it now includes consensus-packed transaction shape, tx-size, occupied-capacity, under-capacity shape checks, resolved ckb-script lock-group verifier execution, and full ckb-script transaction script verification for the four parent authority cases, but it is not the full fixture transaction runner.",
            "State-type CKB VM evidence is attached separately when target/novaseal-state-type-ckb-vm-report.json exists; it executes the key_auth_transition action over the fixture set at action/type scope, not lock scope.",
            "The state-type CKB VM harness uses the canonical 213-byte NovaSealIntentV0 old_cell: OutPoint shape without an intent-shortening adapter.",
            "The parent-lock and state-type CKB VM harnesses now parse the same CSARGv1 witness payload order: intent, receipt_hash, state_hash_commitment, SignaturePayload.",
            "Combined lock+type full transaction script-verifier evidence is attached separately when target/novaseal-combined-tx-report.json exists; it is still an in-memory harness ResolvedTransaction flow, not production builder/full-node acceptance.",
            "Wallet signing alignment evidence is attached separately when target/novaseal-wallet-signing-alignment.json exists; it must pass before local wallet/lock digest readiness is claimed.",
            "The generated authority lock surface covers Script.args binding and spawn/IPC shell wiring; parent-lock CKB VM evidence is still harness-level, not generated ProofPlan transaction coverage.",
            "Passing source-model fixtures do not replace builder-backed/full-node acceptance evidence.",
        ]
    });
    fs::create_dir_all(output.parent().context("output path has no parent")?)?;
    fs::write(&output, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: fixtures={} matched={} mismatched={} ckb_vm_executed={} child_verifier_ckb_vm_executed={} parent_lock_abi_preflight_passed={} parent_lock_ckb_vm_executed={} parent_lock_spawn_executed={} parent_lock_tx_shape_constructed={} parent_lock_resolved_script_verifier_executed={} parent_lock_resolved_script_verifier_matched_expected={} parent_lock_full_tx_executed={} parent_lock_full_tx_matched_expected={} state_type_vm_executed={} state_type_matched_expected={} shared_witness_abi_aligned={} combined_full_tx_executed={} combined_full_tx_matched_expected={} wallet_lock_alignment_ready={}",
        python_scalar(&summary["fixtures"]), python_scalar(&summary["matched"]), python_scalar(&summary["mismatched"]),
        python_scalar(&summary["ckb_vm_executed"]), python_scalar(&summary["child_verifier_ckb_vm_executed"]),
        python_scalar(&summary["parent_lock_abi_preflight_passed"]), python_scalar(&summary["parent_lock_ckb_vm_executed"]),
        python_scalar(&summary["parent_lock_spawn_executed"]), python_scalar(&summary["parent_lock_transaction_shape_constructed"]),
        python_scalar(&summary["parent_lock_resolved_script_verifier_executed"]),
        python_scalar(&summary["parent_lock_resolved_script_verifier_matched_expected"]),
        python_scalar(&summary["parent_lock_full_transaction_executed"]),
        python_scalar(&summary["parent_lock_full_transaction_verifier_matched_expected"]),
        python_scalar(&summary["state_type_action_ckb_vm_executed"]), python_scalar(&summary["state_type_action_matched_expected"]),
        python_scalar(&summary["shared_lock_type_witness_abi_aligned"]), python_scalar(&summary["combined_full_transaction_executed"]),
        python_scalar(&summary["combined_full_transaction_matched_expected"]), python_scalar(&summary["wallet_lock_alignment_ready"])
    );
    Ok(if summary["mismatched"] == 0 { 0 } else { 1 })
}
