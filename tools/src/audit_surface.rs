use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

const FIELD_GUARDS: &[(u64, &str, &[&str])] = &[
    (
        3,
        "state_hash",
        &[
            "require intent.core.old_state_hash == old_cell.state_hash",
            "let actual_state_hash_commitment = hash_blake2b(intent.core.new_state_hash)",
            "require actual_state_hash_commitment == state_hash_commitment",
            "state_hash: intent.core.new_state_hash",
        ],
    ),
    (
        4,
        "nonce",
        &[
            "require intent.core.old_nonce == old_cell.nonce",
            "require intent.core.new_nonce == old_cell.nonce + 1",
            "nonce: intent.core.new_nonce",
        ],
    ),
    (5, "expiry", &["require now <= intent.core.expiry", "expiry: intent.core.expiry"]),
    (7, "policy_hash", &["require intent.core.policy_hash == old_cell.policy_hash", "policy_hash: old_cell.policy_hash"]),
    (
        8,
        "latest_receipt_hash",
        &["require intent.expected_receipt_hash == materialized_receipt_hash", "latest_receipt_hash: materialized_receipt_hash"],
    ),
];

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

fn objects<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value.get(key).and_then(Value::as_array).into_iter().flatten().filter(|value| value.is_object()).collect()
}

fn truthy(value: Option<&Value>) -> bool {
    match value.unwrap_or(&Value::Null) {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn string(value: Option<&Value>) -> String {
    match value.unwrap_or(&Value::Null) {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

fn generated_hits(bundle: &Value, field: &str) -> Vec<Value> {
    objects(bundle, "proof_plan")
        .into_iter()
        .filter(|record| serde_json::to_string(record).unwrap_or_default().contains(field))
        .map(|record| {
            compact(
                record,
                &[
                    "name",
                    "feature",
                    "status",
                    "codegen_coverage_status",
                    "on_chain_checked",
                    "origin",
                    "input_output_relation_checks",
                ],
            )
        })
        .collect()
}

fn field_visibility(bundle: &Value, source: &str) -> Vec<Value> {
    FIELD_GUARDS
        .iter()
        .map(|(criterion, field, snippets)| {
            let missing = snippets.iter().filter(|snippet| !source.contains(**snippet)).copied().collect::<Vec<_>>();
            let hits = generated_hits(bundle, field);
            let classification = if !missing.is_empty() {
                "missing_source_guard"
            } else if !hits.is_empty() {
                "generated_visible"
            } else {
                "source_guard_only"
            };
            json!({
                "criterion": criterion,
                "field": field,
                "source_guard_present": missing.is_empty(),
                "missing_source_snippets": missing,
                "generated_named_obligation": !hits.is_empty(),
                "generated_hits": hits,
                "classification": classification
            })
        })
        .collect()
}

fn strict_predictions(bundle: &Value) -> Vec<Value> {
    let mut predictions = Vec::new();
    for record in objects(bundle, "proof_plan") {
        let status = string(record.get("status"));
        let coverage = string(record.get("codegen_coverage_status"));
        let feature = string(record.get("feature"));
        let origin = string(record.get("origin"));
        if status == "checked-runtime" && !truthy(record.get("on_chain_checked")) {
            predictions.push(json!({
                "code": "PP0103",
                "feature": feature,
                "origin": origin,
                "reason": "checked ProofPlan status is not reflected in on_chain_checked"
            }));
        }
        if status == "runtime-required" || coverage == "gap:metadata-only" {
            predictions.push(json!({
                "code": "PP0150",
                "feature": feature,
                "origin": origin,
                "reason": "strict v0.16 ProofPlan mode rejects metadata-only or runtime-required obligations"
            }));
        }
    }
    predictions
}

fn gaps(bundle: &Value) -> Vec<Value> {
    objects(bundle, "proof_plan")
        .into_iter()
        .filter(|record| {
            string(record.get("status")) == "runtime-required" || string(record.get("codegen_coverage_status")).starts_with("gap:")
        })
        .map(|record| {
            compact(
                record,
                &[
                    "name",
                    "feature",
                    "status",
                    "codegen_coverage_status",
                    "detail",
                    "origin",
                    "on_chain_checked",
                    "input_output_relation_checks",
                ],
            )
        })
        .collect()
}

fn capacity(bundle: &Value) -> Value {
    let ckb = bundle.pointer("/constraints/ckb").filter(|value| value.is_object()).unwrap_or(&Value::Null);
    let contract = ckb.get("capacity_evidence_contract").filter(|value| value.is_object()).unwrap_or(&Value::Null);
    json!({
        "capacity_status": ckb.get("capacity_status").cloned().unwrap_or(Value::Null),
        "cycles_status": ckb.get("cycles_status").cloned().unwrap_or(Value::Null),
        "estimated_cycles": ckb.get("estimated_cycles").cloned().unwrap_or(Value::Null),
        "measured_cycles": ckb.get("measured_cycles").cloned().unwrap_or(Value::Null),
        "tx_size_status": ckb.get("tx_size_status").cloned().unwrap_or(Value::Null),
        "tx_size_bytes": ckb.get("tx_size_bytes").cloned().unwrap_or(Value::Null),
        "occupied_capacity_measurement_required": ckb.get("occupied_capacity_measurement_required").cloned().unwrap_or(Value::Null),
        "tx_size_measurement_required": ckb.get("tx_size_measurement_required").cloned().unwrap_or(Value::Null),
        "capacity_evidence_contract": compact(
            contract,
            &["status", "required", "measured_occupied_capacity_shannons", "measured_tx_size_bytes", "recommended_code_cell_capacity_shannons"]
        )
    })
}

fn positive(value: Option<&Value>) -> bool {
    value.and_then(Value::as_u64).is_some_and(|value| value > 0)
}

fn measurement(bundle: &Value, combined: &Value, display: &Path) -> Value {
    let bundle_capacity = capacity(bundle);
    let summary = combined.get("summary").filter(|value| value.is_object()).unwrap_or(&Value::Null);
    let row = json!({
        "source": display.to_string_lossy().replace('\\', "/"),
        "present": truthy(Some(combined)),
        "classification": combined.get("classification").cloned().unwrap_or(Value::Null),
        "combined_full_transaction_executed": truthy(summary.get("combined_full_transaction_executed")),
        "ckb_node_verification_stack_executed": truthy(summary.get("ckb_node_verification_stack_executed")),
        "total_cases": summary.get("total_cases").cloned().unwrap_or(Value::Null),
        "matched_expected": summary.get("matched_expected").cloned().unwrap_or(Value::Null),
        "node_stack_matched_expected": summary.get("node_stack_matched_expected").cloned().unwrap_or(Value::Null),
        "node_stack_mismatched": summary.get("node_stack_mismatched").cloned().unwrap_or(Value::Null),
        "node_stack_failure_scope_matched": summary.get("node_stack_failure_scope_matched").cloned().unwrap_or(Value::Null),
        "builder_shape_checks_passed": truthy(summary.get("builder_shape_checks_passed")),
        "fee_shape_checks_passed": truthy(summary.get("fee_shape_checks_passed")),
        "under_capacity_shape_rejects": truthy(summary.get("under_capacity_shape_rejects")),
        "non_contextual_checks_passed": truthy(summary.get("non_contextual_checks_passed")),
        "contextual_checks_match_expected": truthy(summary.get("contextual_checks_match_expected")),
        "max_full_transaction_cycles": summary.get("max_full_transaction_cycles").cloned().unwrap_or(Value::Null),
        "max_node_stack_cycles": summary.get("max_node_stack_cycles").cloned().unwrap_or(Value::Null),
        "max_consensus_tx_size_bytes": summary.get("max_consensus_tx_size_bytes").cloned().unwrap_or(Value::Null),
        "max_output_occupied_capacity_shannons": summary.get("max_output_occupied_capacity_shannons").cloned().unwrap_or(Value::Null),
        "min_capacity_margin_shannons": summary.get("min_capacity_margin_shannons").cloned().unwrap_or(Value::Null)
    });
    let node_verified = row["ckb_node_verification_stack_executed"] == true
        && row["non_contextual_checks_passed"] == true
        && row["contextual_checks_match_expected"] == true
        && row["node_stack_mismatched"] == 0
        && row["node_stack_matched_expected"] == row["total_cases"]
        && positive(row.get("max_node_stack_cycles"));
    let combined_measured = row["combined_full_transaction_executed"] == true
        && positive(row.get("max_full_transaction_cycles"))
        && positive(row.get("max_consensus_tx_size_bytes"))
        && positive(row.get("max_output_occupied_capacity_shannons"))
        && row["builder_shape_checks_passed"] == true
        && row["under_capacity_shape_rejects"] == true
        && node_verified;
    let bundle_measured = positive(bundle_capacity.get("measured_cycles"))
        && positive(bundle_capacity.get("tx_size_bytes"))
        && positive(bundle_capacity.pointer("/capacity_evidence_contract/measured_occupied_capacity_shannons"));
    json!({
        "bundle_capacity_evidence": bundle_capacity,
        "combined_tx_report": row,
        "measured": bundle_measured || combined_measured,
        "measurement_layer": if bundle_measured {
            json!("audit-bundle")
        } else if combined_measured {
            json!("ckb-node-verification-stack-harness")
        } else {
            Value::Null
        },
        "node_verification_stack_verified": node_verified,
        "limits": [
            "Combined transaction measurements now include ckb-verification NonContextualTransactionVerifier and ContextualTransactionVerifier over deterministic builder outputs.",
            "This is the local CKB node verification stack, not live-chain RPC submission, dep liveness, or mempool propagation for NovaSeal."
        ]
    })
}

fn build(
    bundle: &Value,
    bundle_display: &Path,
    source_display: &Path,
    source: &str,
    combined: &Value,
    combined_display: &Path,
) -> Value {
    let actions = objects(bundle, "actions")
        .into_iter()
        .map(|value| compact(value, &["name", "proof_plan_records", "estimated_cycles", "runtime_accesses"]))
        .collect::<Vec<_>>();
    let locks = bundle.get("locks").and_then(Value::as_array).cloned().unwrap_or_default();
    let plan = objects(bundle, "proof_plan");
    let generated_plan = plan
        .iter()
        .map(|value| {
            compact(
                value,
                &[
                    "name",
                    "feature",
                    "category",
                    "status",
                    "codegen_coverage_status",
                    "on_chain_checked",
                    "origin",
                    "input_output_relation_checks",
                    "reads",
                    "scope",
                    "trigger",
                    "detail",
                ],
            )
        })
        .collect::<Vec<_>>();
    let assumptions = objects(bundle, "builder_assumptions")
        .into_iter()
        .map(|value| {
            compact(
                value,
                &[
                    "assumption_id",
                    "feature",
                    "origin",
                    "kind",
                    "proof_plan_status",
                    "capacity_policy",
                    "change_policy",
                    "signature_policy",
                    "failure_mode",
                ],
            )
        })
        .collect::<Vec<_>>();
    let gaps = gaps(bundle);
    let predictions = strict_predictions(bundle);
    let visibility = field_visibility(bundle, source);
    let features = plan.iter().map(|record| string(record.get("feature"))).collect::<Vec<_>>();
    let measurement = measurement(bundle, combined, combined_display);
    let mut blockers = Vec::new();
    if !gaps.is_empty() {
        blockers.push("runtime-required ProofPlan gaps remain");
    }
    if !locks.iter().any(|lock| lock.get("name").and_then(Value::as_str) == Some("btc_authority")) {
        blockers.push("generated locks[] does not include btc_authority");
    }
    if visibility.iter().any(|value| value["generated_named_obligation"] != true) {
        blockers.push("state/nonce/expiry/policy/receipt guards are source-visible but not named generated ProofPlan obligations");
    }
    if !features.iter().any(|feature| feature.contains("spawn") || feature.contains("bip340") || feature.contains("btc-verifier")) {
        blockers.push("btc_authority has no generated spawn/IPC wiring");
    }
    if !features.iter().any(|feature| feature.starts_with("create-output:ProofReceiptV0")) {
        blockers.push("ProofReceiptV0 output cell materialisation is not generated");
    }
    if measurement["measured"] != true {
        blockers.push("cycles, tx size, and occupied capacity are not measured");
    }
    json!({
        "schema": "novaseal-audit-surface-v0.1",
        "generated_from": bundle_display.to_string_lossy().replace('\\', "/"),
        "source_checked": source_display.to_string_lossy().replace('\\', "/"),
        "module": bundle.get("module").cloned().unwrap_or(Value::Null),
        "compiler_version": bundle.get("compiler_version").cloned().unwrap_or(Value::Null),
        "target_profile": bundle.get("target_profile").cloned().unwrap_or(Value::Null),
        "audit_bundle_status": bundle.get("status").cloned().unwrap_or(Value::Null),
        "summary": {
            "actions": actions.len(),
            "locks": locks.len(),
            "proof_plan_records": plan.len(),
            "runtime_gaps": gaps.len(),
            "builder_assumptions": assumptions.len(),
            "source_units": objects(bundle, "source_units").len(),
            "strict_prediction_errors": predictions.len(),
            "classification": "non_production_audit_surface"
        },
        "actions": actions,
        "locks": locks,
        "source_units": objects(bundle, "source_units").into_iter().cloned().collect::<Vec<_>>(),
        "proof_plan_soundness": bundle.get("proof_plan_soundness").cloned().unwrap_or_else(|| json!({})),
        "proof_plan": generated_plan,
        "runtime_gaps": gaps,
        "strict_mode_predictions": predictions,
        "field_guard_visibility": visibility,
        "capacity_evidence": capacity(bundle),
        "transaction_measurement_evidence": measurement,
        "builder_assumptions": assumptions,
        "production_blockers": blockers
    })
}

pub fn run(
    root: &Path,
    bundle: Option<&Path>,
    source: Option<&Path>,
    combined: Option<&Path>,
    output: Option<&Path>,
    pretty: bool,
) -> Result<i32> {
    let bundle_display = bundle.unwrap_or(Path::new("target/cellscript-audit-bundle/audit-bundle.json"));
    let source_display = source.unwrap_or(Path::new("src/nova_state_type.cell"));
    let combined_display = combined.unwrap_or(Path::new("target/novaseal-combined-tx-report.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-audit-surface.json"));
    let bundle_path = package_path(root, bundle_display);
    let bundle_value: Value = serde_json::from_slice(
        &fs::read(&bundle_path).with_context(|| format!("missing audit bundle: {}", bundle_display.display()))?,
    )?;
    let source_text = fs::read_to_string(package_path(root, source_display)).unwrap_or_default();
    let combined_path = package_path(root, combined_display);
    let combined_value = if combined_path.exists() {
        let value: Value = serde_json::from_slice(&fs::read(&combined_path)?)?;
        if !value.is_object() {
            bail!("expected JSON object in {}", combined_display.display());
        }
        value
    } else {
        json!({})
    };
    let report = build(&bundle_value, bundle_display, source_display, &source_text, &combined_value, combined_display);
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: actions={} locks={} proof_plan_records={} runtime_gaps={} strict_prediction_errors={}",
        summary["actions"],
        summary["locks"],
        summary["proof_plan_records"],
        summary["runtime_gaps"],
        summary["strict_prediction_errors"]
    );
    Ok(0)
}
