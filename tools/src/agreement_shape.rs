use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::shared::json_text;

const CKB: u64 = 100_000_000;
const U64_MAX: u64 = u64::MAX;
const AGREEMENT_OCCUPIED: u64 = 40 * CKB;
const RECEIPT_OCCUPIED: u64 = 20 * CKB;
const PAYOUT_OCCUPIED: u64 = 40 * CKB;
const BUILDER_FEE: u64 = 100_000;
const START: u64 = 100;
const EXPIRY: u64 = 200;
const COLLATERAL: u64 = 1_000 * CKB;
const PRINCIPAL: u64 = 700 * CKB;
const FIXED_FEE: u64 = 30 * CKB;

fn repeated(byte: &str) -> String {
    format!("0x{}", byte.repeat(32))
}

#[derive(Clone)]
struct OutputShape {
    role: &'static str,
    owner: String,
    occupied: u64,
    capacity: u64,
}

impl OutputShape {
    fn json(&self) -> Value {
        json!({
            "role": self.role, "owner": self.owner, "occupied_capacity_shannons": self.occupied,
            "capacity_shannons": self.capacity,
            "economic_value_shannons": self.capacity as i128 - self.occupied as i128
        })
    }
}

fn output(role: &'static str, owner: &str, occupied: u64, economic: u64) -> OutputShape {
    OutputShape { role, owner: owner.into(), occupied, capacity: occupied + economic }
}

fn under_capacity(role: &'static str, owner: &str, occupied: u64, missing: u64) -> OutputShape {
    OutputShape { role, owner: owner.into(), occupied, capacity: occupied - missing }
}

struct Case {
    fixture: &'static str,
    action: &'static str,
    time: u64,
    actor: String,
    outputs: Vec<OutputShape>,
    note: &'static str,
    principal: u64,
    fee: u64,
    nonce: u64,
}

fn case(fixture: &'static str, action: &'static str, time: u64, actor: &str, outputs: Vec<OutputShape>, note: &'static str) -> Case {
    Case { fixture, action, time, actor: actor.into(), outputs, note, principal: PRINCIPAL, fee: FIXED_FEE, nonce: 0 }
}

fn cases() -> Vec<Case> {
    let borrower = repeated("11");
    let lender = repeated("22");
    let stranger = repeated("33");
    let repayment_outputs = || {
        vec![
            output("closed_agreement", &borrower, AGREEMENT_OCCUPIED, 0),
            output("lender_repayment", &lender, PAYOUT_OCCUPIED, PRINCIPAL + FIXED_FEE),
            output("borrower_collateral_return", &borrower, PAYOUT_OCCUPIED, COLLATERAL),
            output("receipt", &borrower, RECEIPT_OCCUPIED, 0),
        ]
    };
    let mut result = vec![
        case(
            "originate_valid",
            "originate_agreement",
            120,
            &borrower,
            vec![
                output("agreement_collateral", &borrower, AGREEMENT_OCCUPIED, COLLATERAL),
                output("borrower_principal_payout", &borrower, PAYOUT_OCCUPIED, PRINCIPAL),
                output("receipt", &borrower, RECEIPT_OCCUPIED, 0),
            ],
            "Borrower locks collateral while lender-funded principal is paid to borrower.",
        ),
        case(
            "repay_before_expiry_valid",
            "repay_before_expiry",
            180,
            &borrower,
            repayment_outputs(),
            "Borrower repays principal plus fixed fee and receives collateral back.",
        ),
        case(
            "claim_after_expiry_valid",
            "claim_after_expiry",
            220,
            &lender,
            vec![
                output("closed_agreement", &lender, AGREEMENT_OCCUPIED, 0),
                output("lender_default_claim", &lender, PAYOUT_OCCUPIED, COLLATERAL),
                output("receipt", &lender, RECEIPT_OCCUPIED, 0),
            ],
            "After expiry, lender claims the locked collateral. No extra fixed fee is minted.",
        ),
        case(
            "expired_repay_reject",
            "repay_before_expiry",
            220,
            &borrower,
            repayment_outputs(),
            "Repayment after expiry must be rejected by the time guard.",
        ),
        case(
            "early_claim_reject",
            "claim_after_expiry",
            180,
            &lender,
            vec![
                output("closed_agreement", &lender, AGREEMENT_OCCUPIED, 0),
                output("lender_default_claim", &lender, PAYOUT_OCCUPIED, COLLATERAL),
                output("receipt", &lender, RECEIPT_OCCUPIED, 0),
            ],
            "Default claim before expiry must be rejected by the time guard.",
        ),
        case(
            "wrong_party_reject",
            "repay_before_expiry",
            180,
            &stranger,
            repayment_outputs(),
            "A non-borrower actor cannot exercise the repay path.",
        ),
        case(
            "under_capacity_reject",
            "repay_before_expiry",
            180,
            &borrower,
            vec![
                under_capacity("closed_agreement", &borrower, AGREEMENT_OCCUPIED, CKB),
                output("lender_repayment", &lender, PAYOUT_OCCUPIED, PRINCIPAL + FIXED_FEE),
                output("borrower_collateral_return", &borrower, PAYOUT_OCCUPIED, COLLATERAL),
                output("receipt", &borrower, RECEIPT_OCCUPIED, 0),
            ],
            "A terminal agreement output below occupied capacity is invalid.",
        ),
        case(
            "wrong_settlement_amount_reject",
            "repay_before_expiry",
            180,
            &borrower,
            vec![
                output("closed_agreement", &borrower, AGREEMENT_OCCUPIED, 0),
                output("lender_repayment", &lender, PAYOUT_OCCUPIED, PRINCIPAL + FIXED_FEE - CKB),
                output("borrower_collateral_return", &borrower, PAYOUT_OCCUPIED, COLLATERAL),
                output("receipt", &borrower, RECEIPT_OCCUPIED, 0),
            ],
            "The lender repayment output must equal principal plus fixed fee.",
        ),
    ];
    let arithmetic = [
        ("repay_principal_max_fee_1_overflow_reject", U64_MAX, 1, 0, "Repay terminal amount must reject when principal + fixed_fee would overflow u64."),
        ("repay_principal_max_fee_0_accept", U64_MAX, 0, 0, "Repay terminal amount arithmetic accepts the u64 boundary principal + zero-fee case; full payout capacity guards are separate."),
        ("nonce_max_increment_reject", PRINCIPAL, FIXED_FEE, U64_MAX, "Terminal nonce increment must reject when active.nonce is already U64_MAX."),
        ("nonce_max_minus_1_increment_accept", PRINCIPAL, FIXED_FEE, U64_MAX - 1, "Terminal nonce increment accepts U64_MAX - 1 because the new nonce is exactly U64_MAX."),
    ];
    result.extend(arithmetic.into_iter().map(|(fixture, principal, fee, nonce, note)| Case {
        fixture,
        action: "repay_arithmetic_boundary",
        time: 180,
        actor: borrower.clone(),
        outputs: vec![],
        note,
        principal,
        fee,
        nonce,
    }));
    result
}

fn expectations(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = fs::read_dir(path)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    files.sort();
    let mut result = BTreeMap::new();
    for file in files {
        let value: Value = serde_json::from_slice(&fs::read(&file)?)?;
        let fixture = value["fixture"].as_str().context("fixture field must be a string")?;
        let expected = value["expected"].as_str().context("expected field must be a string")?;
        if !matches!(expected, "accepted" | "rejected") {
            bail!("{} has unsupported expected value {expected:?}", file.display());
        }
        result.insert(fixture.into(), expected.into());
    }
    Ok(result)
}

fn economic(case: &Case, role: &str, expected: u64, failures: &mut Vec<String>) {
    let Some(value) = case.outputs.iter().find(|value| value.role == role) else {
        failures.push(format!("missing output role {role}"));
        return;
    };
    let actual = value.capacity as i128 - value.occupied as i128;
    if actual != expected as i128 {
        failures.push(format!("output role {role} economic value {actual} != expected {expected}"));
    }
}

fn evaluate(case: &Case, expected: &str) -> Value {
    let borrower = repeated("11");
    let lender = repeated("22");
    let mut failures = Vec::new();
    let terminal = case.principal.checked_add(case.fee);
    if terminal.is_none() {
        failures.push("principal plus fixed fee would overflow u64".into());
    }
    let new_nonce = case.nonce.checked_add(1);
    if new_nonce.is_none() {
        failures.push("nonce increment would overflow u64".into());
    }
    if case.action == "repay_arithmetic_boundary" {
        let accepted = failures.is_empty();
        return json!({
            "fixture": case.fixture, "action": case.action, "expected": expected, "accepted": accepted,
            "matched_expected": accepted == (expected == "accepted"), "current_timepoint": case.time,
            "actor_authority_hash": case.actor, "principal_amount_shannons": case.principal,
            "fixed_fee_amount_shannons": case.fee, "terminal_amount_shannons": terminal,
            "old_nonce": case.nonce, "new_nonce": new_nonce, "outputs": [], "total_output_capacity_shannons": 0,
            "protocol_input_capacity_shannons": 0, "builder_min_additional_input_capacity_shannons": 0,
            "failures": failures, "note": case.note
        });
    }
    for value in &case.outputs {
        if value.capacity < value.occupied {
            failures
                .push(format!("output role {} capacity {} below occupied capacity {}", value.role, value.capacity, value.occupied));
        }
    }
    match case.action {
        "originate_agreement" => {
            if case.time < START {
                failures.push("current_timepoint before start_timepoint".into());
            }
            if case.time > EXPIRY {
                failures.push("current_timepoint after expiry_timepoint".into());
            }
            if case.actor != borrower {
                failures.push("originator is not borrower".into());
            }
            economic(case, "agreement_collateral", COLLATERAL, &mut failures);
            economic(case, "borrower_principal_payout", PRINCIPAL, &mut failures);
            economic(case, "receipt", 0, &mut failures);
        }
        "repay_before_expiry" => {
            if case.time > EXPIRY {
                failures.push("current_timepoint after expiry_timepoint".into());
            }
            if case.actor != borrower {
                failures.push("actor is not borrower".into());
            }
            economic(case, "closed_agreement", 0, &mut failures);
            if let Some(value) = terminal {
                economic(case, "lender_repayment", value, &mut failures);
            }
            economic(case, "borrower_collateral_return", COLLATERAL, &mut failures);
            economic(case, "receipt", 0, &mut failures);
        }
        "claim_after_expiry" => {
            if case.time <= EXPIRY {
                failures.push("current_timepoint not after expiry_timepoint".into());
            }
            if case.actor != lender {
                failures.push("actor is not lender".into());
            }
            economic(case, "closed_agreement", 0, &mut failures);
            economic(case, "lender_default_claim", COLLATERAL, &mut failures);
            economic(case, "receipt", 0, &mut failures);
        }
        other => failures.push(format!("unsupported action {other}")),
    }
    let total = case.outputs.iter().map(|value| value.capacity).sum::<u64>();
    let protocol = if case.action == "originate_agreement" { 0 } else { AGREEMENT_OCCUPIED + COLLATERAL };
    let additional = total.saturating_add(BUILDER_FEE).saturating_sub(protocol);
    let accepted = failures.is_empty();
    json!({
        "fixture": case.fixture, "action": case.action, "expected": expected, "accepted": accepted,
        "matched_expected": accepted == (expected == "accepted"), "current_timepoint": case.time,
        "actor_authority_hash": case.actor, "outputs": case.outputs.iter().map(OutputShape::json).collect::<Vec<_>>(),
        "total_output_capacity_shannons": total, "protocol_input_capacity_shannons": protocol,
        "builder_min_additional_input_capacity_shannons": additional, "failures": failures, "note": case.note
    })
}

pub fn run(root: &Path, fixtures_dir: Option<&Path>, out: Option<&Path>, pretty: bool) -> Result<i32> {
    let package = root.join("agreement-profile-v0");
    let fixtures = fixtures_dir.map(Path::to_path_buf).unwrap_or_else(|| package.join("fixtures"));
    let out = out.map(Path::to_path_buf).unwrap_or_else(|| package.join("target/nova-agreement-tx-shape-report.json"));
    let expected = expectations(&fixtures)?;
    let cases = cases();
    let missing = cases.iter().filter(|case| !expected.contains_key(case.fixture)).map(|case| case.fixture).collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("missing fixture files for cases: {}", missing.join(", "));
    }
    let covered = cases.iter().map(|case| case.fixture.to_owned()).collect::<BTreeSet<_>>();
    let unexecuted = expected.keys().filter(|name| !covered.contains(name.as_str())).cloned().collect::<Vec<_>>();
    let results = cases.iter().map(|case| evaluate(case, &expected[case.fixture])).collect::<Vec<_>>();
    let mismatches = results.iter().filter(|case| case["matched_expected"] != true).count();
    let accepted = results.iter().filter(|case| case["accepted"] == true).count();
    let report = json!({
        "schema": "novaseal-agreement-tx-shape-report-v0.1", "package": "novaseal-agreement-profile-v0 0.0.1",
        "classification": "local-transaction-shape-evidence", "generated_by": "tools/src/agreement_shape.rs",
        "constants": {"ckb_shannons": CKB, "agreement_occupied_capacity_shannons": AGREEMENT_OCCUPIED,
            "receipt_occupied_capacity_shannons": RECEIPT_OCCUPIED, "payout_occupied_capacity_shannons": PAYOUT_OCCUPIED,
            "builder_fee_shannons": BUILDER_FEE},
        "canonical_terms": {"collateral_amount_shannons": COLLATERAL, "principal_amount_shannons": PRINCIPAL,
            "fixed_fee_amount_shannons": FIXED_FEE, "start_timepoint": START, "expiry_timepoint": EXPIRY,
            "borrower_authority_hash": repeated("11"), "lender_authority_hash": repeated("22")},
        "summary": {"total_cases": results.len(), "accepted_cases": accepted, "rejected_cases": results.len() - accepted,
            "matched_expected_cases": results.len() - mismatches, "mismatched_expected_cases": mismatches,
            "capacity_shape_checks_exercised": true, "settlement_amount_checks_exercised": true,
            "time_guards_exercised": true, "party_guards_exercised": true,
            "covered_fixture_names": covered, "unexecuted_fixture_names": unexecuted},
        "cases": results,
        "limits": ["Does not execute generated CellScript in CKB VM.", "Does not call ckb-verification.",
            "Does not prove live-chain RPC, deployment, mempool, or miner acceptance.",
            "Does not check typed payout, terms_hash, or receipt_hash output bindings; those are covered by the resolved transaction harness.",
            "Cryptographic borrower/lender authority locks are not implemented in this profile slice.",
            "Native CKB settlement capacity/value shape is checked here as local builder evidence."]
    });
    fs::create_dir_all(out.parent().context("output path has no parent")?)?;
    fs::write(&out, json_text(&report, pretty)?)?;
    println!("wrote {} total={} matched={} mismatched={}", out.display(), results.len(), results.len() - mismatches, mismatches);
    Ok(if mismatches == 0 { 0 } else { 1 })
}
