use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use blake2b_ref::Blake2bBuilder;
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

const ENCODING_PROFILE: &str = "packed-fixed-v0-reference";
const PACKED_HASH_DOMAIN: &[u8] = b"CellScriptPackedHashV0\0";

fn blake(personal: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut state = Blake2bBuilder::new(32).personal(personal).build();
    for chunk in chunks {
        state.update(chunk);
    }
    let mut digest = [0_u8; 32];
    state.finalize(&mut digest);
    digest
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn python_str(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => {
            format!("[{}]", values.iter().map(|value| format!("{:?}", python_str(value))).collect::<Vec<_>>().join(", "))
        }
        Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn byte32(value: &Value) -> (Vec<u8>, &'static str) {
    if let Some(text) = value.as_str() {
        let raw = text.strip_prefix("0x").unwrap_or(text);
        if raw.len() == 64
            && let Ok(bytes) = hex::decode(raw)
        {
            return (bytes, "literal_hex");
        }
    }
    (blake(b"NovaSealVecV0", &[b"Byte32", b"\0", python_str(value).as_bytes()]).to_vec(), "derived_from_placeholder")
}

fn uint(value: &Value, size: usize, context: &str) -> Result<(Vec<u8>, &'static str, u64)> {
    if value.is_boolean() {
        bail!("{context}: boolean is not a valid integer");
    }
    let number = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .with_context(|| format!("{context}: expected integer-compatible value, got {value:?}"))?;
    if size < 8 && number >= (1_u64 << (size * 8)) {
        bail!("{context}: integer {number} does not fit in {size} bytes");
    }
    Ok((number.to_le_bytes()[..size].to_vec(), "integer_literal", number))
}

fn packed_hash(type_name: &str, bytes: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut preimage = Vec::with_capacity(PACKED_HASH_DOMAIN.len() + type_name.len() + 5 + bytes.len());
    preimage.extend_from_slice(PACKED_HASH_DOMAIN);
    preimage.extend_from_slice(type_name.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    preimage.extend_from_slice(bytes);
    let digest = blake(b"ckb-default-hash", &[&preimage]);
    (preimage, digest)
}

fn type_map(layout: &Value) -> BTreeMap<String, Value> {
    layout
        .get("types")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|ty| ty.get("name").and_then(Value::as_str).map(|name| (name.to_owned(), ty.clone())))
        .collect()
}

fn encode_outpoint(value: &Value, context: &str) -> Result<(Vec<u8>, Value, &'static str)> {
    let (tx_hash_value, index_value, source) = if let Some(object) = value.as_object() {
        (
            object.get("tx_hash").cloned().unwrap_or_else(|| json!(format!("{context}:tx_hash"))),
            object.get("index").cloned().unwrap_or_else(|| json!(0)),
            "object",
        )
    } else {
        (json!(format!("{}:tx_hash", python_str(value))), json!(0), "derived_from_placeholder")
    };
    let (tx_hash, tx_source) = byte32(&tx_hash_value);
    let (index, index_source, number) = uint(&index_value, 4, &format!("{context}.index"))?;
    let mut encoded = tx_hash.clone();
    encoded.extend_from_slice(&index);
    Ok((
        encoded,
        json!([
            {"name": "tx_hash", "hex": hex0x(&tx_hash), "source": tx_source},
            {"name": "index", "hex": hex0x(&index), "source": index_source, "value": number}
        ]),
        source,
    ))
}

fn encode_struct(type_name: &str, values: &Map<String, Value>, types: &BTreeMap<String, Value>, context: &str) -> Result<Value> {
    let layout = types.get(type_name).with_context(|| format!("missing layout for {type_name}"))?;
    let layout_fields = layout.get("fields").and_then(Value::as_array).context("layout fields must be an array")?;
    let mut encoded = Vec::new();
    let mut field_rows = Vec::new();
    for field in layout_fields {
        let name = field.get("name").and_then(Value::as_str).context("layout field missing name")?;
        let ty = field.get("type").and_then(Value::as_str).context("layout field missing type")?;
        let value = values.get(name).with_context(|| format!("{context}: missing field {name}"))?;
        let field_context = format!("{context}.{name}");
        let mut detail = Map::new();
        let bytes = match ty {
            "Byte32" => {
                let (bytes, source) = byte32(value);
                detail.insert("source".into(), json!(source));
                bytes
            }
            "u8" | "u16" | "u32" | "u64" => {
                let size = field.get("size_bytes").and_then(Value::as_u64).unwrap() as usize;
                let (bytes, source, number) = uint(value, size, &field_context)?;
                detail.insert("source".into(), json!(source));
                detail.insert("value".into(), json!(number));
                bytes
            }
            "OutPoint" => {
                let (bytes, components, source) = encode_outpoint(value, &field_context)?;
                detail.insert("source".into(), json!(source));
                detail.insert("components".into(), components);
                bytes
            }
            nested if types.contains_key(nested) => {
                let nested_values =
                    value.as_object().with_context(|| format!("{field_context}: nested {nested} requires an object value"))?;
                let nested = encode_struct(nested, nested_values, types, &field_context)?;
                let bytes = hex::decode(nested["hex"].as_str().unwrap().trim_start_matches("0x"))?;
                detail.insert("source".into(), json!("nested_fixed_type"));
                detail.insert("nested".into(), nested);
                bytes
            }
            _ => bail!("{field_context}: unsupported field type {ty}"),
        };
        let mut row = Map::new();
        row.insert("name".into(), json!(name));
        row.insert("type".into(), json!(ty));
        row.insert("offset".into(), field.get("offset").cloned().unwrap_or(Value::Null));
        row.insert("size_bytes".into(), field.get("size_bytes").cloned().unwrap_or(Value::Null));
        row.insert("hex".into(), json!(hex0x(&bytes)));
        row.extend(detail);
        field_rows.push(Value::Object(row));
        encoded.extend_from_slice(&bytes);
    }
    let expected_size = layout.get("total_static_size_bytes").and_then(Value::as_u64).unwrap() as usize;
    if encoded.len() != expected_size {
        bail!("{context}: encoded {} bytes, expected {expected_size}", encoded.len());
    }
    let (preimage, digest) = packed_hash(type_name, &encoded);
    Ok(json!({
        "type": type_name,
        "encoding_profile": ENCODING_PROFILE,
        "size_bytes": encoded.len(),
        "hex": hex0x(&encoded),
        "hash_preimage_rule": "CellScriptPackedHashV0\\0 || canonical_type_name || \\0 || u32_le(byte_len) || packed_bytes",
        "hash_preimage_hex": hex0x(&preimage),
        "digest_blake2b_256": hex0x(&digest),
        "fields": field_rows
    }))
}

fn merge(base: &mut Value, patch: &Value) {
    if let (Some(base), Some(patch)) = (base.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            if let Some(existing) = base.get_mut(key)
                && existing.is_object()
                && value.is_object()
            {
                merge(existing, value);
            } else {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

fn baseline() -> Value {
    json!({
        "old_cell": {
            "version": 0,
            "btc_authority_hash": "0xc89fe99d72fcfa969434ddd87bb186a48213e9df3ec4b8a77042cf9559fc5765",
            "state_hash": "0xstate-old",
            "policy_hash": "0xpolicy",
            "latest_receipt_hash": "0xreceipt-root",
            "nonce": 42,
            "expiry": 999999
        },
        "intent": {
            "protocol_id": "0xnovaseal-domain",
            "package_hash": "0xpackage",
            "action": 1,
            "terminal_path": 0,
            "old_cell": "0xoutpoint",
            "old_state_hash": "0xstate-old",
            "new_state_hash": "0xstate-new",
            "policy_hash": "0xpolicy",
            "expected_receipt_hash": "0xreceipt",
            "old_nonce": 42,
            "new_nonce": 43,
            "expiry": 1000
        },
        "current_timepoint": 200,
        "actual_old_cell": "0xoutpoint",
        "btc_signature": "valid (source-model delegate success)",
        "btc_authority_pubkey_matches": true,
        "lock_args_authority_matches": true,
        "proposed_new_cell": {}
    })
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn model_hash(value: &Value) -> String {
    hex0x(&blake(b"NovaSealModel", &[python_str(value).as_bytes()]))
}

pub(crate) fn normalize(fixture: &Value) -> Value {
    let raw = fixture.get("inputs").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({}));
    let mut model = baseline();
    merge(&mut model, &raw);
    let raw_intent = raw.get("intent").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({}));
    if raw_intent.get("nonce").is_some() && raw_intent.get("new_nonce").is_none() {
        model["intent"]["new_nonce"] = raw_intent["nonce"].clone();
    }
    if raw_intent.get("receipt_hash").is_some() && raw_intent.get("expected_receipt_hash").is_none() {
        model["intent"]["expected_receipt_hash"] = raw_intent["receipt_hash"].clone();
    }
    model["materialized_receipt_hash"] =
        raw.get("actual_receipt_hash").cloned().unwrap_or_else(|| model["intent"]["expected_receipt_hash"].clone());
    model["state_hash_commitment"] =
        raw.get("state_hash_commitment").cloned().unwrap_or_else(|| json!(model_hash(&model["intent"]["new_state_hash"])));
    let signature_ok = if let Some(value) = raw.get("btc_signature_result").and_then(Value::as_bool) {
        value
    } else {
        let text = raw.get("btc_signature").cloned().unwrap_or_else(|| baseline()["btc_signature"].clone());
        let text = python_str(&text).to_lowercase();
        if ["invalid", "failure", "reject"].iter().any(|token| text.contains(token)) {
            false
        } else {
            ["valid", "success"].iter().any(|token| text.contains(token))
        }
    };
    model["signature_ok"] = json!(signature_ok);
    model["btc_authority_pubkey_matches"] =
        json!(truthy(raw.get("btc_authority_pubkey_matches").unwrap_or(&baseline()["btc_authority_pubkey_matches"])));
    model["lock_args_authority_matches"] =
        json!(truthy(raw.get("lock_args_authority_matches").unwrap_or(&baseline()["lock_args_authority_matches"])));
    model
}

fn outpoint(value: &Value) -> (Value, u64) {
    if let Some(object) = value.as_object() {
        return (object.get("tx_hash").cloned().unwrap_or(Value::Null), object.get("index").and_then(Value::as_u64).unwrap_or(0));
    }
    (json!(format!("{}:tx_hash", python_str(value))), 0)
}

pub(crate) fn model_result(model: &Value) -> Value {
    let old = &model["old_cell"];
    let intent = &model["intent"];
    let mut checks = Vec::new();
    let mut add = |name: &str, passed: bool, failure: &str| {
        checks.push(json!({"name": name, "passed": passed, "failure_mode": if passed { Value::Null } else { json!(failure) }}));
        passed
    };
    let mut failed = None;
    macro_rules! check {
        ($name:expr, $condition:expr, $failure:expr) => {
            if failed.is_none() && !add($name, $condition, $failure) {
                failed = Some($failure);
            }
        };
    }
    check!("btc_signature_delegate", truthy(&model["signature_ok"]), "btc_signature_verification_failed");
    check!("lock_args_authority_matches", truthy(&model["lock_args_authority_matches"]), "authority_hash_mapping_mismatch");
    check!("btc_authority_pubkey_bound", truthy(&model["btc_authority_pubkey_matches"]), "btc_authority_pubkey_mismatch");
    if failed.is_none() {
        let (intent_hash, intent_index) = outpoint(&intent["old_cell"]);
        let actual_value = model.get("actual_old_cell").unwrap_or(&intent["old_cell"]);
        let (actual_hash, actual_index) = outpoint(actual_value);
        check!("old_outpoint_tx_hash_matches", intent_hash == actual_hash, "old_outpoint_tx_hash_mismatch");
        check!("old_outpoint_index_matches", intent_index == actual_index, "old_outpoint_index_mismatch");
    }
    check!("old_state_hash_matches", intent["old_state_hash"] == old["state_hash"], "state_hash_mismatch");
    check!(
        "state_hash_commitment_matches",
        model["state_hash_commitment"] == json!(model_hash(&intent["new_state_hash"])),
        "state_hash_commitment_mismatch"
    );
    check!("policy_hash_matches", intent["policy_hash"] == old["policy_hash"], "policy_hash_mismatch");
    check!("old_nonce_matches", intent["old_nonce"] == old["nonce"], "old_nonce_mismatch");
    check!("nonce_not_at_u64_max", old["nonce"].as_u64().unwrap_or(u64::MAX) < u64::MAX, "nonce_overflow");
    check!("nonce_increments", intent["new_nonce"].as_u64() == old["nonce"].as_u64().map(|value| value + 1), "nonce_must_increment");
    check!(
        "intent_not_expired",
        model["current_timepoint"].as_u64().unwrap_or(u64::MAX) <= intent["expiry"].as_u64().unwrap_or(0),
        "intent_expired"
    );
    check!("receipt_hash_matches", model["materialized_receipt_hash"] == intent["expected_receipt_hash"], "receipt_hash_mismatch");
    let proposed = model.get("proposed_new_cell").and_then(Value::as_object);
    let proposed_authority = proposed.and_then(|value| value.get("btc_authority_hash")).unwrap_or(&old["btc_authority_hash"]);
    check!("authority_not_rotated_implicitly", proposed_authority == &old["btc_authority_hash"], "implicit_authority_rotation");
    if let Some(failure) = failed {
        json!({"result": "rejected", "failure_mode": failure, "checks": checks, "new_cell": Value::Null})
    } else {
        json!({
            "result": "accepted",
            "failure_mode": Value::Null,
            "checks": checks,
            "new_cell": {
                "version": old["version"],
                "btc_authority_hash": old["btc_authority_hash"],
                "state_hash": intent["new_state_hash"],
                "policy_hash": old["policy_hash"],
                "latest_receipt_hash": model["materialized_receipt_hash"],
                "nonce": intent["new_nonce"],
                "expiry": intent["expiry"]
            }
        })
    }
}

fn core_values(model: &Value) -> Map<String, Value> {
    let intent = model["intent"].as_object().unwrap();
    [
        "protocol_id",
        "package_hash",
        "policy_hash",
        "action",
        "terminal_path",
        "old_cell",
        "old_state_hash",
        "new_state_hash",
        "old_nonce",
        "new_nonce",
        "expiry",
    ]
    .into_iter()
    .map(|key| (key.to_owned(), intent.get(key).cloned().unwrap_or(Value::Null)))
    .collect()
}

fn cell_commitment(old: &Value, core: &Map<String, Value>) -> Map<String, Value> {
    [
        ("version", old["version"].clone()),
        ("btc_authority_hash", old["btc_authority_hash"].clone()),
        ("state_hash", core["new_state_hash"].clone()),
        ("policy_hash", old["policy_hash"].clone()),
        ("nonce", core["new_nonce"].clone()),
        ("expiry", core["expiry"].clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn receipt_commitment(core: &Map<String, Value>, new_cell_hash: &str, intent_hash: &str) -> Map<String, Value> {
    let mut values = core.clone();
    values.insert("new_cell_commitment".into(), json!(new_cell_hash));
    values.insert("intent_core_hash".into(), json!(intent_hash));
    values.insert("payout_commitment_hash".into(), json!(format!("0x{}", "00".repeat(32))));
    values
}

fn receipt_values(
    model: &Value,
    core: &Map<String, Value>,
    new_cell_hash: &str,
    intent_hash: &str,
    signed_hash: &str,
) -> Map<String, Value> {
    let mut values = receipt_commitment(core, new_cell_hash, intent_hash);
    values.insert("signed_intent_hash".into(), json!(signed_hash));
    values.insert("signer_authority_hash".into(), model["old_cell"]["btc_authority_hash"].clone());
    values.insert("expiry".into(), core["expiry"].clone());
    values
}

fn new_cell_values(model: &Value, receipt_hash: &str) -> Map<String, Value> {
    let old = &model["old_cell"];
    let core = core_values(model);
    [
        ("version", old["version"].clone()),
        ("btc_authority_hash", old["btc_authority_hash"].clone()),
        ("state_hash", core["new_state_hash"].clone()),
        ("policy_hash", old["policy_hash"].clone()),
        ("latest_receipt_hash", json!(receipt_hash)),
        ("nonce", core["new_nonce"].clone()),
        ("expiry", core["expiry"].clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn resolved(model: &Value, types: &BTreeMap<String, Value>, context: &str) -> Result<Value> {
    let core = core_values(model);
    let intent_core = encode_struct("NovaSealIntentCoreV0", &core, types, &format!("{context}.intent_core"))?;
    let intent_hash = intent_core["digest_blake2b_256"].as_str().unwrap();
    let new_commitment = encode_struct(
        "NovaSealCellCommitmentV0",
        &cell_commitment(&model["old_cell"], &core),
        types,
        &format!("{context}.new_cell_commitment"),
    )?;
    let new_hash = new_commitment["digest_blake2b_256"].as_str().unwrap();
    let receipt_commitment = encode_struct(
        "ProofReceiptCommitmentV0",
        &receipt_commitment(&core, new_hash, intent_hash),
        types,
        &format!("{context}.receipt_commitment"),
    )?;
    let receipt_hash = receipt_commitment["digest_blake2b_256"].as_str().unwrap();
    let signed_values = [("core".to_owned(), Value::Object(core.clone())), ("expected_receipt_hash".to_owned(), json!(receipt_hash))]
        .into_iter()
        .collect();
    let signed_intent = encode_struct("NovaSealSignedIntentV0", &signed_values, types, &format!("{context}.signed_intent"))?;
    let signed_hash = signed_intent["digest_blake2b_256"].as_str().unwrap();
    let receipt = encode_struct(
        "ProofReceiptV0",
        &receipt_values(model, &core, new_hash, intent_hash, signed_hash),
        types,
        &format!("{context}.receipt"),
    )?;
    let new_cell = encode_struct("NovaSealCellV0", &new_cell_values(model, receipt_hash), types, &format!("{context}.new_cell"))?;
    Ok(json!({
        "rule": "latest_receipt_hash = hash_blake2b_packed(ProofReceiptCommitmentV0)",
        "intent_core": intent_core,
        "new_cell_commitment": new_commitment,
        "receipt_commitment": receipt_commitment,
        "resolved_receipt_hash": receipt_hash,
        "resolved_intent": signed_intent,
        "signed_intent": signed_intent,
        "signed_intent_hash": signed_hash,
        "resolved_receipt": receipt,
        "resolved_new_cell": new_cell,
        "receipt_hash_matches_intent": true,
        "new_cell_latest_receipt_hash_matches": true
    }))
}

fn fixture_vector(path: &Path, types: &BTreeMap<String, Value>) -> Result<Value> {
    let fixture: Value = serde_json::from_slice(&fs::read(path)?)?;
    let model = normalize(&fixture);
    let result = model_result(&model);
    let stem = path.file_stem().unwrap().to_string_lossy();
    let old_cell = encode_struct("NovaSealCellV0", model["old_cell"].as_object().unwrap(), types, &format!("{stem}.old_cell"))?;
    let core = core_values(&model);
    let declared_values = [
        ("core".to_owned(), Value::Object(core)),
        ("expected_receipt_hash".to_owned(), model["intent"]["expected_receipt_hash"].clone()),
    ]
    .into_iter()
    .collect();
    let declared = encode_struct("NovaSealSignedIntentV0", &declared_values, types, &format!("{stem}.declared_intent"))?;
    let resolved = resolved(&model, types, &format!("{stem}.resolved"))?;
    let (declared_receipt, declared_source) = byte32(&model["intent"]["expected_receipt_hash"]);
    Ok(json!({
        "fixture": path.file_name().unwrap().to_string_lossy(),
        "name": fixture.get("name").cloned().unwrap_or_else(|| json!(stem)),
        "category": fixture.get("category").cloned().unwrap_or(Value::Null),
        "source_model_result": {"result": result["result"], "failure_mode": result["failure_mode"]},
        "encoded": {
            "old_cell": old_cell,
            "declared_intent": declared,
            "new_cell": if result["new_cell"].is_null() { Value::Null } else { resolved["resolved_new_cell"].clone() },
            "resolved": resolved
        },
        "hashes": {
            "intent_core_hash": resolved["intent_core"]["digest_blake2b_256"],
            "declared_signed_intent_hash": declared["digest_blake2b_256"],
            "declared_expected_receipt_hash": hex0x(&declared_receipt),
            "declared_expected_receipt_hash_source": declared_source,
            "new_cell_commitment_hash": resolved["new_cell_commitment"]["digest_blake2b_256"],
            "resolved_receipt_hash": resolved["resolved_receipt_hash"],
            "latest_receipt_hash": resolved["resolved_receipt_hash"],
            "resolved_receipt_hash_matches_intent": resolved["receipt_hash_matches_intent"],
            "new_cell_latest_receipt_hash_matches": resolved["new_cell_latest_receipt_hash_matches"],
            "signed_intent_hash_after_resolved_receipt": resolved["signed_intent_hash"]
        },
        "notes": [
            "The declared_intent vector preserves the fixture-declared expected_receipt_hash for mismatch fixtures.",
            "The resolved vector uses the v0 split intent rule and CellScript hash_blake2b_packed preimage.",
            "Byte32 placeholders are deterministically derived for test-vector stability."
        ]
    }))
}

fn analysis() -> Value {
    json!({
        "status": "split_intent_and_explicit_receipt_commitment",
        "selected_rule": {
            "intent_core_hash": "hash_blake2b_packed(NovaSealIntentCoreV0)",
            "latest_receipt_hash": "hash_blake2b_packed(ProofReceiptCommitmentV0)",
            "signed_intent_hash": "hash_blake2b_packed(NovaSealSignedIntentV0 { core, expected_receipt_hash })",
            "new_cell_commitment": "hash_blake2b_packed(NovaSealCellCommitmentV0), excluding latest_receipt_hash"
        },
        "why_this_breaks_the_cycle": [
            "ProofReceiptCommitmentV0 commits to intent_core_hash, not signed_intent_hash.",
            "NovaSealSignedIntentV0 commits to the expected receipt hash after the receipt commitment is materialized.",
            "NovaSealCellV0.latest_receipt_hash stores the current transition commitment only; it is not a rolling root."
        ],
        "remaining_limits": [
            "This is still a packed-reference vector rule, not Molecule output.",
            "Wallet/verifier signing rules must adopt this exact preimage before production."
        ]
    })
}

pub fn run(root: &Path, fixtures: Option<&Path>, layout: Option<&Path>, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let fixtures_display = fixtures.unwrap_or(Path::new("fixtures"));
    let layout_display = layout.unwrap_or(Path::new("target/novaseal-schema-layout.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-canonical-vectors.json"));
    let fixtures_path = package_path(root, fixtures_display);
    let layout_value: Value = serde_json::from_slice(&fs::read(package_path(root, layout_display))?)?;
    let types = type_map(&layout_value);
    let mut paths = fs::read_dir(&fixtures_path)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<PathBuf>>();
    paths.sort();
    let vectors = paths.iter().map(|path| fixture_vector(path, &types)).collect::<Result<Vec<_>>>()?;
    let accepted = vectors.iter().filter(|vector| !vector["encoded"]["new_cell"].is_null()).count();
    let resolved_matches = vectors.iter().filter(|vector| vector["hashes"]["resolved_receipt_hash_matches_intent"] == true).count();
    let latest_matches = vectors.iter().filter(|vector| vector["hashes"]["new_cell_latest_receipt_hash_matches"] == true).count();
    let report = json!({
        "schema": "novaseal-canonical-vectors-v0.2",
        "encoding_profile": ENCODING_PROFILE,
        "hash_preimage_rule": "CellScriptPackedHashV0\\0 || canonical_type_name || \\0 || u32_le(byte_len) || packed_bytes",
        "hash_algorithm": "blake2b-256(personal=ckb-default-hash)",
        "layout_artifact": layout_display.to_string_lossy().replace('\\', "/"),
        "layout_fingerprint_sha256": layout_value.get("layout_fingerprint_sha256").cloned().unwrap_or(Value::Null),
        "fixtures": fixtures_display.to_string_lossy().replace('\\', "/"),
        "summary": {
            "vectors": vectors.len(),
            "old_cell_vectors": vectors.len(),
            "intent_core_vectors": vectors.len(),
            "signed_intent_vectors": vectors.len(),
            "receipt_commitment_vectors": vectors.len(),
            "accepted_new_cell_vectors": accepted,
            "resolved_receipt_hash_matches_intent": resolved_matches,
            "new_cell_latest_receipt_hash_matches": latest_matches,
            "classification": "packed_reference_test_vectors"
        },
        "receipt_commitment_analysis": analysis(),
        "vectors": vectors,
        "limitations": [
            "Not Molecule output.",
            "Not CKB VM witness encoding.",
            "Not BTC wallet signing material.",
            "Placeholder Byte32 values are deterministic test derivations, not protocol constants."
        ]
    });
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: vectors={} signed_intent_vectors={} resolved_receipt_matches={} latest_receipt_matches={} classification={}",
        summary["vectors"],
        summary["signed_intent_vectors"],
        summary["resolved_receipt_hash_matches_intent"],
        summary["new_cell_latest_receipt_hash_matches"],
        summary["classification"].as_str().unwrap()
    );
    println!("receipt_commitment_status={}", report["receipt_commitment_analysis"]["status"].as_str().unwrap());
    Ok(0)
}
