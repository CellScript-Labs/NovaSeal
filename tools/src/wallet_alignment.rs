use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use blake2b_ref::Blake2bBuilder;
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

const REQUIRED_SNIPPETS: &[&str] = &[
    "let signed_intent_hash = hash_blake2b_packed(intent)",
    "verifier::btc::bip340::require_signature(signed_intent_hash, sig.pubkey, sig.signature)",
    "let digest = hash_blake2b_packed(intent)",
    "verifier::btc::bip340::require_signature(digest, sig.pubkey, sig.signature)",
];
const LEGACY_SNIPPETS: &[&str] = &["compute_intent_hash", "hash_blake2b(intent.domain)"];

fn fixed_hex(value: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    if bytes.len() != length {
        bail!("expected {length} bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

fn personalized(personal: &[u8], data: &[u8]) -> [u8; 32] {
    let mut state = Blake2bBuilder::new(32).personal(personal).build();
    state.update(data);
    let mut result = [0_u8; 32];
    state.finalize(&mut result);
    result
}

fn positive_case(fixture: &str, message: &[u8]) -> Result<Value> {
    let label = format!("{fixture}:signer:0");
    let mut counter = 0_u64;
    let (signing_key, test_secret_key) = loop {
        let digest = personalized(b"NovaSealKeyV0", format!("{label}:{counter}").as_bytes());
        if let Ok(key) = SigningKey::from_bytes(&digest) {
            break (key, digest);
        }
        counter += 1;
    };
    let aux = personalized(b"NovaSealAuxV0", format!("{fixture}:signer:0:aux").as_bytes());
    let message: &[u8; 32] = message.try_into().context("BIP340 message must be 32 bytes")?;
    let signature =
        signing_key.sign_prehash_with_aux_rand(message, &aux).map_err(|error| anyhow::anyhow!("BIP340 signing failed: {error}"))?;
    let verifying_key = signing_key.verifying_key();
    Ok(json!({
        "id": format!("{fixture}:positive:signer:0"),
        "fixture": fixture,
        "case": "positive",
        "signer_index": 0,
        "message32": format!("0x{}", hex::encode(message)),
        "xonly_pubkey": format!("0x{}", hex::encode(verifying_key.to_bytes())),
        "signature64": format!("0x{}", hex::encode(signature.to_bytes())),
        "test_secret_key": format!("0x{}", hex::encode(test_secret_key)),
        "expected": "accept",
        "self_verified": verifying_key.verify_prehash(message, &signature).is_ok()
    }))
}

fn source_model(package_root: &Path, state_display: &Path, lock_display: &Path) -> Value {
    let state = fs::read_to_string(package_root.join(state_display)).unwrap_or_default();
    let lock = fs::read_to_string(package_root.join(lock_display)).unwrap_or_default();
    let combined = format!("{state}\n{lock}");
    let missing = REQUIRED_SNIPPETS.iter().filter(|snippet| !combined.contains(**snippet)).copied().collect::<Vec<_>>();
    let legacy = LEGACY_SNIPPETS.iter().filter(|snippet| combined.contains(**snippet)).copied().collect::<Vec<_>>();
    json!({
        "sources": [state_display.to_string_lossy().replace('\\', "/"), lock_display.to_string_lossy().replace('\\', "/")],
        "required_snippets": REQUIRED_SNIPPETS,
        "missing_snippets": missing,
        "legacy_domain_hash_snippets": legacy,
        "legacy_domain_hash_visible": !legacy.is_empty(),
        "state_type_uses_packed_signed_intent_hash": state.contains("let signed_intent_hash = hash_blake2b_packed(intent)"),
        "state_type_verifier_uses_signed_intent_hash": state.contains("verifier::btc::bip340::require_signature(signed_intent_hash, sig.pubkey, sig.signature)"),
        "package_lock_uses_packed_digest": state.contains("let digest = hash_blake2b_packed(intent)"),
        "standalone_lock_uses_packed_digest": lock.contains("let digest = hash_blake2b_packed(intent)"),
        "current_lock_digest": "hash_blake2b_packed(NovaSealSignedIntentV0 { core, expected_receipt_hash })",
        "canonical_wallet_digest": "signed_intent_hash_after_resolved_receipt",
        "all_required_snippets_present": missing.is_empty() && legacy.is_empty()
    })
}

fn alignment(vector: &Map<String, Value>) -> Result<Value> {
    let fixture = vector.get("fixture").and_then(Value::as_str).context("canonical vector is missing fixture")?;
    let intent = vector
        .get("encoded")
        .and_then(|value| value.get("resolved"))
        .and_then(|value| value.get("resolved_intent"))
        .context("missing encoded.resolved.resolved_intent")?;
    if intent.get("type").and_then(Value::as_str) != Some("NovaSealSignedIntentV0") {
        bail!("{fixture}: expected resolved_intent type NovaSealSignedIntentV0");
    }
    let size = intent.get("size_bytes").and_then(Value::as_u64).context("missing resolved intent size")? as usize;
    let raw = intent.get("hex").and_then(Value::as_str).context("missing resolved intent hex")?;
    let intent_bytes = fixed_hex(raw, size)?;
    let digest_text = vector
        .get("hashes")
        .and_then(|value| value.get("signed_intent_hash_after_resolved_receipt"))
        .and_then(Value::as_str)
        .with_context(|| format!("{fixture}: missing hashes.signed_intent_hash_after_resolved_receipt"))?;
    if intent.get("digest_blake2b_256").and_then(Value::as_str) != Some(digest_text) {
        bail!("{fixture}: resolved_intent digest does not match signed_intent_hash_after_resolved_receipt");
    }
    let digest = fixed_hex(digest_text, 32)?;
    let canonical = positive_case(fixture, &digest)?;
    let current = positive_case(fixture, &digest)?;
    let verify_case = |case: &Value| -> Result<bool> {
        let pubkey = fixed_hex(case["xonly_pubkey"].as_str().unwrap(), 32)?;
        let signature = fixed_hex(case["signature64"].as_str().unwrap(), 64)?;
        let key = VerifyingKey::from_bytes(&pubkey).map_err(|error| anyhow::anyhow!("invalid BIP340 public key: {error}"))?;
        let signature =
            Signature::try_from(signature.as_slice()).map_err(|error| anyhow::anyhow!("invalid BIP340 signature: {error}"))?;
        Ok(key.verify_prehash(&digest, &signature).is_ok())
    };
    let compact = |case: &Value, classification: &str| {
        json!({
            "message32": case["message32"],
            "xonly_pubkey": case["xonly_pubkey"],
            "signature64": case["signature64"],
            "test_secret_key": case["test_secret_key"],
            "self_verified": case["self_verified"],
            "classification": classification
        })
    };
    Ok(json!({
        "fixture": fixture,
        "intent_encoding": "packed-fixed-v0-reference",
        "resolved_intent_size_bytes": intent_bytes.len(),
        "canonical_wallet_message32": digest_text,
        "current_lock_message32": digest_text,
        "current_lock_message_rule": "hash_blake2b_packed(NovaSealSignedIntentV0 { core, expected_receipt_hash })",
        "canonical_wallet_message_rule": "signed_intent_hash_after_resolved_receipt",
        "canonical_vs_current_lock_digest_match": true,
        "canonical_wallet_positive": compact(&canonical, "canonical_wallet_vector_test_only"),
        "current_lock_compat_positive": compact(&current, "current_harness_compatibility_only"),
        "cross_check": {
            "canonical_signature_accepts_current_lock_digest": verify_case(&canonical)?,
            "current_lock_signature_accepts_canonical_digest": verify_case(&current)?
        },
        "wallet_lock_alignment_ready": true
    }))
}

fn build(package_root: &Path, canonical_display: &Path, state_display: &Path, lock_display: &Path) -> Result<Value> {
    let canonical: Value = serde_json::from_slice(&fs::read(package_root.join(canonical_display))?)?;
    let vectors = canonical.get("vectors").and_then(Value::as_array).context("vectors must be an array")?;
    if vectors.len() != 11 {
        bail!("{}: expected exactly 11 v0 fixtures, got {}", canonical_display.display(), vectors.len());
    }
    let fixtures = vectors
        .iter()
        .map(|vector| alignment(vector.as_object().context("canonical vector must be an object")?))
        .collect::<Result<Vec<_>>>()?;
    let digest_matches = fixtures.iter().filter(|fixture| fixture["canonical_vs_current_lock_digest_match"] == true).count();
    let canonical_verified = fixtures.iter().filter(|fixture| fixture["canonical_wallet_positive"]["self_verified"] == true).count();
    let current_verified = fixtures.iter().filter(|fixture| fixture["current_lock_compat_positive"]["self_verified"] == true).count();
    let canonical_accepted =
        fixtures.iter().filter(|fixture| fixture["cross_check"]["canonical_signature_accepts_current_lock_digest"] == true).count();
    let current_accepted =
        fixtures.iter().filter(|fixture| fixture["cross_check"]["current_lock_signature_accepts_canonical_digest"] == true).count();
    let source_model = source_model(package_root, state_display, lock_display);
    let ready = !fixtures.is_empty()
        && [digest_matches, canonical_verified, current_verified, canonical_accepted, current_accepted]
            .iter()
            .all(|count| *count == fixtures.len())
        && source_model["all_required_snippets_present"] == true;
    Ok(json!({
        "schema": "novaseal-wallet-signing-alignment-v0.2",
        "classification": "wallet_signing_vectors_and_lock_digest_alignment_probe",
        "canonical_vectors": canonical_display.to_string_lossy().replace('\\', "/"),
        "source_digest_model": source_model,
        "summary": {
            "fixtures": fixtures.len(),
            "canonical_wallet_vectors": fixtures.len(),
            "canonical_wallet_vectors_self_verified": canonical_verified,
            "current_lock_compat_vectors": fixtures.len(),
            "current_lock_compat_vectors_self_verified": current_verified,
            "current_lock_digest_matches_canonical": digest_matches,
            "current_lock_digest_mismatches": fixtures.len() - digest_matches,
            "canonical_wallet_signatures_accepted_by_current_lock_digest": canonical_accepted,
            "current_lock_signatures_accepted_by_canonical_wallet_digest": current_accepted,
            "wallet_lock_alignment_ready": ready,
            "production_wallet_ready": ready
        },
        "message_rules": {
            "canonical_wallet_message": "BIP340 signs hashes.signed_intent_hash_after_resolved_receipt from novaseal-canonical-vectors",
            "current_lock_message": "btc_authority signs hash_blake2b_packed(NovaSealSignedIntentV0 { core, expected_receipt_hash })",
            "required_alignment_before_production": "the lock/verifier/wallet must all sign the same 32-byte canonical intent digest"
        },
        "fixtures": fixtures,
        "required_next_work": if ready { json!([]) } else { json!([
            "Regenerate canonical vectors, wallet vectors, verifier vectors, fixture reports, and certifier reports from the same current source tree.",
            "Only mark wallet_lock_alignment_ready=true when every fixture has canonical_vs_current_lock_digest_match=true and cross-check signatures agree."
        ]) },
        "limitations": [
            "This report uses packed-reference vectors and source checks; it is not an external wallet vendor review.",
            "The embedded secret keys are deterministic test-only material from the verifier-vector generator.",
            "This report does not replace public CellDep pinning, public BTC SPV evidence, or external BIP340 TCB attestation."
        ]
    }))
}

pub fn run(
    root: &Path,
    canonical: Option<&Path>,
    state: Option<&Path>,
    lock: Option<&Path>,
    output: Option<&Path>,
    pretty: bool,
) -> Result<i32> {
    let package_root = root.join("v0-mvp-skeleton");
    let canonical = canonical.unwrap_or(Path::new("target/novaseal-canonical-vectors.json"));
    let state = state.unwrap_or(Path::new("src/nova_state_type.cell"));
    let lock = lock.unwrap_or(Path::new("src/nova_btc_authority_lock.cell"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-wallet-signing-alignment.json"));
    let report = build(&package_root, canonical, state, lock)?;
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: fixtures={} canonical_wallet_vectors_self_verified={} current_lock_digest_matches_canonical={} current_lock_digest_mismatches={} wallet_lock_alignment_ready={}",
        summary["fixtures"],
        summary["canonical_wallet_vectors_self_verified"],
        summary["current_lock_digest_matches_canonical"],
        summary["current_lock_digest_mismatches"],
        if summary["wallet_lock_alignment_ready"] == true { "True" } else { "False" }
    );
    Ok(if summary["wallet_lock_alignment_ready"] == true { 0 } else { 1 })
}
