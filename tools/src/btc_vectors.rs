use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use blake2b_ref::Blake2bBuilder;
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::shared::{json_text, package_path};

const CURVE_ORDER: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const FIELD_PRIME: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

fn personalized(personal: &[u8], data: &[u8]) -> [u8; 32] {
    let mut state = Blake2bBuilder::new(32).personal(personal).build();
    state.update(data);
    let mut digest = [0_u8; 32];
    state.finalize(&mut digest);
    digest
}

fn derived_key(label: &str) -> (SigningKey, [u8; 32]) {
    let mut counter = 0_u64;
    loop {
        let secret = personalized(b"NovaSealKeyV0", format!("{label}:{counter}").as_bytes());
        if let Ok(key) = SigningKey::from_bytes(&secret) {
            return (key, secret);
        }
        counter += 1;
    }
}

fn verify(message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    key.verify_prehash(message, &signature).is_ok()
}

fn positive(fixture: &str, message: &[u8], signer_index: usize) -> Result<Value> {
    let label = format!("{fixture}:signer:{signer_index}");
    let (key, secret) = derived_key(&label);
    let aux = personalized(b"NovaSealAuxV0", format!("{label}:aux").as_bytes());
    let message: &[u8; 32] = message.try_into().context("BIP340 message must be 32 bytes")?;
    let signature =
        key.sign_prehash_with_aux_rand(message, &aux).map_err(|error| anyhow::anyhow!("BIP340 signing failed: {error}"))?;
    let pubkey = key.verifying_key().to_bytes();
    Ok(json!({
        "id": format!("{fixture}:positive:signer:{signer_index}"),
        "fixture": fixture,
        "case": "positive",
        "signer_index": signer_index,
        "message32": format!("0x{}", hex::encode(message)),
        "xonly_pubkey": format!("0x{}", hex::encode(pubkey)),
        "signature64": format!("0x{}", hex::encode(signature.to_bytes())),
        "test_secret_key": format!("0x{}", hex::encode(secret)),
        "expected": "accept",
        "self_verified": verify(message, &pubkey, &signature.to_bytes())
    }))
}

fn decode(value: &Value, length: usize) -> Result<Vec<u8>> {
    let text = value.as_str().context("vector field must be hex")?;
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))?;
    if bytes.len() != length {
        bail!("expected {length} bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

fn negatives(fixture: &str, message: &[u8], positive: &Value) -> Result<Vec<Value>> {
    let pubkey = decode(&positive["xonly_pubkey"], 32)?;
    let signature = decode(&positive["signature64"], 64)?;
    let (wrong_key, _) = derived_key(&format!("{fixture}:wrong-pubkey"));
    let wrong_pubkey = wrong_key.verifying_key().to_bytes();
    let mut wrong_message = message.to_vec();
    wrong_message[0] ^= 1;
    let mut bitflip_signature = signature.clone();
    *bitflip_signature.last_mut().unwrap() ^= 1;
    let mut s_out = signature[..32].to_vec();
    s_out.extend_from_slice(&hex::decode(CURVE_ORDER)?);
    let mut r_out = hex::decode(FIELD_PRIME)?;
    r_out.extend_from_slice(&signature[32..]);
    let rows = [
        ("wrong_message", "message first byte flipped", wrong_message, pubkey.clone(), signature.clone()),
        ("wrong_pubkey", "pubkey replaced", message.to_vec(), wrong_pubkey.to_vec(), signature.clone()),
        ("signature_bitflip", "signature last byte flipped", message.to_vec(), pubkey.clone(), bitflip_signature),
        ("s_out_of_range", "s set to curve order N", message.to_vec(), pubkey.clone(), s_out),
        ("r_out_of_range", "r set to field prime P", message.to_vec(), pubkey, r_out),
    ];
    Ok(rows
        .into_iter()
        .map(|(id, mutation, message, pubkey, signature)| {
            json!({
                "id": format!("{fixture}:negative:{id}"),
                "fixture": fixture,
                "case": "negative",
                "mutation": mutation,
                "message32": format!("0x{}", hex::encode(&message)),
                "xonly_pubkey": format!("0x{}", hex::encode(&pubkey)),
                "signature64": format!("0x{}", hex::encode(&signature)),
                "expected": "reject",
                "self_verified": verify(&message, &pubkey, &signature)
            })
        })
        .collect())
}

fn build(source: &Path, display: &Path) -> Result<Value> {
    let canonical: Value = serde_json::from_slice(&fs::read(source)?)?;
    let mut positives = Vec::new();
    let mut negatives_all = Vec::new();
    for vector in canonical.get("vectors").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let fixture = vector.get("fixture").and_then(Value::as_str).context("canonical vector is missing fixture")?;
        let message = decode(&vector["hashes"]["signed_intent_hash_after_resolved_receipt"], 32)?;
        let mut fixture_positives = Vec::new();
        for index in 0..4 {
            fixture_positives.push(positive(fixture, &message, index)?);
        }
        negatives_all.extend(negatives(fixture, &message, &fixture_positives[0])?);
        positives.extend(fixture_positives);
    }
    let positive_ok = positives.iter().filter(|value| value["self_verified"] == true).count();
    let negative_ok = negatives_all.iter().filter(|value| value["self_verified"] == false).count();
    Ok(json!({
        "schema": "novaseal-btc-verifier-vectors-v0.1",
        "canonical_vectors": display.to_string_lossy().replace('\\', "/"),
        "scheme": {
            "name": "bip340_schnorr_secp256k1",
            "curve": "secp256k1",
            "pubkey_format": "x-only 32-byte",
            "signature_format": "64-byte r||s",
            "message_format": "32-byte signed_intent_hash_after_resolved_receipt from novaseal-canonical-vectors",
            "low_s_rule": "not applicable to BIP340 Schnorr; reject s >= curve order",
            "malleability_rules": [
                "reject r >= field prime",
                "reject s >= curve order",
                "lift x-only pubkey to even-y point",
                "verify resulting R has even y"
            ]
        },
        "summary": {
            "positive_vectors": positives.len(),
            "negative_vectors": negatives_all.len(),
            "positive_self_verified": positive_ok,
            "negative_self_rejected": negative_ok,
            "classification": "reference_bip340_vectors"
        },
        "positive": positives,
        "negative": negatives_all,
        "limitations": [
            "Generated by an external reference implementation, not the RISC-V verifier binary.",
            "Uses deterministic test-only secret keys derived from fixture names.",
            "Does not wire nova_btc_authority_lock.cell to spawn the verifier.",
            "Does not cover ECDSA or multisig descriptors."
        ]
    }))
}

pub fn run(root: &Path, source: Option<&Path>, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let source_display = source.unwrap_or(Path::new("target/novaseal-canonical-vectors.json"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-btc-verifier-vectors.json"));
    let report = build(&package_path(root, source_display), source_display)?;
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    let summary = &report["summary"];
    println!("wrote {}", output_display.display());
    println!(
        "summary: positive={} negative={} positive_self_verified={} negative_self_rejected={}",
        summary["positive_vectors"], summary["negative_vectors"], summary["positive_self_verified"], summary["negative_self_rejected"]
    );
    let passed = summary["positive_vectors"] == summary["positive_self_verified"]
        && summary["negative_vectors"] == summary["negative_self_rejected"];
    Ok(if passed { 0 } else { 1 })
}
