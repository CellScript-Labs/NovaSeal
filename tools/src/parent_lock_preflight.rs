use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use blake2b_ref::Blake2bBuilder;
use serde_json::{json, Map, Value};

use crate::shared::{json_text, package_path};

fn suffix(target: &str) -> String {
    if target.ends_with("-asm") {
        "s".into()
    } else if target.ends_with("-elf") {
        "elf".into()
    } else {
        target.replace(['/', '-'], "_")
    }
}

fn blake2b(bytes: &[u8]) -> [u8; 32] {
    let mut state = Blake2bBuilder::new(32).build();
    state.update(bytes);
    let mut digest = [0_u8; 32];
    state.finalize(&mut digest);
    digest
}

fn build(package_root: &Path, cellc: &Path, source_display: &Path, target: &str) -> Result<Value> {
    let artifact_display = PathBuf::from(format!("target/novaseal-parent-lock-abi-preflight.{}", suffix(target)));
    let args: Vec<OsString> = vec![
        source_display.as_os_str().to_owned(),
        "--entry-lock".into(),
        "btc_authority".into(),
        "--target-profile".into(),
        "ckb".into(),
        "--target".into(),
        target.into(),
        "-o".into(),
        artifact_display.as_os_str().to_owned(),
    ];
    let output = Command::new(cellc).args(args).current_dir(package_root).output()?;
    let mut result = Map::new();
    result.insert("target".into(), json!(target));
    result.insert("source".into(), json!(source_display.to_string_lossy().replace('\\', "/")));
    result.insert("status_code".into(), json!(output.status.code().unwrap_or(1)));
    result.insert("stdout".into(), json!(String::from_utf8_lossy(&output.stdout)));
    result.insert("stderr".into(), json!(String::from_utf8_lossy(&output.stderr)));
    if output.status.success() {
        let bytes = fs::read(package_root.join(&artifact_display))?;
        result.insert(
            "summary".into(),
            json!({
                "artifact": artifact_display.to_string_lossy().replace('\\', "/"),
                "artifact_format": suffix(target),
                "artifact_hash": format!("0x{}", hex::encode(blake2b(&bytes))),
                "artifact_size_bytes": bytes.len(),
                "status": "ok"
            }),
        );
    }
    Ok(Value::Object(result))
}

fn checks(assembly: &str) -> Value {
    let decoder_prefix =
        assembly.split("# cellscript entry abi: lock_args param expected_btc_authority_hash consumes").next().unwrap_or_default();
    let mut values = Map::new();
    values.insert("load_script_args_visible".into(), json!(assembly.contains("# cellscript abi: LOAD_SCRIPT reason=entry_lock_args")));
    values.insert(
        "expected_btc_authority_hash_from_lock_args".into(),
        json!(assembly.contains("# cellscript entry abi: lock_args param expected_btc_authority_hash consumes 32 script arg byte(s)")),
    );
    values.insert("script_args_u32_decoder_pointer_safe".into(), json!(!decoder_prefix.contains("lbu t0, 1(t0)")));
    values.insert(
        "lock_args_not_rebound_from_input_cell_data".into(),
        json!(
            !assembly.contains("bind read-only param expected_btc_authority_hash to Input#")
                && !assembly.contains("bind read-only param expected_btc_authority_hash to CellDep#")
        ),
    );
    values
        .insert("protected_cell_bound_from_input0".into(), json!(assembly.contains("bind read-only param cell to Input#0 cell data")));
    values.insert("spawn_with_fd_helper_visible".into(), json!(assembly.contains("__ckb_spawn_with_fd1")));
    values.insert("vm2_spawn_syscall_visible".into(), json!(assembly.contains("li a7, 2601")));
    values.insert("vm2_wait_syscall_visible".into(), json!(assembly.contains("li a7, 2602")));
    values.insert(
        "vm2_pipe_syscalls_visible".into(),
        json!(["li a7, 2604", "li a7, 2605", "li a7, 2608"].iter().all(|marker| assembly.contains(marker))),
    );
    let passed = values.values().all(|value| value == &json!(true));
    values.insert("passed".into(), json!(passed));
    Value::Object(values)
}

fn summary(result: &Value) -> Value {
    result.get("summary").cloned().unwrap_or_else(|| {
        json!({
            "status_code": result.get("status_code").cloned().unwrap_or(Value::Null),
            "stderr": result.get("stderr").cloned().unwrap_or(Value::Null)
        })
    })
}

pub fn run(root: &Path, cellc: Option<&Path>, source: Option<&Path>, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let package_root = root.join("v0-mvp-skeleton");
    let default_cellc =
        root.parent().and_then(Path::parent).context("NovaSeal root must be under proposals")?.join("target/debug/cellc");
    let cellc_display = cellc.unwrap_or(&default_cellc);
    let source_display = source.unwrap_or(Path::new("src/nova_btc_authority_lock.cell"));
    let output_display = output.unwrap_or(Path::new("target/novaseal-parent-lock-abi-preflight.json"));
    let asm = build(&package_root, cellc_display, source_display, "riscv64-asm")?;
    let elf = build(&package_root, cellc_display, source_display, "riscv64-elf")?;
    let assembly = asm
        .pointer("/summary/artifact")
        .and_then(Value::as_str)
        .and_then(|path| fs::read_to_string(package_root.join(path)).ok())
        .unwrap_or_default();
    let checks = checks(&assembly);
    let builds_ok = asm["status_code"] == 0 && elf["status_code"] == 0;
    let passed = builds_ok && checks["passed"] == true;
    let report = json!({
        "schema": "novaseal-parent-lock-abi-preflight-v0.1",
        "classification": "parent_lock_elf_abi_preflight",
        "cellc": cellc_display.to_string_lossy().replace('\\', "/"),
        "source": source_display.to_string_lossy().replace('\\', "/"),
        "builds": {"asm": summary(&asm), "elf": summary(&elf)},
        "checks": checks,
        "status": {
            "preflight_passed": passed,
            "parent_lock_elf_built": elf["status_code"] == 0,
            "parent_lock_asm_built": asm["status_code"] == 0,
            "parent_lock_ckb_vm_executed": false,
            "parent_spawn_executed": false,
            "ready_for_parent_child_ckb_vm_harness": passed,
            "production_ready": false
        },
        "limits": [
            "This preflight inspects generated parent lock artifacts; it does not execute CKB VM bytecode.",
            "The child verifier CKB VM harness is separate and does not prove parent lock spawn/wait behaviour.",
            "No transaction, capacity, tx-size, or full parent/child execution transcript is produced here."
        ]
    });
    let output_path = package_path(root, output_display);
    fs::create_dir_all(output_path.parent().context("output path has no parent")?)?;
    fs::write(output_path, json_text(&report, pretty)?)?;
    println!("wrote {}", output_display.display());
    println!(
        "summary: preflight_passed={} parent_lock_elf_built={} ready_for_parent_child_ckb_vm_harness={} parent_lock_ckb_vm_executed={}",
        if report["status"]["preflight_passed"] == true { "True" } else { "False" },
        if report["status"]["parent_lock_elf_built"] == true { "True" } else { "False" },
        if report["status"]["ready_for_parent_child_ckb_vm_harness"] == true { "True" } else { "False" },
        if report["status"]["parent_lock_ckb_vm_executed"] == true { "True" } else { "False" }
    );
    Ok(if passed { 0 } else { 1 })
}
