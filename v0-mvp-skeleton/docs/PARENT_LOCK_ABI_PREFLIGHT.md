# NovaSeal Parent Lock ABI Preflight

**Date**: 2026-05-30
**Script**: `../tools/src/parent_lock_preflight.rs`
**Report**: `target/novaseal-parent-lock-abi-preflight.json`
**Classification**: parent lock ELF/ASM ABI preflight.

This preflight builds the `btc_authority` parent lock as both RISC-V assembly and RISC-V ELF, then inspects the generated ABI surface that must be correct before parent/child CKB VM evidence can be meaningful.

## Current Result

Run:

```bash
cargo run --quiet --locked --manifest-path ../tools/Cargo.toml -- parent-lock-abi-preflight --pretty
```

Current summary:

```text
preflight_passed=true
parent_lock_elf_built=true
ready_for_parent_child_ckb_vm_harness=true
parent_lock_ckb_vm_executed=false
```

## Checked Surface

The preflight currently requires:

- `LOAD_SCRIPT reason=entry_lock_args` is present.
- `expected_btc_authority_hash` consumes exactly 32 Script.args bytes.
- Script.args u32 decoding does not clobber its own base pointer.
- `expected_btc_authority_hash` is not rebound from `Input#N` or `CellDep#N` data.
- the protected `cell` remains bound from `GroupInput#0` cell data.
- `spawn_with_fd`, VM2 spawn, wait, pipe/write, and close syscall surfaces remain visible.

## Boundary

This preflight is not itself CKB VM transaction evidence. It proves the generated parent lock artifact is structurally ready; the separate parent-lock and combined harnesses provide resolved ScriptGroup/cell-dep execution and fixture coverage in `docs/PARENT_LOCK_CKB_VM_HARNESS.md` and `docs/COMBINED_TX_HARNESS.md`.
