#!/usr/bin/env bash
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verifier_root="$(cd "$crate_dir/.." && pwd)"
cargo_home_dir="${CARGO_HOME:-${HOME}/.cargo}"
target_dir="${CARGO_TARGET_DIR:-$crate_dir/target}"

for command in cargo rustc; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command" >&2
        exit 1
    fi
done

mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd)"

rust_sysroot="$(rustc --print sysroot)"
host_triple="$(rustc -vV | awk '/^host: / { print $2 }')"
rust_objcopy="$rust_sysroot/lib/rustlib/$host_triple/bin/rust-objcopy"
if [[ ! -x "$rust_objcopy" ]]; then
    printf 'rust-objcopy not found; install the llvm-tools-preview component\n' >&2
    exit 1
fi

unit_separator=$'\x1f'
encoded_rustflags="--remap-path-prefix=$verifier_root=/src/verifier"
encoded_rustflags+="${unit_separator}--remap-path-prefix=$cargo_home_dir=/cargo"

env -u RUSTFLAGS \
    CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_dir" \
    cargo build \
        --locked \
        --manifest-path "$crate_dir/Cargo.toml" \
        --release \
        --target riscv64imac-unknown-none-elf \
        --bin novaseal_btc_verifier_riscv

artifact="$target_dir/riscv64imac-unknown-none-elf/release/novaseal_btc_verifier_riscv"
stripped_artifact="$artifact.stripped"
rm -f "$stripped_artifact"

if [[ "$(uname -s)" == "Linux" ]]; then
    LD_LIBRARY_PATH="$rust_sysroot/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$rust_objcopy" --strip-all "$artifact" "$stripped_artifact"
else
    "$rust_objcopy" --strip-all "$artifact" "$stripped_artifact"
fi
mv "$stripped_artifact" "$artifact"

cargo run --quiet --locked \
    --manifest-path "$verifier_root/../../tools/Cargo.toml" -- \
    artifact-identity "$artifact"
