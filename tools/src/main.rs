#![recursion_limit = "256"]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod agreement_shape;
mod audit_surface;
mod btc_vectors;
mod canonical_vectors;
mod fixture_harness;
mod ipc_vectors;
mod parent_lock_preflight;
mod riscv_artifact;
mod schema_layout;
mod shared;
mod shell_report;
mod spawn_backend;
mod wallet_alignment;

#[derive(Debug, Parser)]
#[command(name = "novaseal-tools")]
struct Cli {
    /// NovaSeal submodule root. Defaults to the parent of this tools crate.
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Tool,
}

#[derive(Debug, Subcommand)]
enum Tool {
    /// Print the reproducible artifact size and cryptographic identities.
    ArtifactIdentity { artifact: PathBuf },
    /// Check Agreement Profile v0 builder-visible transaction shapes.
    AgreementTxShape {
        #[arg(long)]
        fixtures_dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Extract the conservative NovaSeal audit surface from a CellScript bundle.
    AuditSurface {
        #[arg(long)]
        audit_bundle: Option<PathBuf>,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        combined_tx_report: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate packed-reference canonical fixture vectors.
    CanonicalVectors {
        #[arg(long)]
        fixtures: Option<PathBuf>,
        #[arg(long)]
        layout: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Run NovaSeal fixtures through the source-model evidence harness.
    FixtureHarness {
        #[arg(long)]
        fixtures: Option<PathBuf>,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        audit_surface: Option<PathBuf>,
        #[arg(long)]
        canonical_vectors: Option<PathBuf>,
        #[arg(long)]
        btc_verifier_vectors: Option<PathBuf>,
        #[arg(long)]
        wallet_signing_alignment_report: Option<PathBuf>,
        #[arg(long)]
        btc_verifier_ipc_vectors: Option<PathBuf>,
        #[arg(long)]
        btc_verifier_shell_report: Option<PathBuf>,
        #[arg(long)]
        ckb_vm_child_verifier_report: Option<PathBuf>,
        #[arg(long)]
        parent_lock_abi_preflight_report: Option<PathBuf>,
        #[arg(long)]
        parent_lock_ckb_vm_report: Option<PathBuf>,
        #[arg(long)]
        state_type_ckb_vm_report: Option<PathBuf>,
        #[arg(long)]
        combined_tx_report: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate deterministic NovaSeal BIP340 verifier vectors.
    BtcVerifierVectors {
        #[arg(long)]
        canonical_vectors: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Extract packed fixed-field NovaSeal v0 schema layouts.
    SchemaLayout {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate fixed NovaSeal BIP340 verifier IPC envelope vectors.
    BtcVerifierIpcVectors {
        #[arg(long)]
        btc_vectors: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate the RISC-V verifier shell decision report.
    BtcVerifierShellReport {
        #[arg(long)]
        ipc_vectors: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Compare canonical wallet messages with the current lock digest.
    WalletSigningAlignment {
        #[arg(long)]
        canonical_vectors: Option<PathBuf>,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        lock_source: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Stage and verify the NovaSeal RISC-V verifier shell artifact.
    RiscvShellArtifact {
        #[arg(long)]
        release_elf: Option<PathBuf>,
        #[arg(long)]
        staged_elf: Option<PathBuf>,
        #[arg(long)]
        staged_sha256: Option<PathBuf>,
        #[arg(long)]
        shell_report: Option<PathBuf>,
        #[arg(long)]
        audit_surface: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        sync: bool,
        #[arg(long)]
        pretty: bool,
    },
    /// Build and inspect the NovaSeal parent-lock ELF/ASM ABI surface.
    ParentLockAbiPreflight {
        #[arg(long)]
        cellc: Option<PathBuf>,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Probe CellScript VM2 spawn/IPC lowering for the BIP340 verifier surface.
    SpawnBackendProbe {
        #[arg(long)]
        cellc: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        audit_surface: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = shared::root(cli.root.as_deref()).and_then(|root| match cli.command {
        Tool::ArtifactIdentity { artifact } => shared::print_artifact_identity(&artifact),
        Tool::AgreementTxShape { fixtures_dir, out, pretty } => {
            agreement_shape::run(&root, fixtures_dir.as_deref(), out.as_deref(), pretty)
        }
        Tool::AuditSurface { audit_bundle, source, combined_tx_report, output, pretty } => audit_surface::run(
            &root,
            audit_bundle.as_deref(),
            source.as_deref(),
            combined_tx_report.as_deref(),
            output.as_deref(),
            pretty,
        ),
        Tool::CanonicalVectors { fixtures, layout, output, pretty } => {
            canonical_vectors::run(&root, fixtures.as_deref(), layout.as_deref(), output.as_deref(), pretty)
        }
        Tool::FixtureHarness {
            fixtures,
            source,
            audit_surface,
            canonical_vectors,
            btc_verifier_vectors,
            wallet_signing_alignment_report,
            btc_verifier_ipc_vectors,
            btc_verifier_shell_report,
            ckb_vm_child_verifier_report,
            parent_lock_abi_preflight_report,
            parent_lock_ckb_vm_report,
            state_type_ckb_vm_report,
            combined_tx_report,
            output,
            pretty,
        } => fixture_harness::run(
            &root,
            fixtures.as_deref(),
            source.as_deref(),
            audit_surface.as_deref(),
            canonical_vectors.as_deref(),
            btc_verifier_vectors.as_deref(),
            wallet_signing_alignment_report.as_deref(),
            btc_verifier_ipc_vectors.as_deref(),
            btc_verifier_shell_report.as_deref(),
            ckb_vm_child_verifier_report.as_deref(),
            parent_lock_abi_preflight_report.as_deref(),
            parent_lock_ckb_vm_report.as_deref(),
            state_type_ckb_vm_report.as_deref(),
            combined_tx_report.as_deref(),
            output.as_deref(),
            pretty,
        ),
        Tool::BtcVerifierVectors { canonical_vectors, output, pretty } => {
            btc_vectors::run(&root, canonical_vectors.as_deref(), output.as_deref(), pretty)
        }
        Tool::SchemaLayout { output, pretty } => schema_layout::run(&root, output.as_deref(), pretty),
        Tool::BtcVerifierIpcVectors { btc_vectors, output, pretty } => {
            ipc_vectors::run(&root, btc_vectors.as_deref(), output.as_deref(), pretty)
        }
        Tool::BtcVerifierShellReport { ipc_vectors, output, pretty } => {
            shell_report::run(&root, ipc_vectors.as_deref(), output.as_deref(), pretty)
        }
        Tool::WalletSigningAlignment { canonical_vectors, source, lock_source, output, pretty } => wallet_alignment::run(
            &root,
            canonical_vectors.as_deref(),
            source.as_deref(),
            lock_source.as_deref(),
            output.as_deref(),
            pretty,
        ),
        Tool::RiscvShellArtifact { release_elf, staged_elf, staged_sha256, shell_report, audit_surface, output, sync, pretty } => {
            riscv_artifact::run(
                &root,
                release_elf.as_deref(),
                staged_elf.as_deref(),
                staged_sha256.as_deref(),
                shell_report.as_deref(),
                audit_surface.as_deref(),
                output.as_deref(),
                sync,
                pretty,
            )
        }
        Tool::ParentLockAbiPreflight { cellc, source, output, pretty } => {
            parent_lock_preflight::run(&root, cellc.as_deref(), source.as_deref(), output.as_deref(), pretty)
        }
        Tool::SpawnBackendProbe { cellc, output, audit_surface, pretty } => {
            spawn_backend::run(&root, cellc.as_deref(), output.as_deref(), audit_surface.as_deref(), pretty)
        }
    });
    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
