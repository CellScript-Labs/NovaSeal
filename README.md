# NovaSeal

NovaSeal protocol packages, profiles, schemas, fixtures, proof artefacts, and local evidence tooling for CellScript.

## Layout

- `v0-mvp-skeleton/`: canonical v0 MVP skeleton and core profile.
- `agreement-profile-v0/`: Agreement profile.
- `fungible-xudt-profile-v0/`: fungible xUDT profile.
- `rwa-receipt-profile-v0/`: RWA receipt profile.
- `btc-transaction-commitment-profile-v0/`: BTC transaction commitment profile.
- `btc-utxo-seal-profile-v0/`: BTC UTXO seal profile.
- `dual-seal-profile-v0/`: dual seal profile.
- `fiber-candidate-profile-v0/`: Fiber candidate profile.
- `scripts/`: evidence, wallet, SPV, attestation, and devnet tooling used by the profiles.

The parent CellScript compiler repository consumes this repository as a submodule at `proposals/novaseal`.

