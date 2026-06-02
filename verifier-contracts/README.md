# Generated verifier contracts

These packages are generated with `export-aptos-verifier.exe generate`.
Do not hand-edit `sources/verifier.move` or `tests/verifier_tests.move`; regenerate them from circuit artifacts instead.

## Packages

- `ark_mimc_bn254`: generated from `circuits/ark-mimc/artifacts/bn254/groth16_artifacts.json`
- `ark_mimc_bls12381`: generated from `circuits/ark-mimc/artifacts/bls12_381/groth16_artifacts.json`
- `mul_circuit_bls12381`: generated from `circuits/MulCircuit/artifacts/bls12_381/verification_key.json` and `proof.json`
- `multiplier_bn254`: generated from `circuits/Multiplier/verification_key_bn.json`, `proof_bn.json`, and `public.json`
- `multiplier_bls12381`: generated from `circuits/Multiplier/verification_key_bls.json`, `proof_bls.json`, and `public_bls.json`
- `cubic_gnark_bls12381`: generated from `circuits/cubic-gnark/verification_key.json` and `proof.json`
