# zk-aptos-examples

Examples and generated Aptos Move contracts for Groth16 and Bulletproofs verification.

- Aptos Groth16 docs: <https://aptos.dev/build/smart-contracts/cryptography#groth16-zksnark-verifier>

## Manual verifier contract generation

Run these commands from the repository root. Add `--run-aptos-test` to any command if you want the generated package test to run immediately after generation.

### Cubic gnark BLS12-381

```sh
export-aptos-verifier generate --vk circuits/cubic-gnark/verification_key.json --proof circuits/cubic-gnark/proof.json --out verifier-contracts/cubic_gnark_bls12381 --package-name zk_aptos --module-name CubicGnarkBlsVerifier --account-address 0x0 --curve bls12381 --input-format snarkjs-json --force
```

### ark-mimc BN254

```sh
export-aptos-verifier generate --bundle circuits/ark-mimc/artifacts/bn254/groth16_artifacts.json --out verifier-contracts/ark_mimc_bn254 --package-name zk_aptos --module-name ArkMimcBn254Verifier --account-address 0x0 --curve bn254 --input-format arkworks-compact --force
```

### ark-mimc BLS12-381

```sh
export-aptos-verifier generate --bundle circuits/ark-mimc/artifacts/bls12_381/groth16_artifacts.json --out verifier-contracts/ark_mimc_bls12381 --package-name zk_aptos --module-name ArkMimcBlsVerifier --account-address 0x0 --curve bls12381 --input-format arkworks-compact --force
```

### MulCircuit BLS12-381

```sh
export-aptos-verifier generate --vk circuits/MulCircuit/artifacts/bls12_381/verification_key.json --proof circuits/MulCircuit/artifacts/bls12_381/proof.json --out verifier-contracts/mul_circuit_bls12381 --package-name zk_aptos --module-name MulCircuitBlsVerifier --account-address 0x0 --curve bls12381 --input-format snarkjs-json --force
```

### Multiplier BN254

```sh
export-aptos-verifier generate --vk circuits/Multiplier/verification_key_bn.json --proof circuits/Multiplier/proof_bn.json --public circuits/Multiplier/public.json --out verifier-contracts/multiplier_bn254 --package-name zk_aptos --module-name MultiplierBnVerifier --account-address 0x0 --curve bn254 --input-format snarkjs-json --force
```

### Multiplier BLS12-381

```sh
export-aptos-verifier generate --vk circuits/Multiplier/verification_key_bls.json --proof circuits/Multiplier/proof_bls.json --public circuits/Multiplier/public_bls.json --out verifier-contracts/multiplier_bls12381 --package-name zk_aptos --module-name MultiplierBlsVerifier --account-address 0x0 --curve bls12381 --input-format snarkjs-json --force
```

## Run Move packages

```sh
aptos move test --package-dir examples/bp_demo
aptos move test --package-dir examples/verifier_example

aptos move test --package-dir verifier-contracts/ark_mimc_bn254
aptos move test --package-dir verifier-contracts/ark_mimc_bls12381
aptos move test --package-dir verifier-contracts/mul_circuit_bls12381
aptos move test --package-dir verifier-contracts/multiplier_bn254
aptos move test --package-dir verifier-contracts/multiplier_bls12381
aptos move test --package-dir verifier-contracts/cubic_gnark_bls12381
```

## Circuit artifact commands

### ark-mimc

```sh
cd circuits/ark-mimc
cargo run -- export bn254 artifacts
cargo run -- export bls12_381 artifacts
cargo test test_mimc_groth16_bn254
cargo test test_mimc_groth16_bls12_381
```

### MulCircuit

```sh
cd circuits/MulCircuit
cargo run
```

### cubic-gnark

```sh
cd circuits/cubic-gnark
go run .
```

### Multiplier

`circuits/Multiplier` contains the Circom circuit and checked proof/vk/public JSON artifacts for BN254 and BLS12-381.

#### Compile BN254

```sh
cd circuits/Multiplier
circom Multiplier.circom --r1cs --wasm --sym --output build_bn
```

#### Trusted setup and proof for BN254

```sh
cd circuits/Multiplier/build_bn

snarkjs powersoftau new bn128 10 pot10_0000.ptau -v
snarkjs powersoftau contribute pot10_0000.ptau pot10_0001.ptau --name="First contribution" -v -e="seed"
snarkjs powersoftau prepare phase2 pot10_0001.ptau pot10_final.ptau -v

snarkjs groth16 setup Multiplier.r1cs pot10_final.ptau Multiplier_0000.zkey
snarkjs zkey contribute Multiplier_0000.zkey Multiplier_final.zkey --name="1st contributor" -v -e="seed"
snarkjs zkey export verificationkey Multiplier_final.zkey ../verification_key_bn.json

node Multiplier_js/generate_witness.js Multiplier_js/Multiplier.wasm input.json witness.wtns
snarkjs groth16 prove Multiplier_final.zkey witness.wtns ../proof_bn.json ../public.json
snarkjs groth16 verify ../verification_key_bn.json ../public.json ../proof_bn.json
```

#### Compile BLS12-381

```sh
cd circuits/Multiplier
circom Multiplier.circom --r1cs --wasm --sym --prime bls12-381 --output build_bls
```

#### Trusted setup and proof for BLS12-381

```sh
cd circuits/Multiplier/build_bls

snarkjs powersoftau new bls12-381 10 pot10_0000.ptau -v
snarkjs powersoftau contribute pot10_0000.ptau pot10_0001.ptau --name="First contribution" -v -e="seed"
snarkjs powersoftau prepare phase2 pot10_0001.ptau pot10_final.ptau -v

snarkjs groth16 setup Multiplier.r1cs pot10_final.ptau Multiplier_0000.zkey
snarkjs zkey contribute Multiplier_0000.zkey Multiplier_final.zkey --name="1st contributor" -v -e="seed"
snarkjs zkey export verificationkey Multiplier_final.zkey ../verification_key_bls.json

node Multiplier_js/generate_witness.js Multiplier_js/Multiplier.wasm input.json witness.wtns
snarkjs groth16 prove Multiplier_final.zkey witness.wtns ../proof_bls.json ../public_bls.json
snarkjs groth16 verify ../verification_key_bls.json ../public_bls.json ../proof_bls.json
```

### Bulletproofs CLI

```sh
cd bulletproofs-cli
cargo run -- prove --value 12345 --bits 32 --dst "my-aptos-app/range-proof/v1" --out proof.json
cargo run -- verify --input proof.json --bits 32 --dst "my-aptos-app/range-proof/v1"
```
