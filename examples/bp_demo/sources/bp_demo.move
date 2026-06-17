module my_addr::bp_demo {
    use std::option;
    use std::vector;
    use 0x1::ristretto255_bulletproofs;
    use 0x1::ristretto255_pedersen;

    const MAX_DST_LENGTH: u64 = 256;

    fun expected_single_proof_length(num_bits: u64): u64 {
        if (num_bits == 8) {
            480
        } else if (num_bits == 16) {
            544
        } else if (num_bits == 32) {
            608
        } else {
            672
        }
    }

    /// The proof is generated off-chain (the Move module does only verification).
    ///
    /// `value` and `blinding` are secrets and must never be sent on-chain.
    ///
    /// The `dst` bytes passed here must be exactly the same as used in the Rust prover.
    ///
    /// Changing `num_bits` or `dst` from the verifier settings must make this check fail.
    public fun verify_range(
        commitment_bytes: vector<u8>,
        proof_bytes: vector<u8>,
        num_bits: u64,
        dst: vector<u8>,
    ): bool {
        if (num_bits != 8 && num_bits != 16 && num_bits != 32 && num_bits != 64) {
            return false;
        };
        if (vector::length(&dst) > MAX_DST_LENGTH) {
            return false;
        };
        if (vector::length(&proof_bytes) != expected_single_proof_length(num_bits)) {
            return false;
        };

        let commitment_opt = ristretto255_pedersen::new_commitment_from_bytes(commitment_bytes);
        if (!option::is_some(&commitment_opt)) {
            return false;
        };

        let commitment = option::extract(&mut commitment_opt);
        let proof = ristretto255_bulletproofs::range_proof_from_bytes(proof_bytes);

        ristretto255_bulletproofs::verify_range_proof_pedersen(
            &commitment,
            &proof,
            num_bits,
            dst,
        )
    }
}
