#[test_only]
module zk_aptos::CubicGnarkBlsVerifier_tests {
    use zk_aptos::CubicGnarkBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"b4233d0f264fee101fa232f42bb7547de7e033eeeba27fe340aef989b1d3f202dee621c702f34bb1ca6f0dba66a0575c" }
    fun proof_b_bytes(): vector<u8> { x"a444054c69c813fb4eea6234a456958b75b233fec560a6a8bbd1dc9b8d501c90de0b356302dbd179f85989542d0ace96003016d61a397d60a9a2aee0192299e29df42f58bce95d130d1d4efe613f3b009c9f8afd468e6e8725ca4939045382e8" }
    fun proof_c_bytes(): vector<u8> { x"a7cb98a3126146d69ccff49af2dd63b3187780015e4b21be6e89338e126a89533a1ec55b8837f59509945263c4d3d1bb" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"2300000000000000000000000000000000000000000000000000000000000000",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = CubicGnarkBlsVerifier::verify(
            public_inputs_bytes(),
            proof_a_bytes(),
            proof_b_bytes(),
            proof_c_bytes(),
        );
        assert!(ok, 1);
    }

    #[test]
    fun test_invalid_proof_fails() {
        let ok = CubicGnarkBlsVerifier::verify(
            public_inputs_bytes(),
            proof_c_bytes(),
            proof_b_bytes(),
            proof_a_bytes(),
        );
        assert!(!ok, 1);
    }

    #[test]
    fun test_invalid_public_input_fails() {
        let public_inputs = public_inputs_bytes();
        if (vector::is_empty(&public_inputs)) {
            let proof_a = proof_a_bytes();
            if (!vector::is_empty(&proof_a)) {
                let first = *vector::borrow(&proof_a, 0);
                vector::pop_back(&mut proof_a);
                vector::push_back(&mut proof_a, first + 1);
            };
            let empty_public_inputs: vector<vector<u8>> = vector[];
            let ok = CubicGnarkBlsVerifier::verify(
                empty_public_inputs,
                proof_a,
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        } else {
            let last_input = vector::pop_back(&mut public_inputs);
            if (vector::is_empty(&last_input)) {
                vector::push_back(&mut last_input, 1);
            } else {
                let first = *vector::borrow(&last_input, 0);
                vector::pop_back(&mut last_input);
                vector::push_back(&mut last_input, first + 1);
            };
            vector::push_back(&mut public_inputs, last_input);
            let ok = CubicGnarkBlsVerifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
