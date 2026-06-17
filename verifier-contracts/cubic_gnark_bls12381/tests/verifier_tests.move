#[test_only]
module zk_aptos::CubicGnarkBlsVerifier_tests {
    use zk_aptos::CubicGnarkBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"a1164497ca6f47f48c75fa44231a5888160ea558439b316e78199fb90ea6b53b3f879823951f1f1270cb81a3ed283554" }
    fun proof_b_bytes(): vector<u8> { x"89e2a2c434275ebf5d1b63b0b24b79bb657b27b44a1f09cee0eb9d9e422a903eadacd290dd681b1662560c98fb016e8d0798d6f7d1f88b85d294de0a71b3b6ecc64be50638906cf53df003e5f6df807ee1b3d40ce92cd82dc4c56bf6e08a6332" }
    fun proof_c_bytes(): vector<u8> { x"8a111ec767f3963ea49640eea7ac4f6e5718e92c255cb906d07505b098962a20d3ef48c7102d2348213f8d233e8326b2" }
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
