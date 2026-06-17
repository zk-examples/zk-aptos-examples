#[test_only]
module zk_aptos::MultiplierBnVerifier_tests {
    use zk_aptos::MultiplierBnVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"9974d3f96a8a31f0c32cb8770ac251e1ee524c48fb2416c8c67b788414e9292754f49b503b5053f98235ce4f41fc1f47ab9823cb8457df9dc179024d44603b18" }
    fun proof_b_bytes(): vector<u8> { x"8a487b6450a58c4e675b7bab8dd94bf4f8051a6f39cd824a5562ec443cc29606241b8d354783cb13401165843bb3f5db182d448994dbb0a3644f3b14ba6ba4272ae1dd740053f2c41cfb648d1137de5683dd0c73dc8c3e69d92715a0797e3b276f9f46eb7dea8e0ba3c144c7051b31ee75d3d03d13e806d66311a6146e875c21" }
    fun proof_c_bytes(): vector<u8> { x"172be206a3d197d95a9d1267aa45d78b05ccd0bcc0f8fc72c74c820ca4049e2a7f74ebc72f1c4d21ae69f07ed845ce66d7ef58c92725585b85ee4b82b68bc907" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"2100000000000000000000000000000000000000000000000000000000000000",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = MultiplierBnVerifier::verify(
            public_inputs_bytes(),
            proof_a_bytes(),
            proof_b_bytes(),
            proof_c_bytes(),
        );
        assert!(ok, 1);
    }

    #[test]
    fun test_invalid_proof_fails() {
        let ok = MultiplierBnVerifier::verify(
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
            let ok = MultiplierBnVerifier::verify(
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
            let ok = MultiplierBnVerifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
