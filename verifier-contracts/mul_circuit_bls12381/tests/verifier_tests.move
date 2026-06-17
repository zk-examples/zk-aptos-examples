#[test_only]
module zk_aptos::MulCircuitBlsVerifier_tests {
    use zk_aptos::MulCircuitBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"975a0a44a973a656402ffdb80c62d0a4afa80b06e3662ee24cabed074b249241feb43654762c1055e388d49a622a64cf" }
    fun proof_b_bytes(): vector<u8> { x"b71e0f9dd07c06a1e09f8eaa68d5fea1ee6177b145c97302218acd4352b7c9d594896e7d585f0e652b2b11301889e0a008f1bccb031dbbd2cf05ec68aa730ea001260510ee3785ad817c6078e52b16b8859068950d647a92001d399909384cf6" }
    fun proof_c_bytes(): vector<u8> { x"a331dd0522195973eaf09c931c679fda4441f3804119cf5ffb710939c9ae9f20a84a8495b313924eb603cd6a0f00903d" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"0100000001000000000000000000000000000000000000000000000000000000",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = MulCircuitBlsVerifier::verify(
            public_inputs_bytes(),
            proof_a_bytes(),
            proof_b_bytes(),
            proof_c_bytes(),
        );
        assert!(ok, 1);
    }

    #[test]
    fun test_invalid_proof_fails() {
        let ok = MulCircuitBlsVerifier::verify(
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
            let ok = MulCircuitBlsVerifier::verify(
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
            let ok = MulCircuitBlsVerifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
