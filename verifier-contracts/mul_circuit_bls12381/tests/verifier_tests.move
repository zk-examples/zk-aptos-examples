#[test_only]
module zk_aptos::MulCircuitBlsVerifier_tests {
    use zk_aptos::MulCircuitBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"8b81f87d0af11fca60f0415196099021266a33393e78810975b4e7e9ff9fb7e40dbed9d5aed14d93de10a592dc1ecefb" }
    fun proof_b_bytes(): vector<u8> { x"88726fd4e690ced6b11e12cd0feb5466864cc01896b878706bc408e42f7775a1e00981fc04e1acf7ecaffbff4aa8bd4c0d1d6c53d186784febc37d8028f7507d9c0789a15e54e3e1a12d1d92915d73535fd391879b603b3c61f649c276584eae" }
    fun proof_c_bytes(): vector<u8> { x"a1f5ae000dec042878355a2d9de7e9fa2915480a6a68510a293f206680234b712ab73870b2056e13dc8c4a60102df503" }
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
