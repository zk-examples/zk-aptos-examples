#[test_only]
module zk_aptos::CubicGnarkBlsVerifier_tests {
    use zk_aptos::CubicGnarkBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"abfe1943a963dcf8a7c6ad5e1ad7ec32e0d846136a4390bb151d15d8bae3c8143defcebc25ab3f87aa6ba8f406216b01" }
    fun proof_b_bytes(): vector<u8> { x"ad56a39a16158ee13f10713482664715906995852ccceebfc0a976934c3f0ba5327eaac7348f7ed02d216a93fd49116d12ca0d35d63454cda1d7b674b6656550b78201063f8f37dbb77793915ddb1eb21e915e34cd7e71fd2ca793d76191ea87" }
    fun proof_c_bytes(): vector<u8> { x"87058e16fddbbad467e5be6a7f5411050f7a2fa08142457956d4c2013e7890366a47dd0d5d8340a273542ea7105a3b6a" }
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
    fun test_invalid_public_input_fails() {
        let public_inputs = public_inputs_bytes();
        if (vector::is_empty(&public_inputs)) {
            let proof_a = proof_a_bytes();
            if (!vector::is_empty(&proof_a)) {
                let first = *vector::borrow(&proof_a, 0);
                vector::pop_back(&mut proof_a);
                vector::push_back(&mut proof_a, first + 1);
            };
            let ok = CubicGnarkBlsVerifier::verify(
                vector::empty<vector<u8>>(),
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
