#[test_only]
module zk_aptos::MultiplierBlsVerifier_tests {
    use zk_aptos::MultiplierBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"96037fc8dc9e11b22aa681a8179658834d7ee6e18ffe897d67e3c016ba841c6b1fd1b2cd47e124bf714c5ac00ce72398" }
    fun proof_b_bytes(): vector<u8> { x"af999cad00aba39b977ed07df77c08701371325f40f3c165d4b07ac98b2890150873256a64ffa94319e0f7607f48f40f0459e84e39de1ea48364bcbee03b7f2168ba26e9a71c9f05fe6eee89f98ba36f970e03f4357dfbb6383c3b290d3fe9ef" }
    fun proof_c_bytes(): vector<u8> { x"aa630277d5088688dc694c012f92af79b59c92459c81b739347a1c26c35fe64683130ea4977385fe5eea7df62f44100a" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"2100000000000000000000000000000000000000000000000000000000000000",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = MultiplierBlsVerifier::verify(
            public_inputs_bytes(),
            proof_a_bytes(),
            proof_b_bytes(),
            proof_c_bytes(),
        );
        assert!(ok, 1);
    }

    #[test]
    fun test_invalid_proof_fails() {
        let ok = MultiplierBlsVerifier::verify(
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
            let ok = MultiplierBlsVerifier::verify(
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
            let ok = MultiplierBlsVerifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
