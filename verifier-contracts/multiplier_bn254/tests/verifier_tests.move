#[test_only]
module zk_aptos::MultiplierBnVerifier_tests {
    use zk_aptos::MultiplierBnVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"4a76b68897135cbbe126a17dda6bb5dc4fe7681975a93ceee45282b78139750ce68dc5655515861a87d36500b2f1cca74320401c327da3b05276114184503c18" }
    fun proof_b_bytes(): vector<u8> { x"95e9b8568c56b277de15c25d7fa94324c3739ee4beb34e19711b378c9739f40135cbc6e835b26efe48d4f26875bbd80ed65fdcdae7d07a8fec91ca6eec8ebb066c55de11eeab54be0e453a2d82805c78360626eadf5f464cf33b5ddb22c8cc0f1f13b0ec0c5b8bf8fe90388d4b4b84646f4bcf649752909e5868a1a6ebad3906" }
    fun proof_c_bytes(): vector<u8> { x"59fdde95cbd772e351ee29352ed55ced364e6a5bf41ef4a0263a2343c933782d540b38eeb6bfe6ca5a73fe538a4145d510997e860ed4e87ecf9eb8d043647017" }
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
    fun test_invalid_public_input_fails() {
        let public_inputs = public_inputs_bytes();
        if (vector::is_empty(&public_inputs)) {
            let proof_a = proof_a_bytes();
            if (!vector::is_empty(&proof_a)) {
                let first = *vector::borrow(&proof_a, 0);
                vector::pop_back(&mut proof_a);
                vector::push_back(&mut proof_a, first + 1);
            };
            let ok = MultiplierBnVerifier::verify(
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
