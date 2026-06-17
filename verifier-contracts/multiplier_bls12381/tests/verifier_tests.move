#[test_only]
module zk_aptos::MultiplierBlsVerifier_tests {
    use zk_aptos::MultiplierBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"8f08324f59bd052b0a518a599b9d22f3e796d8762e7d6de6232b04bf28908568cd467e6a7ce45404695cc008c48c7206" }
    fun proof_b_bytes(): vector<u8> { x"b4c789bba251ed0a11d8916933d0e0edfb488a5cd7d10d99bb483e0fe35f443cd1ef286840b92013b8a21e8a0069a8d9110cf8edb8c30734e565b87c21154952dc63a0d76bb87955975ad332dd209462418edd7db03364556019cc4383616fa9" }
    fun proof_c_bytes(): vector<u8> { x"9206cc60dad617c1eab5e051080f95f76bdbcd0d56a50f6fcbb9da7666378f33f56ed83037d41da65ad898302da03f6a" }
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
