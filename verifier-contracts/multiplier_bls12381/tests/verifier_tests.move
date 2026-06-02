#[test_only]
module zk_aptos::MultiplierBlsVerifier_tests {
    use zk_aptos::MultiplierBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"aaf37388201f626b3d52a076918c70df40f506cf0b0a324fc51b95f1f6c5e786c78b6efa1f769d7f7a85daa7cbc1dec1" }
    fun proof_b_bytes(): vector<u8> { x"a47a519b7db4e960a3eacc178d63aca0084ef2dccfcda88da8de6dedb557d63d3b7f382ba687ede826fdd48872a98fdc05d0d1cd5683ad6f9a3f790c85ea92a411f0dfb0d3198a9895c4a17cb1e3b34cd5210e682b63d90309e10d2883c847fc" }
    fun proof_c_bytes(): vector<u8> { x"a8e97077bc05a3f958eb1618d0c540a4d28ff95c6354c6a2cfbc3d1de9f8e6603d255946ccb1ec662f4a922e19918d4b" }
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
    fun test_invalid_public_input_fails() {
        let public_inputs = public_inputs_bytes();
        if (vector::is_empty(&public_inputs)) {
            let proof_a = proof_a_bytes();
            if (!vector::is_empty(&proof_a)) {
                let first = *vector::borrow(&proof_a, 0);
                vector::pop_back(&mut proof_a);
                vector::push_back(&mut proof_a, first + 1);
            };
            let ok = MultiplierBlsVerifier::verify(
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
