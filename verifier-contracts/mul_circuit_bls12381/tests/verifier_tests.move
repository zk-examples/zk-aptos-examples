#[test_only]
module zk_aptos::MulCircuitBlsVerifier_tests {
    use zk_aptos::MulCircuitBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"a4c1e28d7af82b998433b0d060cba4e510ae02c09f272c586d033986714ea5df6fee91808077b4097f9ddf929791161b" }
    fun proof_b_bytes(): vector<u8> { x"8b0fc8f39bbb1cca2997380c22f95519e0eb8b2524f90f0cbd1918824cc1d734253dee09da3a766d90658c19a2bbaddb0869718c238d0baa36e5422e51081f90fcefb61fdc5a09d5a61a76473f81b8c4b4dd1aaaa94dd5293cd542e40b359c78" }
    fun proof_c_bytes(): vector<u8> { x"a495d3bc05fc6dd6d098f3be372553b80417d788521c551c41a62b6327db9622c0d1e466a8d794963abf64f5c4698942" }
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
    fun test_invalid_public_input_fails() {
        let public_inputs = public_inputs_bytes();
        if (vector::is_empty(&public_inputs)) {
            let proof_a = proof_a_bytes();
            if (!vector::is_empty(&proof_a)) {
                let first = *vector::borrow(&proof_a, 0);
                vector::pop_back(&mut proof_a);
                vector::push_back(&mut proof_a, first + 1);
            };
            let ok = MulCircuitBlsVerifier::verify(
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
