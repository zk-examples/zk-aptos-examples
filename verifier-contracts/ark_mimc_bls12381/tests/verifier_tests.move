#[test_only]
module zk_aptos::ArkMimcBlsVerifier_tests {
    use zk_aptos::ArkMimcBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"991cb4f15ee73f0a70573803c00da564911afe8c9639252e74e263b13c6afbcab2a6b72d21e80bc14fa6fe7ab83b49e0" }
    fun proof_b_bytes(): vector<u8> { x"b776aa83e9258556d50156353d1e8764c1fbc48d3682fe4849f27ba2a6f25984e88285b5ebd325fc4a98bc94e183b38d04207cd70529663ab690852fcd62585de3a0222ccdf74002ef7c9a56d3a3d564ce5bfe2d6ff6f2d1e5c5960129a34db3" }
    fun proof_c_bytes(): vector<u8> { x"8574965f4a74a081a4aa3b5b7b44c60a170d25a438435df591edf120b67576dfb99f62da2fa6c9ea69eb6a214c633254" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"0ee291cfc951388c3c7f7c85ff2dfd42bbc66a6b4acaef9a5a51ce955125a74f",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = ArkMimcBlsVerifier::verify(
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
            let ok = ArkMimcBlsVerifier::verify(
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
            let ok = ArkMimcBlsVerifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
