#[test_only]
module zk_aptos::ArkMimcBn254Verifier_tests {
    use zk_aptos::ArkMimcBn254Verifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"4af94d64eb4c8a384c07b00c2744ecdbfeeb5d2d51283739ab4f279beefcdb149ab4a817c18794e4eb12a4dce4b47e8178af938f62fd503fc1bb52338497f01c" }
    fun proof_b_bytes(): vector<u8> { x"9f98c5c87fd280bf525c57cbf3148bce69507627300622a9c4fd046b88aa9716eb19a5f79b77aa3252dc57bc487c8c59f4decab20be64a24e7845a07e094c310435ebf3c5aa1c9afe7713edac8a71d03e6e6bfbafb3bc40cb344fccd398d331c8817cc5b4a869ff364dedb6bc9a6b75c00e59f6897370add2a0190da228a670a" }
    fun proof_c_bytes(): vector<u8> { x"572546ee5e79efc990bb697e0f1b3026d9298f7d5475d4270698f872f5e5f208d6b8199520916391c96a10ff02f0059684b8d804e1358abb2dde7997658f0814" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"2615248c0a010455af186e8fc226c299562d254ad30f15216aa10bed71861702",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = ArkMimcBn254Verifier::verify(
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
            let ok = ArkMimcBn254Verifier::verify(
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
            let ok = ArkMimcBn254Verifier::verify(
                public_inputs,
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
