#[test_only]
module zk_aptos::MultiplierBnVerifier_tests {
    use zk_aptos::MultiplierBnVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"faaa7c88b093ad609c006f27bc32916c74f622cf60b6b25eb6ae6e83d243bd2d4339c2f7958e81a8feac82b177df6ef37f354843f888aedde28ca517889db50d" }
    fun proof_b_bytes(): vector<u8> { x"a22bde9c4e2df8d849a06d8b3c7a15537dd557dc8074b8295de4d88a87985e2124740ed44130ba8b9fcfde48e2199a1a2d8e0ecc66b6ce990fc41ca3ad77b51e6942503e369bf2987bb6f1b79ee7a449b0a710b6209f15d5d43154e3fa7724065daf28f54471b6dc40cfe70240d36d5142a7066d45ee3dae343c36ae500ba20f" }
    fun proof_c_bytes(): vector<u8> { x"c986d84dde4eba35f54a361ce6050a97b3d3be6e1c8ea322f9a846300d17f71c921b9ef18782e095947a08488242c3717da021e05007ef5d014c9ceba628240f" }
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
    fun test_invalid_proof_fails() {
        let ok = MultiplierBnVerifier::verify(
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
            let ok = MultiplierBnVerifier::verify(
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
