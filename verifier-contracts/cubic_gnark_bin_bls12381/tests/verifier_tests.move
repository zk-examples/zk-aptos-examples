#[test_only]
module zk_aptos::CubicGnarkNativeBinBlsVerifier_tests {
    use zk_aptos::CubicGnarkNativeBinBlsVerifier;
    use std::vector;

    fun proof_a_bytes(): vector<u8> { x"b93b405f3280c9c0bd8d1bbf7f16744045e551b763a946e1a17afb381923c043c8052ad6561723af516bb5e1d3e0e817" }
    fun proof_b_bytes(): vector<u8> { x"85183b50dc0bd8e662d50292c369e53c25afd6ce0682272c3c0c6eb9706e7a420c19507c1ba3b5e34e0b5e511c08353508fdce31347691a2eacd7c2db7873156da3649c2d22643709fbadb34533dee86fd45094df99d529b334808938a7fa0d3" }
    fun proof_c_bytes(): vector<u8> { x"adaff9352f2358cac7f10e53809f99b688eee61be3ad132e0981456b61c2ffd20be6295ed9f54785c667b911e33390f3" }
    fun public_inputs_bytes(): vector<vector<u8>> { vector[
        x"2300000000000000000000000000000000000000000000000000000000000000",
    ] }
    fun invalid_public_inputs_bytes(): vector<vector<u8>> { vector[
        x"0000000000000000000000000000000000000000000000000000000000000000",
    ] }

    #[test]
    fun test_valid_proof() {
        let ok = CubicGnarkNativeBinBlsVerifier::verify(
            public_inputs_bytes(),
            proof_a_bytes(),
            proof_b_bytes(),
            proof_c_bytes(),
        );
        assert!(ok, 1);
    }

    #[test]
    fun test_invalid_proof_fails() {
        let ok = CubicGnarkNativeBinBlsVerifier::verify(
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
            let ok = CubicGnarkNativeBinBlsVerifier::verify(
                empty_public_inputs,
                proof_a,
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        } else {
            let ok = CubicGnarkNativeBinBlsVerifier::verify(
                invalid_public_inputs_bytes(),
                proof_a_bytes(),
                proof_b_bytes(),
                proof_c_bytes(),
            );
            assert!(!ok, 1);
        };
    }
}
