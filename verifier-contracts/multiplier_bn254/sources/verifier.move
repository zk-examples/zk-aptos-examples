module zk_aptos::MultiplierBnVerifier {
    use aptos_std::bn254_algebra::{
        Fr as Bn254Fr,
        FormatFrLsb as Bn254FormatFrLsb,
        FormatG1Uncompr as Bn254FormatG1Uncompr,
        FormatG2Uncompr as Bn254FormatG2Uncompr,
        G1 as Bn254G1,
        G2 as Bn254G2,
        Gt as Bn254Gt,
    };
    use aptos_std::crypto_algebra::{
        deserialize as deserialize_element,
        Element,
        add,
        eq,
        multi_scalar_mul,
        pairing,
        zero,
    };
    use std::option;
    use std::vector;

    const EINVALID_PROOF: u64 = 1;

    fun vk_alpha_g1_bytes(): vector<u8> { x"4c546ec198ad2be20d6f281184e8060ee0434843a6cd82cf9ebc1526c1ca8b1740b5fb50458cf4b1e4c08b5153a213ef9fe3bfa03182d4a8eeae41126034761a" }
    fun vk_beta_g2_bytes(): vector<u8> { x"0baaaf8b3075e6ce1a90cebfd6551b747ca5a8006c4e30b2090eb36cf3d0281dd31654fefbd6b956435427243759828cbc6a70e07d9511e5f41d7b89304ff42c5429592eb920737facb290bb8038d70a97042b0530cb923cfb86d5c68ceee703319386b6ec40dc01981b2859aebe28fc9702cbc815d9b71904a4d073c1360f09" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609" }
    fun vk_delta_g2_bytes(): vector<u8> { x"85a0d216766c0e0b57a6b12c15ad93b2b09b3a65a3f2b0d8a5b8dd35b6fea3245c0de39a6fc729b9107c1d9a422795479c3b6eb2782b5f8e9b9fc5d047f84a01be17a5f5e85c72c416f0f56b918aa44149d715b5a4ea8ff49db82b7dec8b0a243d24c9174dc72a0e5d79b1556b94dec88287304cee32c01ebf867efb4a50ba0e" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"0a446c5dfcd22c9065e90e1cd61dda5121f53d09889778ccc571deff1d9ea1166cb6c7460e39752f1e5d613c9955f3e43dae0456404bde84bcba76534b49f229",
        x"1adb626f24d71b6a8e804280adfc3feeedd4917d8b92cc2cf43cf49824bc200ad27f0910ac0aa6bcf531fdc9046009295158f12bdc15781d745dff88d940dc28",
    ] }

    fun vk_alpha_g1(): Element<Bn254G1> {
        deserialize_or_abort_bn254_g1(&vk_alpha_g1_bytes())
    }

    fun vk_beta_g2(): Element<Bn254G2> {
        deserialize_or_abort_bn254_g2(&vk_beta_g2_bytes())
    }

    fun vk_gamma_g2(): Element<Bn254G2> {
        deserialize_or_abort_bn254_g2(&vk_gamma_g2_bytes())
    }

    fun vk_delta_g2(): Element<Bn254G2> {
        deserialize_or_abort_bn254_g2(&vk_delta_g2_bytes())
    }

    fun vk_gamma_abc_g1(): vector<Element<Bn254G1>> {
        let result = vector::empty<Element<Bn254G1>>();
        let bytes = vk_gamma_abc_g1_bytes();
        let idx = 0;
        while (idx < vector::length(&bytes)) {
            vector::push_back(
                &mut result,
                deserialize_or_abort_bn254_g1(vector::borrow(&bytes, idx)),
            );
            idx = idx + 1;
        };
        result
    }

    fun vk_gamma_abc_commitment(
        public_inputs: vector<vector<u8>>,
        ic: vector<Element<Bn254G1>>,
    ): (Element<Bn254G1>, bool) {
        if (vector::length(&public_inputs) + 1 != vector::length(&ic)) {
            return (zero<Bn254G1>(), false);
        };

        let acc = *vector::borrow(&ic, 0);
        if (!vector::is_empty(&public_inputs)) {
            let idx = 0;
            while (idx < vector::length(&public_inputs)) {
                let scalar = deserialize_or_abort_bn254_fr(vector::borrow(&public_inputs, idx));
                let points = vector::empty<Element<Bn254G1>>();
                vector::push_back(&mut points, *vector::borrow(&ic, idx + 1));
                let scalars = vector::empty<Element<Bn254Fr>>();
                vector::push_back(&mut scalars, scalar);
                let scaled = multi_scalar_mul(&points, &scalars);
                acc = add(&acc, &scaled);
                idx = idx + 1;
            };
        };
        (acc, true)
    }

    public fun verify(
        public_inputs: vector<vector<u8>>,
        proof_a: vector<u8>,
        proof_b: vector<u8>,
        proof_c: vector<u8>,
    ): bool {
        let ic = vk_gamma_abc_g1();
        let (commitments, valid_inputs) = vk_gamma_abc_commitment(public_inputs, ic);
        if (!valid_inputs) {
            return false;
        };
        let a = deserialize_or_abort_bn254_g1(&proof_a);
        let b = deserialize_or_abort_bn254_g2(&proof_b);
        let c = deserialize_or_abort_bn254_g1(&proof_c);

        let expected = pairing<Bn254G1, Bn254G2, Bn254Gt>(&vk_alpha_g1(), &vk_beta_g2());
        expected = add(&expected, &pairing<Bn254G1, Bn254G2, Bn254Gt>(&commitments, &vk_gamma_g2()));
        expected = add(&expected, &pairing<Bn254G1, Bn254G2, Bn254Gt>(&c, &vk_delta_g2()));

        let lhs = pairing<Bn254G1, Bn254G2, Bn254Gt>(&a, &b);
        eq(&lhs, &expected)
    }

    public entry fun verify_entry(
        _signer: &signer,
        public_inputs: vector<vector<u8>>,
        proof_a: vector<u8>,
        proof_b: vector<u8>,
        proof_c: vector<u8>,
    ) {
        assert!(verify(public_inputs, proof_a, proof_b, proof_c), EINVALID_PROOF);
    }

    fun deserialize_or_abort_bn254_g1(value: &vector<u8>): Element<Bn254G1> {
        let point = deserialize_element<Bn254G1, Bn254FormatG1Uncompr>(value);
        if (option::is_none(&point)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(point)
    }

    fun deserialize_or_abort_bn254_g2(value: &vector<u8>): Element<Bn254G2> {
        let point = deserialize_element<Bn254G2, Bn254FormatG2Uncompr>(value);
        if (option::is_none(&point)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(point)
    }

    fun deserialize_or_abort_bn254_fr(value: &vector<u8>): Element<Bn254Fr> {
        let scalar = deserialize_element<Bn254Fr, Bn254FormatFrLsb>(value);
        if (option::is_none(&scalar)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(scalar)
    }
}
