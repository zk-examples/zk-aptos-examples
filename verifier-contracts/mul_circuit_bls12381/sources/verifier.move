module zk_aptos::MulCircuitBlsVerifier {
    use aptos_std::bls12381_algebra::{
        Fr,
        FormatFrLsb as Bls12381FormatFrLsb,
        FormatG1Compr as Bls12381FormatG1Compr,
        FormatG2Compr as Bls12381FormatG2Compr,
        G1 as Bls12381G1,
        G2 as Bls12381G2,
        Gt as Bls12381Gt,
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

    fun vk_alpha_g1_bytes(): vector<u8> { x"81d64df1734de5176989f8be61a3a5a9594618fb791198e3cabc2d713bf419fc809856b87536748c76fd6861bfe110e9" }
    fun vk_beta_g2_bytes(): vector<u8> { x"9460ee1f756c2a314f55c0b50e1420a5ad86cc3b34c48b605c4731f160d2777f182116c41de8440b1e964190ff55402011342ff63424642bf9dbcc3672d9dd7ce0da5583103a7ffbfbd201bf978cf1d35ad6ab4279a68420114032f6d86d7a2f" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"a184a71a4cc3da246aa223cd0ad60896e68eafb55027e8c7f28c0b103a8ae5b485e14b8612ffa3f772def7d4fcc02a500445d1dd2f956b6703a7f7fee37c3de224b9fda5e6e7d63dcf2d23c0af6130c401f82fe040bbad7ba762121a481d06cc" }
    fun vk_delta_g2_bytes(): vector<u8> { x"a35dcf82618381a94db3c92d0a7a3bb2a8834663e040f180753a58d2e0a4185bccd3580760152c9a5d764c1e23bb0b990188e1251a87ac453332cc7990a7d4a9342d535a6147c8e204a11d55d2eee3af9b9f7999005a561e96ec3820cbcd72ce" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"9471cf4ba9576b2c7be52ad99fe901f79f07812f7a9bd4b6cf3f65942fe60575ea8a75e54f3d3c2e2bf1aac40c64a1c2",
        x"8b407aff6b16f5f0cc428550d7dd947604474d1893aa7329f9971efe84fa21e4ae38e4e9a993e207453236ffe8b91b16",
    ] }

    fun vk_alpha_g1(): Element<Bls12381G1> {
        deserialize_or_abort_bls12381_g1(&vk_alpha_g1_bytes())
    }

    fun vk_beta_g2(): Element<Bls12381G2> {
        deserialize_or_abort_bls12381_g2(&vk_beta_g2_bytes())
    }

    fun vk_gamma_g2(): Element<Bls12381G2> {
        deserialize_or_abort_bls12381_g2(&vk_gamma_g2_bytes())
    }

    fun vk_delta_g2(): Element<Bls12381G2> {
        deserialize_or_abort_bls12381_g2(&vk_delta_g2_bytes())
    }

    fun vk_gamma_abc_g1(): vector<Element<Bls12381G1>> {
        let result = vector::empty<Element<Bls12381G1>>();
        let bytes = vk_gamma_abc_g1_bytes();
        let idx = 0;
        while (idx < vector::length(&bytes)) {
            vector::push_back(
                &mut result,
                deserialize_or_abort_bls12381_g1(vector::borrow(&bytes, idx)),
            );
            idx = idx + 1;
        };
        result
    }

    fun vk_gamma_abc_commitment(
        public_inputs: vector<vector<u8>>,
        ic: vector<Element<Bls12381G1>>,
    ): (Element<Bls12381G1>, bool) {
        if (vector::length(&public_inputs) + 1 != vector::length(&ic)) {
            return (zero<Bls12381G1>(), false);
        };

        let acc = *vector::borrow(&ic, 0);
        if (!vector::is_empty(&public_inputs)) {
            let idx = 0;
            while (idx < vector::length(&public_inputs)) {
                let scalar = deserialize_or_abort_bls12381_fr(vector::borrow(&public_inputs, idx));
                let points = vector::empty<Element<Bls12381G1>>();
                vector::push_back(&mut points, *vector::borrow(&ic, idx + 1));
                let scalars = vector::empty<Element<Fr>>();
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
        let a = deserialize_or_abort_bls12381_g1(&proof_a);
        let b = deserialize_or_abort_bls12381_g2(&proof_b);
        let c = deserialize_or_abort_bls12381_g1(&proof_c);

        let expected = pairing<Bls12381G1, Bls12381G2, Bls12381Gt>(&vk_alpha_g1(), &vk_beta_g2());
        expected = add(&expected, &pairing<Bls12381G1, Bls12381G2, Bls12381Gt>(&commitments, &vk_gamma_g2()));
        expected = add(&expected, &pairing<Bls12381G1, Bls12381G2, Bls12381Gt>(&c, &vk_delta_g2()));

        let lhs = pairing<Bls12381G1, Bls12381G2, Bls12381Gt>(&a, &b);
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

    fun deserialize_or_abort_bls12381_g1(value: &vector<u8>): Element<Bls12381G1> {
        let point = deserialize_element<Bls12381G1, Bls12381FormatG1Compr>(value);
        if (option::is_none(&point)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(point)
    }

    fun deserialize_or_abort_bls12381_g2(value: &vector<u8>): Element<Bls12381G2> {
        let point = deserialize_element<Bls12381G2, Bls12381FormatG2Compr>(value);
        if (option::is_none(&point)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(point)
    }

    fun deserialize_or_abort_bls12381_fr(value: &vector<u8>): Element<Fr> {
        let scalar = deserialize_element<Fr, Bls12381FormatFrLsb>(value);
        if (option::is_none(&scalar)) {
            abort EINVALID_PROOF;
        };
        option::destroy_some(scalar)
    }
}
