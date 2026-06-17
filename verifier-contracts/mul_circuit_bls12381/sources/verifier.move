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

    fun vk_alpha_g1_bytes(): vector<u8> { x"b13156dbfafc99598736ea32e6e6f76827157189c543310546b43a8c03bb1f7fddee354893bedc017d2f262ef2f40ff0" }
    fun vk_beta_g2_bytes(): vector<u8> { x"b610a2b2c1a42c291e1454ffa17752bf6e4e731cf5c370572015d1a42f171d1d75d08b9fa4d89567a6dbd49bedff979d1467573ef4b9e5558777827349f49d1b559e6f0aacf02caca7f4ee29231d5ba47c27963caa961f141c3fc6501d64e387" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"a105ed0647bec69f861267f8f6cf69d71b2a6bf428bc63b3c9617cda0771d30aa7580baf6a110f4aebf3309b59f98fce09a3b08c5179a85a9ed20a49a1c5e755e02000f5e693a51734e210bbda693e12343721418e4bf278723e483b6a3dc055" }
    fun vk_delta_g2_bytes(): vector<u8> { x"b78ccbd6ad8ac7aaeb77f43097947b23c664d46ba907451c4495dd6b50f496f84bb66d4e1da6deeea3d8411399b98180011ec8009e7bc96643ae1505435d3c7e6256d7c58a28ab4c947a58413727f73e2a91211838b1bb2742ce202e16384860" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"aec4d3fddcd21c24e102ef761399729fc5966ccd17bf236e87ed11e8529411955368044469ac9c3359892b0a03ef7d0f",
        x"b82b392707badaf5f781a35fbc89b1336d63080eecb0c06e63e47d2cf837e20f42ed01519a6f3286e08aab9b0745b5a4",
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
        let result: vector<Element<Bls12381G1>> = vector[];
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
                let points: vector<Element<Bls12381G1>> = vector[];
                vector::push_back(&mut points, *vector::borrow(&ic, idx + 1));
                let scalars: vector<Element<Fr>> = vector[];
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
