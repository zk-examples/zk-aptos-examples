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

    fun vk_alpha_g1_bytes(): vector<u8> { x"a33b59f3334adfa2e1d8f3d5dc8d4ef296db118e1f3c7c833c6459f2a717dcfcfacd25cf9c14569f45d77bea45af2754" }
    fun vk_beta_g2_bytes(): vector<u8> { x"a68d5343563ed062cdf3400aadc1e99ce4b0ab628c350f413c8a6cc0dbb071c51c62132c8a05c956b89c31dc6e4231260b2b0478b9aea8b1168857dc105216fb3059b8622eeece51ae9e174214b253a6fef26caaa9bd6789c24e9ed47bfa5c10" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"954bd5d3702150e9bb7f90ee549e76917e42ee50d03e7142322f2e113b25449c59dc94314db3eed282f5ad5324c546aa097d17bb033b930d34002a62123216b409f304244eddfca634da280728782211cbb89ba97ec7aaca79e428081e085e9a" }
    fun vk_delta_g2_bytes(): vector<u8> { x"8155c4205042624e5b4f3950aa0252a5f3324c1934d50f3b923132d430b1c80731fdf80deb00613a6569448fb05644980f8865716fde6eb0f3eefe2a92d8d1ca689ca0b0f9bf7719d490ee08e126648249ac7b5c1e5a3666d1013bbf890c2f0e" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"93208a117c173f965f28c0843ceec139d48eee613717abe5a3a4bd8819efc17f36792ba76e65a894c92645bab86b5dfe",
        x"a8bf87001bd7466230085451dc2e49472153c00339fa884f128685ce57a6c562bce0b936e343915d579008b224dfb5d0",
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
