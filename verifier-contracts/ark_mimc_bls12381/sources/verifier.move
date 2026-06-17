module zk_aptos::ArkMimcBlsVerifier {
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

    fun vk_alpha_g1_bytes(): vector<u8> { x"9819f632fa8d724e351d25081ea31ccf379991ac25c90666e07103fffb042ed91c76351cd5a24041b40e26d231a5087e" }
    fun vk_beta_g2_bytes(): vector<u8> { x"871f36a996c71a89499ffe99aa7d3f94decdd2ca8b070dbb467e42d25aad918af6ec94d61b0b899c8f724b2b549d99fc1623a0e51b6cfbea220e70e7da5803c8ad1144a67f98934a6bf2881ec6407678fd52711466ad608d676c60319a299824" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"96750d8445596af8d679487c7267ae9734aeac584ace191d225680a18ecff8ebae6dd6a5fd68e4414b1611164904ee120363c2b49f33a873d6cfc26249b66327a0de03e673b8139f79809e8b641586cde9943fa072ee5ed701c81b3fd426c220" }
    fun vk_delta_g2_bytes(): vector<u8> { x"8d3ac832f2508af6f01872ada87ea66d2fb5b099d34c5bac81e7482c956276dfc234c8d2af5fd2394b5440d0708a2c9f124a53c0755e9595cf9f8adade5deefcb8a574a67debd3b74d08c49c23ddc14cd6d48b65dce500c8a5d330e760fe85bb" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"8190f875ce3a03267d1c60f5d51dbfdae7afc56913cb465dda6d27cbd74d0436a4891ebe4441630aa87eb7eed662d9ed",
        x"84ef9f5acf7eb4cd46ab33fc795a4bd91303c05ac69598bd85ba57bc18929cdd842398184313b6e08e4aace22df66f7f",
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
