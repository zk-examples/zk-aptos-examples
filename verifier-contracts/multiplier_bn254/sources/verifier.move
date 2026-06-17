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

    fun vk_alpha_g1_bytes(): vector<u8> { x"ae552ff44bb74a89a001dd034d83d44ba0738776597f63521a94ec91cf2bf71e15714a9be1624959f6287fbbe8c7fd74b6cb216d46f60ef0bcab96df5508ef18" }
    fun vk_beta_g2_bytes(): vector<u8> { x"42b21d373bdc239c363b441e29ebb429195b4c8e53f12fe732fa3fb5229e231a47cfd12ba893ffe18c114778220b784979bf9be6ec5d5f8684ac215782983520f036372124603ad385230cfa792154bfdf882f37c6caa91a7f157ca5e1d47a0b8143b07c7daef7877acbd87e86a98011cffc8abcb38f68b644fc93bd5a3f3404" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609" }
    fun vk_delta_g2_bytes(): vector<u8> { x"057fcc59db0ab695f617b3e2ce42ff271813a8904cd1b153f603d44f7a51e226c08c4cfdc1a5418a4df8dc65d52fe96887bca2a6f76d389eaf172e7b4dedb81cdcdb7d500f5ded178230783ce30a848b939e18358f989b03c26d98a62b29a503830854482613e4ee31364f86dea9511ecc37d32b41e08f5d573dadb9bf9a4c21" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"23f21d91a8077f7d782ab5b1ccec1fdd62d6c69c66da497ad221108438ae3c14ae6a578bd77f4b1cdf67abc450cab23d0caeb3f9c95d7c085b0e7ea5d1f5a826",
        x"6a33aeb191a6c038dff1fb0a12ca97680a818e9e6cf62a7d99674c5b431c290315fa8837931222c1248a4e760e97201dae0dd2d267e0c4d400744e8d352ea418",
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
        let result: vector<Element<Bn254G1>> = vector[];
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
                let points: vector<Element<Bn254G1>> = vector[];
                vector::push_back(&mut points, *vector::borrow(&ic, idx + 1));
                let scalars: vector<Element<Bn254Fr>> = vector[];
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
