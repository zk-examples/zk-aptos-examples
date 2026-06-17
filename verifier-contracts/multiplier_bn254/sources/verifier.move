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

    fun vk_alpha_g1_bytes(): vector<u8> { x"2914789e8255981455de247e68f372a73c983c6c18387c8d946eeb607efe5e05361a7b5c27ffcc9a4471ec5cae15bc39a62070125e2d032a93a03a8aa8bb6210" }
    fun vk_beta_g2_bytes(): vector<u8> { x"7f936ba9280c8f647c9356e547df42fbc03ffacb1e6ee2a28449adc9cab4c01757f47646665aea8b3a84cf8e605e062e8ef9e9da2eaab64d9730b31b7e01bc2672cc4fb74cdcfae6325dc4027c5db99e9b44dec2946c3193c70ffce72b77062855de43dc70945a76527e2dbf06390e4dc94035eb4342947de443b1fb3d49e012" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609" }
    fun vk_delta_g2_bytes(): vector<u8> { x"97254237a4e7565ccc6b819c8d0b1b1ec09d67ba96ddb53290f04bceb42f5011ed972c180b6bb755bd97e3890f1979eedbb656191b4cf8744604592e625cc100e247d02ee36bdd74486949a0a9cb93842e260378e5f6a14ff4d02fc57b2433123e26dbd583236a923ca2b302d46265b2364185285106f25d3e7669eea6653a0c" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"1271b0edbd3e05946ba8e4b30ceb45731eb834b73a03ff6946fd40033dcf392eaa3c88c4b37e925627b780fc7d8816d38a01170aac010139215105a691ea1f19",
        x"93859141fdeb3baa923d8684504546259d680a713b8e1cbd1d0d32a27cf8a11a3a7de102302424c57b805689edd06a827a4f428592d6649921c79e102eb55302",
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
