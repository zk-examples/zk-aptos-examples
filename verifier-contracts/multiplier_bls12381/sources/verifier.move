module zk_aptos::MultiplierBlsVerifier {
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

    fun vk_alpha_g1_bytes(): vector<u8> { x"a2f29bb9bb7375a4ee0c713f22890d5d26a53362fe0462c73742049c7f8784acf4fb74bb4aa72ddabb53fddc00436d7c" }
    fun vk_beta_g2_bytes(): vector<u8> { x"af58bc2826a7ddb50cd58303c6a9f7e541116ec45a747253d32ed1053b5b2ec2afb1ca30587f5bcb0655863216b0048e09bfe43e5e972340312f38c46ee62d705837b8ea30f4526a8c94394813a458818f18eb3fdbee7e682fc2b0ee5e8238ee" }
    fun vk_gamma_g2_bytes(): vector<u8> { x"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" }
    fun vk_delta_g2_bytes(): vector<u8> { x"a65c7ffde3fed83e80be997332613c8b732a432b2901734ea2fa571155e5071ef2dc809ab345f7ceafeb8ac1e2187e060a8c531d340b5982b00fe6a685c776ca7abcd539068df8c0f90d440bcd1becde2e9d19310d9584972013e2c3ed77cf1e" }
    fun vk_gamma_abc_g1_bytes(): vector<vector<u8>> { vector[
        x"b053c691e4ec999ecfd8500a76e48204643abedb59e21e1ff701f75995f4420a986faba1531bfb7e0619e102a888fd25",
        x"a9a96bd3ba22ce8228142032870672b03ed5ebe963af9ed893222e2a19ca5b00a24172243e4a4f581c1b2067007dd323",
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
