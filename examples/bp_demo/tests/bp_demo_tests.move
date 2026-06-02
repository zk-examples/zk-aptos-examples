#[test_only]
module my_addr::bp_demo_tests {
    use my_addr::bp_demo;

    fun commitment_bytes(): vector<u8> {
        x"aa034e37289b4a363c10942b1ffe5ba48cfa864ab220c35e93c2ea1fa959863b"
    }

    fun proof_bytes(): vector<u8> {
        x"6e06a3ac2d4b9fc507437186439e488dd8a659cac32bedbaa5f86d6565bcf1259e7c6b5e36d739774c6c1d03d64ec431857c1020c10ea3905d9afa6ca1513a07ee6cd47fa81ad9d881b36419d211a5211e5fd0cdfbc20fe2e843ed009cdc6137c4abca1b7d5136a1efa25b575c3fafcacd803dda850bc3c0478d7a974d07635a3f9dbb9fd32412f54aa6b54aa4c728f9c782e28bb51944a491c1148387008a0d83f12575c7129fd0f9c36e0e6e833d68a5dfba02deeff12df2a6dcf1b4d89005ee6ea65b13f2a7e1cefd7aa4d5bf1d4c15512a3174c18eb4c92f2f8af33f3a0a6c66e0448b2eafdb36922f466923da8dd99d5ae80a6c5b98b57bef10f8f1f242dc6ec4a552191a5d8e116262ed57e09e81d2d97438ff8baa5d41a9028b58907dd26ecb4e42ed899da1aa6050aabda3213dea5c8041bd6f33f3aef6b3e1b97d096a8544dda9e80636cc3e6936fe1b023928dcfebe0ceba232bc265a529058f25e12f574269e50860d732ac8519ebe6fad04423e4328ad518d68d291a8da90f30b0215e4bd3d5e187491134fb1f7068f5a2e5d3d620cb3d1b7ddc8a03c6f7e3a5772fba89ea39971211306a1c69a9734a9fc9fbd27125f8f447c12f8d543f5f34b10dcf512c00026ce3562675009175d5c67a12e964251bd7d44f862adfe95532f662726f64a0ab903039398276f44e8dd61e916203e6f0442ba02050fa6a95e5712abb5d7e89693c1b82558ee099591dafd5250e5504c402d58f30629be12580a7ab6b6f4fbcb5be04b4529f78207c3ca217f7518b7e4f7e26118ed371a9988034c71a61da994f40f63c3dd1b6167f0aadfc74c52e602a183f95f4ddbdfbb990e"
    }

    fun dst(): vector<u8> {
        x"6d792d6170746f732d6170702f72616e67652d70726f6f662f7631"
    }

    #[test]
    fun test_valid_range_proof() {
        assert!(bp_demo::verify_range(
            commitment_bytes(),
            proof_bytes(),
            32,
            dst(),
        ), 1);
    }

    #[test]
    fun test_wrong_dst_fails() {
        assert!(!bp_demo::verify_range(
            commitment_bytes(),
            proof_bytes(),
            32,
            b"wrong-dst",
        ), 1);
    }

    #[test]
    fun test_unsupported_bits_fail() {
        assert!(!bp_demo::verify_range(
            commitment_bytes(),
            proof_bytes(),
            7,
            dst(),
        ), 1);
    }
}
