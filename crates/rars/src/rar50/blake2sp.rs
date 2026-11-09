//! BLAKE2sp, the RAR 5 file hash. `blake2s_simd` picks SSE4.1 or AVX2 at run
//! time; the portable eight-lane code this replaced ran a tenth as fast on
//! baseline x86-64, slower than reading a stored member.

const OUT_BYTES: usize = 32;

pub(crate) struct Hasher(blake2s_simd::blake2sp::State);

impl Hasher {
    pub(crate) fn new() -> Self {
        Self(blake2s_simd::blake2sp::State::new())
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub(crate) fn finalize(self) -> [u8; OUT_BYTES] {
        *self.0.finalize().as_array()
    }
}

pub(crate) fn hash(input: &[u8]) -> [u8; OUT_BYTES] {
    *blake2s_simd::blake2sp::blake2sp(input).as_array()
}

#[cfg(test)]
mod tests {
    use super::{hash, Hasher};

    const BLOCK_BYTES: usize = 64;
    const PARALLELISM: usize = 8;

    /// One BLAKE2sp tree node, built from BLAKE2s parameters rather than the
    /// hasher under test.
    fn node(offset: u64, depth: u8, last: bool) -> blake2s_simd::State {
        blake2s_simd::Params::new()
            .hash_length(32)
            .fanout(PARALLELISM as u8)
            .max_depth(2)
            .inner_hash_length(32)
            .node_offset(offset)
            .node_depth(depth)
            .last_node(last)
            .to_state()
    }

    #[test]
    fn matches_public_blake2sp_vectors() {
        assert_eq!(
            hex(&hash(b"")),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
        assert_eq!(
            hex(&hash(b"abc")),
            "70f75b58f1fecab821db43c88ad84edde5a52600616cd22517b7bb14d440a7d5"
        );
    }

    #[test]
    fn block_and_stripe_boundaries_match_independent_tree_hash_vectors() {
        // Python hashlib.blake2s oracle: distribute consecutive 64-byte
        // blocks over eight leaves, fanout=8, depth=2, inner_size=32,
        // node_offset=leaf index, node_depth=0, last_node on leaf 7. Hash
        // their concatenated digests at node_depth=1, last_node=true.
        // The same oracle reproduces both public vectors above.
        for (length, expected) in [
            (
                1,
                "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239",
            ),
            (
                63,
                "1024c940be7341449b5010522b509f65bbdc1287b455c2bb7f72b2c92fd0d189",
            ),
            (
                64,
                "52603b6cbfad4966cb044cb267568385cf35f21e6c45cf30aed19832cb51e9f5",
            ),
            (
                65,
                "fff24d3cc729d395daf978b0157306cb495797e6c8dca1731d2f6f81b849baae",
            ),
            (
                127,
                "a626543c271fccc3e4450b48d66bc9cbdeb25e5d077a6213cd90cbbd0fd22076",
            ),
            (
                511,
                "8e1e8ee1ffa0a01028fff3bff0ae9df2565a82e55a04e9541bb78b9c4778336f",
            ),
            (
                512,
                "8d9e357863298dd8364b7caf4234317f8a49f180d788b7abffb521925f1e1ff1",
            ),
            (
                513,
                "8a4bc3330497e681f15daf24fc496044a1c32bf0a837a210399e1ae4af7e92be",
            ),
            (
                1023,
                "0db3cb64828effe5b2aa6be5e865121f03226cca6423b8841b1019cfad09ac09",
            ),
            (
                1024,
                "48467549502e2d3f422870bfb1d09bce71a065735763bf654582cf46a5112793",
            ),
            (
                1025,
                "04e03e65b8f19a5f46288802b2a515bab73363262caa300ae75c0eb29c016e5a",
            ),
            (
                4097,
                "055d3f5f5440fe6c8dd0dcceb503b93caa03a533b71b1e47b4fdcb5577b8762a",
            ),
        ] {
            let input: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            assert_eq!(hex(&hash(&input)), expected, "length={length}");
            for chunk_size in [1, 31, 32, 63, 64, 65, 127, 511, 512, 513] {
                let mut hasher = Hasher::new();
                hasher.update(&[]);
                for chunk in input.chunks(chunk_size) {
                    hasher.update(chunk);
                    hasher.update(&[]);
                }
                assert_eq!(
                    hex(&hasher.finalize()),
                    expected,
                    "length={length}, chunk_size={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn streaming_hasher_matches_one_shot_hash() {
        let input: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
        let mut hasher = Hasher::new();
        for chunk in input.chunks(37) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), hash(&input));
    }

    #[test]
    fn batched_stripes_match_independent_long_tree_hash_vectors() {
        // Same independent hashlib tree parameters as the boundary vectors,
        // with enough complete stripes to repeatedly enter the batched path.
        for (length, expected) in [
            (
                65_535,
                "ab141a58697b388f28149af484e466beea9f28dbd5aed8e649f02fa8d0afcb0d",
            ),
            (
                65_536,
                "f31ebaad05d2ead9e476110facfaaf38141a58d53da972a09be1d9e22e0a94ad",
            ),
            (
                65_537,
                "60e42e849f6f22218ae9faeb17cf9eaf00fd9bc140a4b392109d6378557a4192",
            ),
            (
                1_048_576,
                "65f05ea2b52b252474eadbcc69d159009c3b7b98e2c630a3056561269d78656e",
            ),
        ] {
            let input: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            assert_eq!(hex(&hash(&input)), expected, "length={length}");
            for chunk_size in [63, 64, 65, 511, 512, 513, 4097, 65_536] {
                let mut hasher = Hasher::new();
                for chunk in input.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                assert_eq!(
                    hex(&hasher.finalize()),
                    expected,
                    "length={length}, chunk={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn batched_updates_match_scalar_leaves_for_varied_data_and_tails() {
        let mut random = 0x1234_5678u32;
        let input: Vec<_> = (0..65_537)
            .map(|_| {
                random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (random >> 24) as u8
            })
            .collect();
        for length in [
            0, 1, 63, 64, 65, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 65_535, 65_536,
            65_537,
        ] {
            let data = &input[..length];
            let mut leaves: [_; PARALLELISM] =
                std::array::from_fn(|lane| node(lane as u64, 0, lane == PARALLELISM - 1));
            for (block_index, block) in data.chunks(BLOCK_BYTES).enumerate() {
                leaves[block_index % PARALLELISM].update(block);
            }
            let mut root = node(0, 1, true);
            for leaf in leaves {
                root.update(leaf.finalize().as_bytes());
            }
            let expected: [u8; 32] = *root.finalize().as_array();
            assert_eq!(hash(data), expected, "length={length}");
            for chunk_size in [1, 67, 511, 512, 513, 4097] {
                let mut hasher = Hasher::new();
                for chunk in data.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                assert_eq!(
                    hasher.finalize(),
                    expected,
                    "length={length}, chunk={chunk_size}"
                );
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
