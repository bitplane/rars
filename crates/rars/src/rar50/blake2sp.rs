const BLOCK_BYTES: usize = 64;
const OUT_BYTES: usize = 32;
const PARALLELISM: usize = 8;
const BUFFER_BYTES: usize = BLOCK_BYTES * PARALLELISM;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; BLOCK_BYTES],
    buflen: usize,
    last_node: bool,
}

impl Blake2s {
    fn new(node_offset: u64, node_depth: u8, last_node: bool) -> Self {
        let mut param = [0u8; 32];
        param[0] = OUT_BYTES as u8;
        param[2] = PARALLELISM as u8;
        param[3] = 2;
        param[8..14].copy_from_slice(&node_offset.to_le_bytes()[..6]);
        param[14] = node_depth;
        param[15] = OUT_BYTES as u8;

        let mut h = IV;
        for (word, chunk) in h.iter_mut().zip(param.chunks_exact(4)) {
            *word ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        Self {
            h,
            t: 0,
            buf: [0; BLOCK_BYTES],
            buflen: 0,
            last_node,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        // Stripe updates are one 64-byte block, final leaf tails are 1..=64
        // bytes, and the root consumes one 32-byte leaf digest at a time.
        debug_assert!(!input.is_empty() && input.len() <= BLOCK_BYTES);
        if self.buflen > 0 {
            let fill = BLOCK_BYTES - self.buflen;
            if input.len() > fill {
                self.buf[self.buflen..].copy_from_slice(&input[..fill]);
                self.t = self.t.wrapping_add(BLOCK_BYTES as u64);
                let block = self.buf;
                self.compress(&block, false);
                self.buflen = 0;
                input = &input[fill..];
            } else {
                self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
                self.buflen += input.len();
                return;
            }
        }
        self.buf[..input.len()].copy_from_slice(input);
        self.buflen = input.len();
    }

    fn finalize(mut self) -> [u8; OUT_BYTES] {
        self.t = self.t.wrapping_add(self.buflen as u64);
        self.buf[self.buflen..].fill(0);
        let block = self.buf;
        self.compress(&block, true);

        let mut out = [0u8; OUT_BYTES];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES], last_block: bool) {
        let mut m = [0u32; 16];
        for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last_block {
            v[14] = !v[14];
        }
        if last_block && self.last_node {
            v[15] = !v[15];
        }

        for s in SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

pub(crate) struct Hasher {
    leaves: [Blake2s; PARALLELISM],
    buffer: [u8; BUFFER_BYTES],
    buffer_len: usize,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self {
            leaves: [
                Blake2s::new(0, 0, false),
                Blake2s::new(1, 0, false),
                Blake2s::new(2, 0, false),
                Blake2s::new(3, 0, false),
                Blake2s::new(4, 0, false),
                Blake2s::new(5, 0, false),
                Blake2s::new(6, 0, false),
                Blake2s::new(7, 0, true),
            ],
            buffer: [0; BUFFER_BYTES],
            buffer_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }

        if self.buffer_len > 0 {
            let fill = BUFFER_BYTES - self.buffer_len;
            if input.len() >= fill {
                self.buffer[self.buffer_len..].copy_from_slice(&input[..fill]);
                let group = self.buffer;
                self.update_group(&group);
                self.buffer_len = 0;
                input = &input[fill..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
        }

        let mut chunks = input.chunks_exact(BUFFER_BYTES);
        for group in &mut chunks {
            self.update_group(group);
        }
        let tail = chunks.remainder();
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.buffer_len = tail.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; OUT_BYTES] {
        if self.buffer_len > 0 {
            let tail = &self.buffer[..self.buffer_len];
            for (leaf_index, leaf) in self.leaves.iter_mut().enumerate() {
                let start = leaf_index * BLOCK_BYTES;
                if tail.len() > start {
                    let end = (start + BLOCK_BYTES).min(tail.len());
                    leaf.update(&tail[start..end]);
                }
            }
        }

        let mut root = Blake2s::new(0, 1, true);
        for leaf in self.leaves {
            root.update(&leaf.finalize());
        }
        root.finalize()
    }

    fn update_group(&mut self, group: &[u8]) {
        for (leaf, block) in self.leaves.iter_mut().zip(group.chunks_exact(BLOCK_BYTES)) {
            leaf.update(block);
        }
    }
}

pub(crate) fn hash(input: &[u8]) -> [u8; OUT_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[cfg(test)]
mod tests {
    use super::{hash, Hasher};

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
