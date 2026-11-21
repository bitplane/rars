pub(crate) const LANES: usize = 8;
pub(crate) const BLOCK_BYTES: usize = 64;

// Transposed so each state word fills one vector pair.
pub(crate) type Words = [[u32; LANES]; 8];

// RFC 7693 section 2.6.
pub(crate) const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

// RFC 7693 section 2.7.
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

pub(crate) fn compress(
    state: &mut Words,
    blocks: &[u8; LANES * BLOCK_BYTES],
    counters: [u64; LANES],
    last_block: bool,
    last_node: [bool; LANES],
) {
    let flag = |set: bool| if set { u32::MAX } else { 0 };
    let tail = [
        counters.map(|count| count as u32),
        counters.map(|count| (count >> 32) as u32),
        [flag(last_block); LANES],
        last_node.map(flag),
    ];
    // SAFETY: this module only compiles where the build enables `neon`.
    unsafe { neon::compress(state, blocks, &tail) }
}

mod neon {
    use super::{Words, BLOCK_BYTES, IV, LANES, SIGMA};
    use std::arch::aarch64::*;

    const VECTOR: usize = 4;
    type FourLanes = [uint32x4_t; 16];

    // Both halves step through each round together so eight G chains overlap, not four.
    #[target_feature(enable = "neon")]
    pub(super) fn compress(
        state: &mut Words,
        blocks: &[u8; LANES * BLOCK_BYTES],
        tail: &[[u32; LANES]; 4],
    ) {
        let (block_halves, _) = blocks.as_chunks::<{ VECTOR * BLOCK_BYTES }>();
        let h: [[uint32x4_t; 8]; 2] =
            std::array::from_fn(|half| std::array::from_fn(|word| load(&state[word], half)));
        let m: [FourLanes; 2] = std::array::from_fn(|half| transpose_message(&block_halves[half]));
        let mut v: [FourLanes; 2] = std::array::from_fn(|half| {
            let iv = |word: usize| vdupq_n_u32(IV[word]);
            let tail = |word: usize| veorq_u32(iv(word + 4), load(&tail[word], half));
            let h = &h[half];
            [
                h[0],
                h[1],
                h[2],
                h[3],
                h[4],
                h[5],
                h[6],
                h[7],
                iv(0),
                iv(1),
                iv(2),
                iv(3),
                tail(0),
                tail(1),
                tail(2),
                tail(3),
            ]
        });
        for sigma in &SIGMA {
            let [a, b] = &mut v;
            round(a, |word| m[0][sigma[word]]);
            round(b, |word| m[1][sigma[word]]);
        }
        for half in 0..2 {
            for word in 0..8 {
                let mixed = veorq_u32(h[half][word], veorq_u32(v[half][word], v[half][word + 8]));
                store(&mut state[word], half, mixed);
            }
        }
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn transpose_message(blocks: &[u8; VECTOR * BLOCK_BYTES]) -> FourLanes {
        let (rows, _) = blocks.as_chunks::<16>();
        let mut m = [vdupq_n_u32(0); 16];
        for group in 0..4 {
            let row = |lane: usize| load_bytes(&rows[lane * 4 + group]);
            let (r0, r1, r2, r3) = (row(0), row(1), row(2), row(3));
            let t0 = vreinterpretq_u64_u32(vtrn1q_u32(r0, r1));
            let t1 = vreinterpretq_u64_u32(vtrn2q_u32(r0, r1));
            let t2 = vreinterpretq_u64_u32(vtrn1q_u32(r2, r3));
            let t3 = vreinterpretq_u64_u32(vtrn2q_u32(r2, r3));
            m[group * 4] = vreinterpretq_u32_u64(vtrn1q_u64(t0, t2));
            m[group * 4 + 1] = vreinterpretq_u32_u64(vtrn1q_u64(t1, t3));
            m[group * 4 + 2] = vreinterpretq_u32_u64(vtrn2q_u64(t0, t2));
            m[group * 4 + 3] = vreinterpretq_u32_u64(vtrn2q_u64(t1, t3));
        }
        m
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn round(v: &mut FourLanes, m: impl Fn(usize) -> uint32x4_t) {
        g(v, [0, 4, 8, 12], m(0), m(1));
        g(v, [1, 5, 9, 13], m(2), m(3));
        g(v, [2, 6, 10, 14], m(4), m(5));
        g(v, [3, 7, 11, 15], m(6), m(7));
        g(v, [0, 5, 10, 15], m(8), m(9));
        g(v, [1, 6, 11, 12], m(10), m(11));
        g(v, [2, 7, 8, 13], m(12), m(13));
        g(v, [3, 4, 9, 14], m(14), m(15));
    }

    // RFC 7693 section 3.1, with BLAKE2s rotations 16, 12, 8 and 7.
    #[target_feature(enable = "neon")]
    #[inline]
    fn g(v: &mut FourLanes, [a, b, c, d]: [usize; 4], x: uint32x4_t, y: uint32x4_t) {
        v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), x);
        v[d] = rotate_right_16(veorq_u32(v[d], v[a]));
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = rotate_right::<12, 20>(veorq_u32(v[b], v[c]));
        v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), y);
        v[d] = rotate_right_8(veorq_u32(v[d], v[a]));
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = rotate_right::<7, 25>(veorq_u32(v[b], v[c]));
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn rotate_right_16(x: uint32x4_t) -> uint32x4_t {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
    }

    // One byte shuffle instead of a shift and an insert.
    #[target_feature(enable = "neon")]
    #[inline]
    fn rotate_right_8(x: uint32x4_t) -> uint32x4_t {
        let bytes = vcombine_u8(
            vcreate_u8(0x0407_0605_0003_0201),
            vcreate_u8(0x0C0F_0E0D_080B_0A09),
        );
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), bytes))
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn rotate_right<const RIGHT: i32, const LEFT: i32>(x: uint32x4_t) -> uint32x4_t {
        vsriq_n_u32::<RIGHT>(vshlq_n_u32::<LEFT>(x), x)
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn load_bytes(bytes: &[u8; 16]) -> uint32x4_t {
        // SAFETY: reads the 16 bytes `bytes` borrows; on little-endian
        // aarch64 each lane is the little-endian word BLAKE2s expects.
        unsafe { vreinterpretq_u32_u8(vld1q_u8(bytes.as_ptr())) }
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn load(words: &[u32; LANES], half: usize) -> uint32x4_t {
        let (vectors, _) = words.as_chunks::<VECTOR>();
        // SAFETY: reads the four words of `vectors[half]`, a borrowed array.
        unsafe { vld1q_u32(vectors[half].as_ptr()) }
    }

    #[target_feature(enable = "neon")]
    #[inline]
    fn store(words: &mut [u32; LANES], half: usize, value: uint32x4_t) {
        let (vectors, _) = words.as_chunks_mut::<VECTOR>();
        // SAFETY: writes the four words of `vectors[half]`, a mutably borrowed array.
        unsafe { vst1q_u32(vectors[half].as_mut_ptr(), value) }
    }
}

#[cfg(test)]
mod tests {
    use super::{compress, Words, BLOCK_BYTES, IV, LANES};

    fn initial() -> Words {
        // Default BLAKE2s parameters: 32-byte digest, fanout 1, depth 1.
        let mut first = IV;
        first[0] ^= 0x0101_0020;
        std::array::from_fn(|word| [first[word]; LANES])
    }

    fn digest(state: &Words, lane: usize) -> [u8; 32] {
        let mut out = [0; 32];
        for (word, bytes) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            *bytes = state[word][lane].to_le_bytes();
        }
        out
    }

    fn expected(message: &[u8], last_node: bool) -> [u8; 32] {
        *blake2s_simd::Params::new()
            .last_node(last_node)
            .to_state()
            .update(message)
            .finalize()
            .as_array()
    }

    fn sequential(lane: usize, out_len: usize, key: &[u8], input: &[u8]) -> Vec<u8> {
        let mut state = initial();
        let mut first = IV;
        first[0] ^= 0x0101_0000 | (key.len() as u32) << 8 | out_len as u32;
        for (word, words) in state.iter_mut().enumerate() {
            words[lane] = first[word];
        }
        let mut data = Vec::new();
        if !key.is_empty() {
            data.extend_from_slice(key);
            data.resize(BLOCK_BYTES, 0);
        }
        data.extend_from_slice(input);
        let count = data.len().div_ceil(BLOCK_BYTES).max(1);
        for index in 0..count {
            let block = &data[(index * BLOCK_BYTES).min(data.len())..][..];
            let block = &block[..block.len().min(BLOCK_BYTES)];
            let mut blocks = [0; LANES * BLOCK_BYTES];
            blocks[lane * BLOCK_BYTES..][..block.len()].copy_from_slice(block);
            let mut counters = [0; LANES];
            counters[lane] = (index * BLOCK_BYTES + block.len()) as u64;
            compress(
                &mut state,
                &blocks,
                counters,
                index == count - 1,
                [false; LANES],
            );
        }
        digest(&state, lane)[..out_len].to_vec()
    }

    #[test]
    fn rfc_7693_appendix_b_abc() {
        for lane in 0..LANES {
            assert_eq!(
                sequential(lane, 32, b"", b"abc"),
                [
                    0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E,
                    0xEB, 0x45, 0x2F, 0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99,
                    0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
                ],
                "lane {lane}"
            );
        }
    }

    #[test]
    fn rfc_7693_appendix_e_self_test() {
        fn selftest_seq(len: usize, seed: u32) -> Vec<u8> {
            let (mut a, mut b) = (0xDEAD_4BADu32.wrapping_mul(seed), 1u32);
            (0..len)
                .map(|_| {
                    let t = a.wrapping_add(b);
                    a = b;
                    b = t;
                    (t >> 24) as u8
                })
                .collect()
        }
        let mut digests = Vec::new();
        let mut job = 0;
        for out_len in [16, 20, 28, 32] {
            for in_len in [0, 3, 64, 65, 255, 1024] {
                let input = selftest_seq(in_len, in_len as u32);
                let key = selftest_seq(out_len, out_len as u32);
                for key in [&[][..], &key] {
                    digests.extend(sequential(job % LANES, out_len, key, &input));
                    job += 1;
                }
            }
        }
        assert_eq!(
            sequential(0, 32, b"", &digests),
            [
                0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD, 0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45,
                0x1C, 0xEC, 0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87, 0xFB, 0xDC, 0x88, 0x79,
                0x7F, 0x4C, 0x1D, 0xFE,
            ]
        );
    }

    #[test]
    fn lanes_hash_independent_messages_with_their_own_counters_and_flags() {
        let mut random = 0x9E37_79B9u32;
        let data: Vec<u8> = (0..2 * LANES * BLOCK_BYTES)
            .map(|_| {
                random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (random >> 24) as u8
            })
            .collect();
        let last_node = [false, true, false, true, true, false, false, true];
        // One final block per lane.
        let one_block = [0, 1, 33, 64, 2, 63, 31, 16];
        // A full block, then a final block.
        let two_blocks = [1, 17, 63, 64, 64, 3, 32, 48];

        let mut state = initial();
        let mut blocks = [0; LANES * BLOCK_BYTES];
        for (lane, &len) in one_block.iter().enumerate() {
            blocks[lane * BLOCK_BYTES..][..len].copy_from_slice(&data[lane * BLOCK_BYTES..][..len]);
        }
        compress(
            &mut state,
            &blocks,
            one_block.map(|len| len as u64),
            true,
            last_node,
        );
        for (lane, &len) in one_block.iter().enumerate() {
            let message = &data[lane * BLOCK_BYTES..][..len];
            assert_eq!(
                digest(&state, lane),
                expected(message, last_node[lane]),
                "lane {lane}"
            );
        }

        let mut state = initial();
        let first: &[u8; LANES * BLOCK_BYTES] = data[..LANES * BLOCK_BYTES].try_into().unwrap();
        compress(
            &mut state,
            first,
            [BLOCK_BYTES as u64; LANES],
            false,
            [false; LANES],
        );
        let mut blocks = [0; LANES * BLOCK_BYTES];
        for (lane, &len) in two_blocks.iter().enumerate() {
            let start = LANES * BLOCK_BYTES + lane * BLOCK_BYTES;
            blocks[lane * BLOCK_BYTES..][..len].copy_from_slice(&data[start..][..len]);
        }
        compress(
            &mut state,
            &blocks,
            two_blocks.map(|len| (BLOCK_BYTES + len) as u64),
            true,
            last_node,
        );
        for (lane, &len) in two_blocks.iter().enumerate() {
            let mut message = data[lane * BLOCK_BYTES..][..BLOCK_BYTES].to_vec();
            message.extend_from_slice(&data[LANES * BLOCK_BYTES + lane * BLOCK_BYTES..][..len]);
            assert_eq!(
                digest(&state, lane),
                expected(&message, last_node[lane]),
                "lane {lane}"
            );
        }
    }
}
