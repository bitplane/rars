//! Deterministic test data.
//!
//! A test whose expected bytes, sizes or fingerprints depend on its generator
//! keeps that generator to itself, so a change here cannot move a pinned value.

#![allow(dead_code)]

/// xorshift32 bytes: incompressible, and the same for the same `state`, which
/// must not be zero.
pub fn xorshift(len: usize, mut state: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// [`xorshift`] from a hashed `seed`, so neighbouring seeds, zero among them,
/// give unrelated bytes.
pub fn noise(seed: u32, len: usize) -> Vec<u8> {
    xorshift(len, seed.wrapping_mul(2_654_435_761) | 1)
}

/// [`xorshift`] bytes at even offsets and `text` at odd ones, so the data
/// compresses to about half and a compressed member still spans volumes.
pub fn half_noise(len: usize, mut state: u32, text: &[u8]) -> Vec<u8> {
    (0..len)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            if index % 2 == 0 {
                state as u8
            } else {
                text[index % text.len()]
            }
        })
        .collect()
}

/// The top byte of each step of the Numerical Recipes LCG.
pub fn lcg(len: usize, mut state: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}
