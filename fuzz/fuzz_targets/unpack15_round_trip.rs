#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::codec::rar13::{unpack15_decode, unpack15_encode_with_options, EncodeOptions};

const MAX_INPUT_SIZE: usize = 256 * 1024;

// Every option set the RAR 1.3 to 1.5 writers can pick, because which tokens
// the encoder emits is what decides whether the decoder stays in step, and the
// options are the only thing steering that. The bug this target exists for
// showed on exactly one of the five.
fn option_sets() -> [EncodeOptions; 5] {
    [
        EncodeOptions::new(),
        EncodeOptions::new().with_lazy_matching(false),
        EncodeOptions::new()
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false),
        EncodeOptions::new()
            .with_lazy_matching(false)
            .with_old_distance_tokens(false),
        EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024),
    ]
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }
    for options in option_sets() {
        let Ok(packed) = unpack15_encode_with_options(data, options) else {
            continue;
        };
        let decoded = unpack15_decode(&packed, data.len()).unwrap_or_else(|error| {
            panic!(
                "{options:?} encoded {} bytes a decoder rejects: {error}",
                data.len()
            )
        });
        assert_eq!(
            decoded.len(),
            data.len(),
            "{options:?} decoded to the wrong length"
        );
        let first_diff = decoded
            .iter()
            .zip(data)
            .position(|(actual, expected)| actual != expected);
        assert_eq!(first_diff, None, "{options:?} first differing byte");
    }
});
