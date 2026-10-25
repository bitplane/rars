use super::*;
use crate::codec::workspace::RefusingBudget;

const CHUNK: usize = 64 * 1024;

struct Sink<F>(F);
impl<F: FnMut(&[u8]) -> std::io::Result<usize>> Write for Sink<F> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn full_literal_chunks_reuse_their_allocation() {
    let data: Vec<_> = (0..2 * CHUNK + 7).map(|i| (i * 73) as u8).collect();
    let packed = Unpack15Encoder::new().encode_literals_only(&data).unwrap();
    let budget = RefusingBudget::new(usize::MAX);
    let mut decoder = Reader15State::with_allowance(&budget).unwrap();
    let mut output = Vec::new();
    let mut attempts = Vec::new();
    let mut charges = Vec::new();
    let mut lengths = Vec::new();
    decoder
        .decode_member_from_reader(
            &mut packed.as_slice(),
            data.len(),
            false,
            &mut Sink(|bytes: &[u8]| {
                attempts.push(budget.attempts());
                charges.push(budget.used());
                lengths.push(bytes.len());
                output.extend_from_slice(bytes);
                Ok(bytes.len())
            }),
        )
        .unwrap();
    assert_eq!(output, data);
    assert_eq!(lengths, [CHUNK, CHUNK, 7]);
    assert_eq!(
        attempts[1], attempts[0],
        "second full chunk must reuse the buffer"
    );
    assert_eq!(charges[0], charges[1]);
    assert_eq!(charges[2], charges[1] - CHUNK as u64 + 7);
    drop(decoder);
    assert_eq!(budget.used(), 0);
}

// The original loop is an oracle for chunk boundaries and bounded workspace.
fn old_stream<B: Budget>(
    decoder: &mut Reader15State<B>,
    input: &mut impl Read,
    target: usize,
    solid: bool,
    out: &mut impl Write,
) -> Result<()> {
    decoder.read_control.check_codec()?;
    let control = decoder.read_control.clone();
    let input = &mut control.reader(input);
    decoder.init_member(target, solid);
    decoder.bits = ReaderBits::with_allowance(&[], &decoder.window.allowance())?;
    decoder.bits.input.read_to_end(input)?;
    while decoder.output_written < decoder.target {
        let target = decoder
            .output_written
            .saturating_add(CHUNK)
            .min(decoder.target);
        let mut chunk =
            Buffer::with_capacity(target - decoder.output_written, &decoder.window.allowance())?;
        decoder.decode_loop_until(target, &mut chunk)?;
        out.write_all(&chunk).map_err(Error::from)?;
    }
    Ok(())
}

fn stream<B: Budget>(
    old: bool,
    decoder: &mut Reader15State<B>,
    input: &mut impl Read,
    target: usize,
    solid: bool,
    out: &mut impl Write,
) -> Result<()> {
    if old {
        old_stream(decoder, input, target, solid, out)
    } else {
        decoder.decode_member_from_reader(input, target, solid, out)
    }
}

fn matches_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let data: Vec<_> = b"legacy streaming match history "
        .iter()
        .copied()
        .cycle()
        .take(2 * CHUNK + 1024)
        .collect();
    let next = data[137..4234].to_vec();
    let mut encoder = Unpack15Encoder::with_options(EncodeOptions::new().with_lazy_matching(false));
    let packed = encoder.encode_member(&data).unwrap();
    let packed_next = encoder.encode_member(&next).unwrap();
    (data, packed, next, packed_next)
}

#[test]
fn reused_chunks_preserve_match_overshoot_and_solid_continuations() {
    fn check<B: Budget>(budget: &B, members: &[(&[u8], &[u8])]) {
        let mut reference = Reader15State::with_allowance(budget).unwrap();
        let mut decoder = Reader15State::with_allowance(budget).unwrap();
        for (index, &(data, packed)) in members.iter().enumerate() {
            let mut traces = Vec::new();
            for (old, state) in [(true, &mut reference), (false, &mut decoder)] {
                let mut output = Vec::new();
                let mut lengths = Vec::new();
                let mut input = packed;
                stream(
                    old,
                    state,
                    &mut input,
                    data.len(),
                    index != 0,
                    &mut Sink(|bytes: &[u8]| {
                        lengths.push(bytes.len());
                        output.extend_from_slice(bytes);
                        Ok(bytes.len())
                    }),
                )
                .unwrap();
                assert_eq!(output, data);
                if index == 0 {
                    assert!(
                        lengths.iter().any(|&len| len > CHUNK),
                        "fixture must cross a chunk boundary within a match"
                    );
                    assert!(*lengths.last().unwrap() < CHUNK / 2);
                }
                traces.push(lengths);
            }
            assert_eq!(traces[0], traces[1]);
            assert_eq!(reference.bits.bit_pos, decoder.bits.bit_pos);
            assert_eq!(reference.window, decoder.window);
            assert_eq!(reference.output_written, decoder.output_written);
        }
    }
    let (data, packed, next, packed_next) = matches_fixture();
    let members = [
        (data.as_slice(), packed.as_slice()),
        (next.as_slice(), packed_next.as_slice()),
    ];
    check(&Allowance::default(), &members);
    let budget = Allowance::limited(1024 * 1024);
    check(&budget, &members);
    assert_eq!(budget.used(), 0);
}

#[test]
fn reused_chunks_preserve_minimum_workspace_and_release_before_resizing() {
    let (data, packed, _, _) = matches_fixture();
    let mut minima = Vec::new();
    for old in [true, false] {
        let succeeds = |limit| {
            let budget = Allowance::limited(limit);
            let result = (|| {
                let mut decoder = Reader15State::with_allowance(&budget)?;
                stream(
                    old,
                    &mut decoder,
                    &mut packed.as_slice(),
                    data.len(),
                    false,
                    &mut std::io::sink(),
                )
            })();
            assert_eq!(budget.used(), 0);
            if let Err(error) = &result {
                assert!(matches!(error, Error::WorkspaceLimitExceeded(_)));
            }
            result.is_ok()
        };
        let (mut low, mut high) = (0, 1024 * 1024);
        assert!(succeeds(high));
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            if succeeds(mid) {
                high = mid;
            } else {
                low = mid;
            }
        }
        minima.push(high);

        // Fill the remaining quota at the penultimate callback. The final,
        // smaller chunk can be allocated only after releasing its predecessor.
        let budget = Allowance::limited(1024 * 1024);
        let mut decoder = Reader15State::with_allowance(&budget).unwrap();
        let mut held = None;
        let mut written = 0;
        stream(
            old,
            &mut decoder,
            &mut packed.as_slice(),
            data.len(),
            false,
            &mut Sink(|bytes: &[u8]| {
                assert_eq!(bytes, &data[written..written + bytes.len()]);
                written += bytes.len();
                if written < data.len() && data.len() - written < CHUNK / 2 {
                    held = Some(
                        Buffer::<u8, _>::with_capacity(
                            (1024 * 1024 - budget.used()) as usize,
                            &budget,
                        )
                        .unwrap(),
                    );
                    assert_eq!(budget.used(), 1024 * 1024);
                }
                Ok(bytes.len())
            }),
        )
        .unwrap();
        assert_eq!(written, data.len());
        assert!(held.is_some());
        drop(held);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(
        minima[1], minima[0],
        "minimum workspace must stay unchanged"
    );
}

#[test]
fn reused_chunks_release_on_each_allocation_refusal_and_sink_failure() {
    let data: Vec<_> = (0..2 * CHUNK + 7).map(|i| (i * 73) as u8).collect();
    let packed = Unpack15Encoder::new().encode_literals_only(&data).unwrap();
    let run = |budget: &RefusingBudget| -> Result<()> {
        let mut decoder = Reader15State::with_allowance(budget)?;
        decoder.decode_member_from_reader(
            &mut packed.as_slice(),
            data.len(),
            false,
            &mut std::io::sink(),
        )
    };
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    assert_eq!(baseline.used(), 0);
    for failure in 0..baseline.attempts() {
        let budget = RefusingBudget::new(failure);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation {failure}"
        );
        assert_eq!(budget.used(), 0);
    }
    for cancel in [false, true] {
        let budget = Allowance::limited(1024 * 1024);
        let mut decoder = Reader15State::with_allowance(&budget).unwrap();
        let token = crate::ReadCancellation::new();
        decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
        let mut calls = 0;
        let error = decoder
            .decode_member_from_reader(
                &mut packed.as_slice(),
                data.len(),
                false,
                &mut Sink(|bytes: &[u8]| {
                    calls += 1;
                    if cancel {
                        token.cancel();
                    } else if calls == 2 {
                        return Err(std::io::Error::other("second chunk rejected"));
                    }
                    assert_eq!(bytes, &data[(calls - 1) * CHUNK..calls * CHUNK]);
                    Ok(bytes.len())
                }),
            )
            .unwrap_err();
        if cancel {
            assert!(matches!(error, Error::Cancelled));
            assert_eq!(calls, 1);
        } else {
            assert!(matches!(error, Error::Io(_)));
            assert_eq!(calls, 2);
        }
        assert_eq!(
            budget.used(),
            decoder.window.capacity() as u64 + decoder.bits.input.capacity() as u64
        );
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn empty_target_keeps_input_errors_and_emits_nothing() {
    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("packed input failed"))
        }
    }
    let budget = RefusingBudget::new(usize::MAX);
    let mut decoder = Reader15State::with_allowance(&budget).unwrap();
    let mut sink =
        Sink(|_: &[u8]| -> std::io::Result<usize> { panic!("empty member emitted output") });
    decoder
        .decode_member_from_reader(&mut &[][..], 0, false, &mut sink)
        .unwrap();
    assert!(matches!(
        decoder.decode_member_from_reader(&mut FailedReader, 0, false, &mut sink),
        Err(Error::Io(_))
    ));
    drop(decoder);
    assert_eq!(budget.used(), 0);
}
