//! A member's filters applied on a thread of their own, so the decoding thread
//! only hands bytes on. The thread starts at the member's first filter; it
//! takes the bytes and filter records in the order the decoder's own filter
//! stage would, so output and errors match it.
use super::{Budget, DecodedChunk, FilterStage, PendingFilter, ReaderState, StreamDecodeError};
use std::cell::RefCell;
use std::io::Read;
use std::sync::mpsc;

// Bytes handed to the filter thread at once, and how many buffers circulate.
// Tests use small pieces so filters start and end inside and across them.
#[cfg(not(any(test, fuzzing)))]
const PIECE: usize = 256 * 1024;
#[cfg(any(test, fuzzing))]
const PIECE: usize = 3_000;
const PIECES: usize = 4;
/// The buffers between the decoder and the filter thread, for the caller to charge.
pub(crate) const FILTER_THREAD_BYTES: u64 = (PIECE * PIECES) as u64;

enum Piece {
    Bytes(Vec<u8>),
    Repeated {
        byte: u8,
        len: usize,
    },
    Filter(PendingFilter),
    /// The decoder finished, so every filter must be complete.
    Done,
}

/// The filter thread stopped taking pieces, which only its failure does.
#[derive(Debug)]
struct Stopped;

/// The decoder's side, which gathers bytes so the filter thread wakes once a piece.
struct Pieces {
    buffer: Vec<u8>,
    allocated: usize,
    spare: mpsc::Receiver<Vec<u8>>,
    send: mpsc::SyncSender<Piece>,
}

impl Pieces {
    fn send(&mut self, piece: Piece) -> Result<(), Stopped> {
        self.send.send(piece).map_err(|_| Stopped)
    }

    /// Sends the bytes gathered so far, ahead of whatever follows them.
    fn flush(&mut self) -> Result<(), Stopped> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.buffer);
        self.send(Piece::Bytes(bytes))
    }

    fn push(&mut self, chunk: DecodedChunk<'_>) -> Result<(), Stopped> {
        let mut bytes = match chunk {
            DecodedChunk::Bytes(bytes) => bytes,
            DecodedChunk::Repeated { byte, len } => {
                self.flush()?;
                return self.send(Piece::Repeated { byte, len });
            }
        };
        while !bytes.is_empty() {
            if self.buffer.capacity() == 0 {
                self.buffer = match self.spare.try_recv() {
                    Ok(buffer) => buffer,
                    Err(_) if self.allocated < PIECES => {
                        self.allocated += 1;
                        Vec::with_capacity(PIECE)
                    }
                    Err(_) => self.spare.recv().map_err(|_| Stopped)?,
                };
            }
            let take = (PIECE - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == PIECE {
                self.flush()?;
            }
        }
        Ok(())
    }

    /// A filter record goes after every byte emitted before it, as the
    /// decoder's own stage would have seen them.
    fn filter(&mut self, filter: PendingFilter) -> Result<(), Stopped> {
        self.flush()?;
        self.send(Piece::Filter(filter))
    }

    fn finish(&mut self) -> Result<(), Stopped> {
        self.flush()?;
        self.send(Piece::Done)
    }
}

/// The filter thread: the decoder's filter stage, fed through a channel.
fn run_filters<B: Budget, E>(
    stage: &mut FilterStage<B>,
    pieces: mpsc::Receiver<Piece>,
    spare: mpsc::SyncSender<Vec<u8>>,
    sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
) -> std::result::Result<(), StreamDecodeError<E>> {
    for piece in pieces {
        match piece {
            Piece::Bytes(mut bytes) => {
                stage.emit(DecodedChunk::Bytes(&bytes), sink)?;
                bytes.clear();
                // The channel holds every buffer, and a stopped decoder needs none.
                let _ = spare.try_send(bytes);
            }
            Piece::Repeated { byte, len } => {
                stage.emit(DecodedChunk::Repeated { byte, len }, sink)?;
            }
            Piece::Filter(filter) => stage.hold(filter)?,
            Piece::Done => return stage.finish(),
        }
    }
    // The decoder failed, and its error is the one to report.
    Ok(())
}

/// Why the decoder's sink refused bytes.
#[derive(Debug)]
enum Halt<E> {
    Sink(E),
    Stopped,
}

type Filtering<'scope, E> =
    std::thread::ScopedJoinHandle<'scope, std::result::Result<(), StreamDecodeError<E>>>;

/// Where decoded bytes go: straight to the sink until the first filter, then
/// through the filter thread.
enum Route<'scope, S, E> {
    Direct { sink: S, emitted: usize },
    Aside(Pieces, Filtering<'scope, E>),
    Starting,
}

impl<B: Budget> ReaderState<B> {
    /// As [`Self::decode_member_from_reader_with_dictionary_to_sink`], except
    /// that from the member's first filter on, the filters are applied and
    /// `sink` called on a thread of their own.
    pub(crate) fn decode_member_filtering_aside<E: Send>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E> + Send,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let allowance = self.allowance();
        let control = self.read_control.clone();
        std::thread::scope(|scope| {
            let route = RefCell::new(Route::Direct { sink, emitted: 0 });
            let push = |chunk: DecodedChunk<'_>| match &mut *route.borrow_mut() {
                Route::Direct { sink, emitted } => {
                    *emitted += super::chunk_len(chunk);
                    sink(chunk).map_err(Halt::Sink)
                }
                Route::Aside(pieces, _) => pieces.push(chunk).map_err(|Stopped| Halt::Stopped),
                Route::Starting => unreachable!("the filter thread starts between chunks"),
            };
            let mut hand_on = |filter: PendingFilter| {
                let mut route = route.borrow_mut();
                if let Route::Direct { .. } = *route {
                    let Route::Direct { mut sink, emitted } =
                        std::mem::replace(&mut *route, Route::Starting)
                    else {
                        unreachable!("matched above")
                    };
                    let mut stage = FilterStage::new(&allowance);
                    stage.control = control.clone();
                    // The bytes before went straight to the sink.
                    stage.position = emitted;
                    let (send, pieces) = mpsc::sync_channel(PIECES);
                    let (give_back, spare) = mpsc::sync_channel(PIECES);
                    let filtering =
                        scope.spawn(move || run_filters(&mut stage, pieces, give_back, &mut sink));
                    let pieces = Pieces {
                        buffer: Vec::new(),
                        allocated: 0,
                        spare,
                        send,
                    };
                    *route = Route::Aside(pieces, filtering);
                }
                match &mut *route {
                    Route::Aside(pieces, _) => {
                        pieces.filter(filter).map_err(|Stopped| Halt::Stopped)
                    }
                    _ => unreachable!("the filter thread has started"),
                }
            };
            // The decoder refuses filters and judges the member's end itself,
            // so it stops, and leaves its state, where its own stage would.
            let decoded = self.decode_to_sink_handing_filters(
                input,
                algorithm_version,
                output_size,
                dictionary_size,
                solid,
                push,
                Some(&mut hand_on),
                true,
            );
            let decoded = match route.into_inner() {
                Route::Aside(mut pieces, filtering) => {
                    // Bytes emitted before a failure still reach the sink, as they would have.
                    let handed = match decoded {
                        Ok(()) => pieces.finish(),
                        Err(_) => pieces.flush(),
                    };
                    // Closing the channel ends the filter thread if the decoder failed.
                    drop(pieces);
                    let filtered = filtering
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                    // The filter thread only saw what the decoder emitted
                    // before any failure of its own, so its failure came first.
                    filtered?;
                    debug_assert!(handed.is_ok(), "the filter thread stops only when it fails");
                    decoded
                }
                _ => decoded,
            };
            decoded.map_err(|error| match error {
                StreamDecodeError::Decode(error) => StreamDecodeError::Decode(error),
                StreamDecodeError::FilteredMember => StreamDecodeError::FilteredMember,
                StreamDecodeError::Sink(Halt::Sink(error)) => StreamDecodeError::Sink(error),
                StreamDecodeError::Sink(Halt::Stopped) => {
                    unreachable!("the filter thread stops only when it fails")
                }
            })
        })
    }
}

#[cfg(all(test, feature = "write"))]
#[path = "filter_thread_tests.rs"]
mod tests;
