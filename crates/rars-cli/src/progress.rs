use crate::cli::ProgressMode;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rars::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::io::IsTerminal;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

const LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderMode {
    Terminal,
    Milestones,
    Periodic,
    Hidden,
}

#[derive(Default)]
struct PlainState {
    active: bool,
    stop: bool,
    message: String,
}

pub(crate) struct CliProgress {
    mode: RenderMode,
    bar: ProgressBar,
    plain: Arc<(Mutex<PlainState>, Condvar)>,
    heartbeat: Mutex<Option<JoinHandle<()>>>,
}

impl CliProgress {
    pub(crate) fn new(mode: ProgressMode) -> Self {
        let terminal = std::io::stderr().is_terminal();
        let mode = match (mode, terminal) {
            (ProgressMode::Never, _) => RenderMode::Hidden,
            (_, true) => RenderMode::Terminal,
            (ProgressMode::Always, false) => RenderMode::Periodic,
            (ProgressMode::Auto, false) => RenderMode::Milestones,
        };
        let bar = if mode == RenderMode::Terminal {
            ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(12))
        } else {
            ProgressBar::hidden()
        };
        let plain = Arc::new((Mutex::new(PlainState::default()), Condvar::new()));
        let heartbeat = if mode == RenderMode::Periodic {
            let state = Arc::clone(&plain);
            Some(std::thread::spawn(move || heartbeat_loop(state)))
        } else {
            None
        };
        Self {
            mode,
            bar,
            plain,
            heartbeat: Mutex::new(heartbeat),
        }
    }

    pub(crate) fn spinner(&self, message: impl Into<String>) {
        let message = message.into();
        self.set_plain_state(true, &message);
        match self.mode {
            RenderMode::Terminal => {
                // A previous phase may have used `finish_and_clear`, which leaves an
                // indicatif bar in a terminal state until it is fully reset.
                self.bar.reset();
                self.bar.set_length(0);
                self.bar.set_position(0);
                self.bar.reset_elapsed();
                self.bar.set_style(
                    ProgressStyle::with_template("{spinner} [{elapsed_precise}] {wide_msg}")
                        .expect("valid progress spinner template")
                        // indicatif reserves the last string for the finished state.
                        .tick_strings(&["-", "\\", "|", "/", "-"]),
                );
                self.bar.set_message(message);
                self.bar.enable_steady_tick(Duration::from_millis(120));
            }
            RenderMode::Milestones | RenderMode::Periodic => {
                eprintln!("progress: {message}");
            }
            RenderMode::Hidden => {}
        }
    }

    pub(crate) fn bar(&self, message: impl Into<String>, total: u64) {
        let message = message.into();
        self.set_plain_state(true, &message);
        if self.mode == RenderMode::Terminal {
            self.bar.reset();
            self.bar.disable_steady_tick();
            self.bar.set_length(total);
            self.bar.set_position(0);
            self.bar.reset_elapsed();
            self.bar.set_style(
                ProgressStyle::with_template(
                    "[{elapsed_precise}] {bar:32.cyan/blue} {bytes}/{total_bytes} {bytes_per_sec} ETA {eta} {wide_msg}",
                )
                .expect("valid progress bar template")
                .progress_chars("=>-"),
            );
            self.bar.set_message(message);
        } else if matches!(self.mode, RenderMode::Milestones | RenderMode::Periodic) {
            eprintln!("progress: {message}");
        }
    }

    pub(crate) fn advance(&self, bytes: u64) {
        if self.mode == RenderMode::Terminal {
            self.bar.inc(bytes);
        }
    }

    pub(crate) fn set_message(&self, message: impl Into<String>) {
        let message = message.into();
        self.set_plain_state(true, &message);
        if self.mode == RenderMode::Terminal {
            self.bar.set_message(message);
        }
    }

    pub(crate) fn finish(&self, message: impl Into<String>) {
        let message = message.into();
        self.set_plain_state(false, &message);
        match self.mode {
            RenderMode::Terminal => {
                self.bar.disable_steady_tick();
                self.bar.finish_and_clear();
            }
            RenderMode::Milestones | RenderMode::Periodic => {
                eprintln!("progress: {message}");
            }
            RenderMode::Hidden => {}
        }
    }

    fn set_plain_state(&self, active: bool, message: &str) {
        let (lock, wake) = &*self.plain;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active = active;
        state.message.clear();
        state.message.push_str(message);
        wake.notify_all();
    }
}

impl WriteProgress for CliProgress {
    fn report(&self, event: WriteProgressEvent<'_>) {
        match event {
            WriteProgressEvent::OperationStarted {
                operation,
                total_bytes,
                total_entries,
                pass,
            } => {
                let label = operation_label(operation, pass);
                let _ = (total_bytes, total_entries);
                self.spinner(label);
            }
            WriteProgressEvent::EntryStarted { name, .. } => {
                self.set_message(format!("Compressing {}", display_bytes(name)));
            }
            WriteProgressEvent::EntryFinished { input_bytes, .. } => self.advance(input_bytes),
            WriteProgressEvent::Advanced {
                completed_bytes,
                total_bytes,
                ..
            } => {
                if self.mode == RenderMode::Terminal {
                    self.bar.set_length(total_bytes);
                    self.bar.set_position(completed_bytes);
                }
            }
            WriteProgressEvent::OperationFinished {
                operation, pass, ..
            } => {
                self.finish(format!("{} complete", operation_label(operation, pass)));
            }
            _ => {}
        }
    }
}

impl Drop for CliProgress {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
        let (lock, wake) = &*self.plain;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.stop = true;
        wake.notify_all();
        drop(state);
        if let Some(handle) = self
            .heartbeat
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = handle.join();
        }
    }
}

fn heartbeat_loop(shared: Arc<(Mutex<PlainState>, Condvar)>) {
    let (lock, wake) = &*shared;
    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    loop {
        let (next, timeout) = wake
            .wait_timeout(state, LOG_INTERVAL)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state = next;
        if state.stop {
            break;
        }
        if timeout.timed_out() && state.active {
            eprintln!("progress: still working: {}", state.message);
        }
    }
}

fn operation_label(operation: WriteOperation, pass: usize) -> String {
    match operation {
        WriteOperation::Compression => "Compressing archive".to_string(),
        WriteOperation::Recovery if pass > 1 => format!("Building recovery record (pass {pass})"),
        WriteOperation::Recovery => "Building recovery record".to_string(),
        _ => "Preparing archive".to_string(),
    }
}

fn display_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for ch in String::from_utf8_lossy(bytes).chars() {
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}
