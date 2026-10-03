use crate::cli::ProgressMode;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rars::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
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
    last_percent: u8,
}

pub(crate) struct CliProgress {
    mode: RenderMode,
    bar: ProgressBar,
    plain: Arc<(Mutex<PlainState>, Condvar)>,
    heartbeat: Option<JoinHandle<()>>,
    determinate: AtomicBool,
    emitting: AtomicBool,
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
            Some(std::thread::spawn(move || {
                heartbeat_loop(state, LOG_INTERVAL, report_heartbeat);
            }))
        } else {
            None
        };
        Self {
            mode,
            bar,
            plain,
            heartbeat,
            determinate: AtomicBool::new(false),
            emitting: AtomicBool::new(false),
        }
    }

    pub(crate) fn spinner(&self, message: impl Into<String>) {
        let message = message.into();
        self.set_plain_state(true, &message);
        self.determinate.store(false, Ordering::Relaxed);
        self.reset_plain_percent();
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
        self.determinate.store(true, Ordering::Relaxed);
        self.reset_plain_percent();
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

    fn work_bar(&self, message: String, total: u64) {
        self.set_plain_state(true, &message);
        self.determinate.store(true, Ordering::Relaxed);
        self.reset_plain_percent();
        self.bar.reset();
        self.bar.disable_steady_tick();
        self.bar.set_length(total);
        self.bar.set_position(0);
        self.bar.reset_elapsed();
        self.bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:32.cyan/blue} {percent:>3}% ETA {eta} {wide_msg}",
            )
            .expect("valid compression progress bar template")
            .progress_chars("=>-"),
        );
        self.bar.set_message(message);
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

    fn reset_plain_percent(&self) {
        let (lock, _) = &*self.plain;
        lock.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last_percent = 0;
    }

    fn report_plain_percent(&self, completed: u64, total: u64) {
        if total == 0 || !matches!(self.mode, RenderMode::Milestones | RenderMode::Periodic) {
            return;
        }
        // Multiplication in u64 can saturate before division and under-report
        // valid large counters, even when completed == total.
        let percent = (u128::from(completed) * 100 / u128::from(total)).min(100) as u8;
        let step = if self.mode == RenderMode::Periodic {
            10
        } else {
            25
        };
        let threshold = percent / step * step;
        let (lock, _) = &*self.plain;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if threshold > state.last_percent {
            state.last_percent = threshold;
            eprintln!("progress: {threshold}% {}", state.message);
        }
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
                if operation == WriteOperation::Emission {
                    self.emitting.store(true, Ordering::Relaxed);
                }
                let label = operation_label(operation, pass);
                let _ = (total_bytes, total_entries);
                self.spinner(label);
            }
            WriteProgressEvent::EntryStarted {
                operation, name, ..
            } => {
                self.set_message(format!(
                    "{}: {}",
                    operation_label(operation, 1),
                    display_bytes(name)
                ));
            }
            // Advanced is the authoritative byte count; entry completion is
            // lifecycle information, not another increment of the same work.
            WriteProgressEvent::EntryFinished { .. } => {}
            WriteProgressEvent::Advanced {
                operation,
                completed_bytes,
                total_bytes,
                pass,
            } => {
                if self.mode == RenderMode::Terminal {
                    if !self.determinate.swap(true, Ordering::Relaxed) {
                        let current = self.bar.message();
                        let message = if current.is_empty() {
                            operation_label(operation, pass)
                        } else {
                            current.to_string()
                        };
                        self.work_bar(message, total_bytes);
                    }
                    self.bar.set_length(total_bytes);
                    self.bar.set_position(completed_bytes);
                } else {
                    self.report_plain_percent(completed_bytes, total_bytes);
                }
            }
            WriteProgressEvent::BytesWritten { completed_bytes } => {
                let message = format!("Writing: {completed_bytes} bytes");
                if self.mode == RenderMode::Terminal
                    && (self.determinate.load(Ordering::Relaxed) || self.bar.is_finished())
                {
                    self.spinner(message);
                } else {
                    self.set_message(message);
                }
            }
            WriteProgressEvent::OperationFinished {
                operation, pass, ..
            } => {
                self.finish(format!("{} complete", operation_label(operation, pass)));
                if operation == WriteOperation::Emission {
                    self.emitting.store(false, Ordering::Relaxed);
                } else if operation == WriteOperation::Recovery
                    && self.emitting.load(Ordering::Relaxed)
                {
                    self.spinner(operation_label(WriteOperation::Emission, 1));
                }
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
        if let Some(handle) = self.heartbeat.take() {
            let _ = handle.join();
        }
    }
}

fn report_heartbeat(message: &str) {
    eprintln!("progress: still working: {message}");
}

fn heartbeat_loop(
    shared: Arc<(Mutex<PlainState>, Condvar)>,
    interval: Duration,
    mut report: impl FnMut(&str),
) {
    let (lock, wake) = &*shared;
    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    loop {
        let (next, timeout) = wake
            .wait_timeout(state, interval)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state = next;
        if state.stop {
            break;
        }
        if timeout.timed_out() && state.active {
            report(&state.message);
        }
    }
}

fn operation_label(operation: WriteOperation, pass: usize) -> String {
    match operation {
        WriteOperation::Staging => "Staging archive".to_string(),
        WriteOperation::Emission => "Writing archive".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_percent_is_monotonic_and_exact_at_u64_boundaries() {
        let mut progress = CliProgress::new(ProgressMode::Never);
        progress.mode = RenderMode::Milestones;
        progress.bar("work", 100);
        for (completed, total, expected) in [
            (0, 0, 0),
            (24, 100, 0),
            (25, 100, 25),
            (90, 100, 75),
            (40, 100, 75),
            (u64::MAX, u64::MAX, 100),
        ] {
            progress.report_plain_percent(completed, total);
            assert_eq!(progress.plain.0.lock().unwrap().last_percent, expected);
        }
        progress.mode = RenderMode::Periodic;
        progress.bar("next", 100);
        progress.report_plain_percent(19, 100);
        assert_eq!(progress.plain.0.lock().unwrap().last_percent, 10);
        progress.report_plain_percent(u64::MAX, 1);
        assert_eq!(progress.plain.0.lock().unwrap().last_percent, 100);
    }

    #[test]
    fn terminal_restart_and_entry_events_preserve_work_accounting() {
        let mut progress = CliProgress::new(ProgressMode::Never);
        progress.mode = RenderMode::Terminal;
        progress.bar("reading", 100);
        progress.advance(30);
        assert_eq!(progress.bar.position(), 30);
        progress.set_message("source");
        assert_eq!(progress.bar.message(), "source");
        progress.finish("done");
        assert!(progress.bar.is_finished());
        progress.spinner("next phase");
        assert!(!progress.bar.is_finished());
        assert_eq!(progress.bar.position(), 0);
        progress.report(WriteProgressEvent::Advanced {
            operation: WriteOperation::Recovery,
            completed_bytes: 50,
            total_bytes: 100,
            pass: 2,
        });
        assert_eq!(progress.bar.message(), "next phase");
        assert_eq!(progress.bar.position(), 50);
        progress.report(WriteProgressEvent::EntryStarted {
            operation: WriteOperation::Compression,
            index: 0,
            total_entries: 1,
            name: b"name\x1b",
            input_bytes: 50,
        });
        assert!(progress.bar.message().contains("name\\u{1b}"));
        progress.report(WriteProgressEvent::VolumeFinished {
            volume_number: 1,
            total_volumes: Some(1),
            bytes: 999,
        });
        assert_eq!(progress.bar.position(), 50);
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Emission,
            total_bytes: Some(100),
            total_entries: Some(1),
            pass: 1,
        });
        assert!(!progress.emitting.load(Ordering::Relaxed));
        assert_eq!(
            operation_label(WriteOperation::Staging, 1),
            "Staging archive"
        );
        assert_eq!(
            operation_label(WriteOperation::Recovery, 2),
            "Building recovery record (pass 2)"
        );
    }

    #[test]
    fn heartbeat_reports_only_active_work_and_stops_after_notification() {
        let shared = Arc::new((Mutex::new(PlainState::default()), Condvar::new()));
        let (sender, receiver) = std::sync::mpsc::channel();
        let state = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            heartbeat_loop(state, Duration::from_millis(5), |message| {
                sender.send(message.to_owned()).unwrap();
            })
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        {
            let mut state = shared.0.lock().unwrap();
            state.active = true;
            state.message = "busy".into();
            shared.1.notify_all();
        }
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            "busy"
        );
        {
            let mut state = shared.0.lock().unwrap();
            state.active = false;
            shared.1.notify_all();
        }
        while receiver.try_recv().is_ok() {}
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        shared.0.lock().unwrap().stop = true;
        shared.1.notify_all();
        handle.join().unwrap();
    }

    #[test]
    fn plain_state_survives_poisoned_locks_during_updates_and_drop() {
        let mut progress = CliProgress::new(ProgressMode::Never);
        let shared = Arc::clone(&progress.plain);
        assert!(std::thread::spawn(move || {
            let _guard = shared.0.lock().unwrap();
            panic!("simulate failure while holding progress state");
        })
        .join()
        .is_err());
        progress.set_message("recovered");
        progress.spinner("another phase");
        progress.mode = RenderMode::Milestones;
        progress.report_plain_percent(100, 100);
        progress.finish("done");
        assert!(progress.plain.0.is_poisoned());
        let state = progress
            .plain
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.message, "done");
        assert!(!state.active);
        assert_eq!(state.last_percent, 100);
        drop(state);
        drop(progress);
    }

    #[test]
    fn heartbeat_recovers_state_after_a_reporting_panic() {
        let shared = Arc::new((
            Mutex::new(PlainState {
                active: true,
                message: "busy".into(),
                ..Default::default()
            }),
            Condvar::new(),
        ));
        let first = Arc::clone(&shared);
        assert!(std::thread::spawn(move || heartbeat_loop(
            first,
            Duration::from_millis(1),
            |_| panic!("simulate failed reporting")
        ))
        .join()
        .is_err());
        assert!(shared.0.is_poisoned());
        let (sender, receiver) = std::sync::mpsc::channel();
        let second = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            heartbeat_loop(second, Duration::from_millis(1), |message| {
                report_heartbeat(message);
                sender.send(message.to_owned()).unwrap();
            })
        });
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            "busy"
        );
        shared
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stop = true;
        shared.1.notify_all();
        handle.join().unwrap();
    }

    #[test]
    fn hidden_progress_and_standalone_recovery_do_not_invent_emission_work() {
        let progress = CliProgress::new(ProgressMode::Never);
        progress.advance(999);
        assert_eq!(progress.bar.position(), 0);
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Recovery,
            total_bytes: None,
            total_entries: None,
            pass: 2,
        });
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            total_bytes: None,
            total_entries: None,
            pass: 2,
        });
        let state = progress.plain.0.lock().unwrap();
        assert!(!state.active);
        assert_eq!(state.message, "Building recovery record (pass 2) complete");
        assert!(!progress.emitting.load(Ordering::Relaxed));
    }

    #[test]
    fn entry_completion_does_not_add_to_absolute_progress() {
        let mut progress = CliProgress::new(ProgressMode::Never);
        // Exercise terminal accounting against a hidden draw target.
        progress.mode = RenderMode::Terminal;
        progress.report(WriteProgressEvent::Advanced {
            operation: WriteOperation::Compression,
            completed_bytes: 40,
            total_bytes: 100,
            pass: 1,
        });
        progress.report(WriteProgressEvent::EntryFinished {
            operation: WriteOperation::Compression,
            index: 0,
            total_entries: 2,
            name: b"first",
            input_bytes: 40,
        });
        assert_eq!(progress.bar.position(), 40);
        progress.report(WriteProgressEvent::Advanced {
            operation: WriteOperation::Compression,
            completed_bytes: 60,
            total_bytes: 100,
            pass: 1,
        });
        assert_eq!(progress.bar.position(), 60);
    }

    #[test]
    fn recovery_completion_resumes_the_emission_phase() {
        let progress = CliProgress::new(ProgressMode::Never);
        for operation in [WriteOperation::Emission, WriteOperation::Recovery] {
            progress.report(WriteProgressEvent::OperationStarted {
                operation,
                total_bytes: None,
                total_entries: None,
                pass: 1,
            });
        }
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            total_bytes: None,
            total_entries: None,
            pass: 1,
        });
        let state = progress.plain.0.lock().unwrap();
        assert!(state.active);
        assert_eq!(state.message, "Writing archive");
    }
}
