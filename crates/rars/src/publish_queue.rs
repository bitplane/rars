use crate::error::{Error, Result};
use std::any::Any;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

/// What a user of the queue does to put one output in place.
pub trait PublishStep: Send + 'static {
    type Job: Send + 'static;

    /// Publishes `job`, which follows every job before it.
    fn publish(&mut self, job: Self::Job) -> Result<()>;
}

struct Progress<J> {
    /// Jobs sent and not yet published.
    outstanding: usize,
    /// Failures not yet taken, in archive order.
    failures: VecDeque<Error>,
    /// A publish failed: no later one runs until [`PublishQueue::resume`].
    paused: bool,
    /// The queue is going: held jobs are dropped, not published.
    closing: bool,
    /// Jobs submitted inline while paused.
    held: VecDeque<J>,
    panicked: Option<Box<dyn Any + Send>>,
}

struct Shared<P: PublishStep> {
    state: Mutex<P>,
    progress: Mutex<Progress<P::Job>>,
    idle: Condvar,
}

impl<P: PublishStep> Shared<P> {
    fn run(&self, job: P::Job) {
        {
            let mut progress = lock(&self.progress);
            while progress.paused && !progress.closing {
                progress = self
                    .idle
                    .wait(progress)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if progress.closing && progress.paused {
                progress.outstanding -= 1;
                self.idle.notify_all();
                return;
            }
        }
        let result = {
            let mut state = lock(&self.state);
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.publish(job)))
        };
        let mut progress = lock(&self.progress);
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                progress.failures.push_back(error);
                progress.paused = true;
            }
            Err(payload) => {
                progress.panicked.get_or_insert(payload);
            }
        }
        progress.outstanding -= 1;
        self.idle.notify_all();
    }

    fn wait(&self) -> MutexGuard<'_, Progress<P::Job>> {
        let mut progress = lock(&self.progress);
        while progress.outstanding > progress.held.len() && !progress.paused {
            progress = self
                .idle
                .wait(progress)
                .unwrap_or_else(PoisonError::into_inner);
        }
        progress
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs publishes in archive order on a thread of its own where one may start.
///
/// An ordered single consumer does not fit rayon's work-stealing, so this is a
/// thread over a channel, as the RAR 5 write lane is.
pub struct PublishQueue<P: PublishStep> {
    shared: std::sync::Arc<Shared<P>>,
    threaded: bool,
    worker: Option<Worker<P>>,
}

impl<P: PublishStep> PublishQueue<P> {
    /// Publishes on the calling thread until [`Self::publish_on_thread`] says otherwise.
    pub fn new(state: P) -> Self {
        Self {
            shared: std::sync::Arc::new(Shared {
                state: Mutex::new(state),
                progress: Mutex::new(Progress {
                    outstanding: 0,
                    failures: VecDeque::new(),
                    paused: false,
                    closing: false,
                    held: VecDeque::new(),
                    panicked: None,
                }),
                idle: Condvar::new(),
            }),
            threaded: false,
            worker: None,
        }
    }

    /// Starts the thread at the first job, where the caller's cap applies, if one may start.
    pub fn publish_on_thread(&mut self, allowed: bool) {
        self.threaded = allowed;
    }

    /// The state publishing changes; never hold it across [`Self::submit`], which can lock it.
    pub fn state(&self) -> MutexGuard<'_, P> {
        lock(&self.shared.state)
    }

    /// Queues `job` after every earlier one.
    pub fn submit(&mut self, job: P::Job) {
        if self.threaded && self.worker.is_none() && crate::parallel::may_spawn() {
            self.worker = self.start();
        }
        lock(&self.shared.progress).outstanding += 1;
        let Some(jobs) = self.worker.as_ref().and_then(|worker| worker.jobs.as_ref()) else {
            self.run_inline(job);
            return;
        };
        if let Err(mpsc::SendError(job)) = jobs.send(job) {
            // Only a thread that has gone fails the send.
            self.worker = None;
            self.run_inline(job);
        }
    }

    fn run_inline(&self, job: P::Job) {
        if lock(&self.shared.progress).paused {
            lock(&self.shared.progress).held.push_back(job);
        } else {
            self.shared.run(job);
        }
    }

    /// The run goes on past the failure taken: held jobs publish. Otherwise they are dropped.
    pub fn resume(&self) {
        let mut progress = lock(&self.shared.progress);
        progress.paused = false;
        self.shared.idle.notify_all();
        while !progress.paused {
            let Some(job) = progress.held.pop_front() else {
                break;
            };
            drop(progress);
            self.shared.run(job);
            progress = lock(&self.shared.progress);
        }
    }

    fn start(&self) -> Option<Worker<P>> {
        let (jobs, queued) = mpsc::channel::<P::Job>();
        let shared = std::sync::Arc::clone(&self.shared);
        let thread = std::thread::Builder::new()
            .name("rars-publish".into())
            .spawn(move || {
                for job in queued {
                    shared.run(job);
                }
            })
            .ok()?;
        Some(Worker {
            shared: std::sync::Arc::clone(&self.shared),
            jobs: Some(jobs),
            thread: Some(thread),
        })
    }

    /// The first failure of a publish not yet taken, without waiting for any.
    pub fn take_failure(&self) -> Option<Error> {
        lock(&self.shared.progress).failures.pop_front()
    }

    /// Waits until every job submitted so far is published, or the first failure held the rest.
    pub fn wait(&self) {
        let mut progress = self.shared.wait();
        if let Some(payload) = progress.panicked.take() {
            drop(progress);
            std::panic::resume_unwind(payload);
        }
    }

    /// [`Self::wait`] for another thread; a panic is left for the queue to report.
    pub fn waiter(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = std::sync::Arc::downgrade(&self.shared);
        move || {
            if let Some(shared) = shared.upgrade() {
                drop(shared.wait());
            }
        }
    }

    /// Publishes everything queued, and returns the state with each failure not yet taken.
    pub fn finish(self) -> (P, Vec<Error>) {
        self.wait();
        let Self { shared, worker, .. } = self;
        // Joins the thread, which holds the other reference.
        drop(worker);
        let Ok(shared) = std::sync::Arc::try_unwrap(shared) else {
            unreachable!("the thread has been joined, and a waiter waits only during the run");
        };
        let failures = lock(&shared.progress).failures.drain(..).collect();
        (
            shared
                .state
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
            failures,
        )
    }
}

/// The thread, joined once its jobs are all published when the queue goes.
struct Worker<P: PublishStep> {
    shared: std::sync::Arc<Shared<P>>,
    jobs: Option<mpsc::Sender<P::Job>>,
    thread: Option<JoinHandle<()>>,
}

impl<P: PublishStep> Drop for Worker<P> {
    fn drop(&mut self) {
        drop(self.jobs.take());
        lock(&self.shared.progress).closing = true;
        self.shared.idle.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct Log {
        published: Vec<u32>,
        refuse: Vec<u32>,
        delay_first: bool,
    }

    impl PublishStep for Log {
        type Job = u32;

        fn publish(&mut self, job: u32) -> Result<()> {
            if self.delay_first && job == 0 {
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            self.published.push(job);
            if self.refuse.contains(&job) {
                return Err(Error::InvalidHeader("refused"));
            }
            Ok(())
        }
    }

    fn queue(log: Log, threads: usize) -> PublishQueue<Log> {
        let mut queue = PublishQueue::new(log);
        queue.publish_on_thread(threads > 1);
        queue
    }

    // `may_spawn` is false under a cap of one, and elsewhere only where a thread may start.
    fn capped<T>(threads: usize, run: impl FnOnce() -> T) -> T {
        let _cap = crate::parallel::ThreadCap::set(Some(threads));
        run()
    }

    #[test]
    fn publishes_in_the_order_submitted_at_any_thread_count() {
        for threads in [1, 2, 8] {
            capped(threads, || {
                let mut queue = queue(
                    Log {
                        delay_first: true,
                        ..Log::default()
                    },
                    threads,
                );
                for job in 0..50 {
                    queue.submit(job);
                }
                let (log, failures) = queue.finish();
                assert_eq!(log.published, (0..50).collect::<Vec<_>>());
                assert!(failures.is_empty());
            });
        }
    }

    #[test]
    fn after_a_failure_later_jobs_wait_for_the_user_to_resume() {
        for threads in [1, 2, 8] {
            capped(threads, || {
                let mut queue = queue(
                    Log {
                        refuse: vec![1, 3],
                        ..Log::default()
                    },
                    threads,
                );
                for job in 0..5 {
                    queue.submit(job);
                }
                queue.wait();
                assert_eq!(queue.state().published, vec![0, 1]);
                assert_eq!(queue.take_failure(), Some(Error::InvalidHeader("refused")));
                queue.resume();
                queue.wait();
                assert_eq!(queue.state().published, vec![0, 1, 2, 3]);
                assert_eq!(queue.take_failure(), Some(Error::InvalidHeader("refused")));
                queue.resume();
                let (log, failures) = queue.finish();
                assert_eq!(log.published, vec![0, 1, 2, 3, 4]);
                assert!(failures.is_empty());
            });
        }
    }

    #[test]
    fn jobs_after_a_failure_are_dropped_if_the_run_does_not_go_on() {
        for threads in [1, 2, 8] {
            capped(threads, || {
                let mut queue = queue(
                    Log {
                        refuse: vec![1],
                        ..Log::default()
                    },
                    threads,
                );
                for job in 0..5 {
                    queue.submit(job);
                }
                let (log, failures) = queue.finish();
                assert_eq!(log.published, vec![0, 1]);
                assert_eq!(failures.len(), 1);
            });
        }
    }

    #[test]
    fn dropping_the_queue_publishes_what_is_queued() {
        capped(4, || {
            let published = Arc::new(Mutex::new(Vec::new()));
            struct Slow(Arc<Mutex<Vec<u32>>>);
            impl PublishStep for Slow {
                type Job = u32;
                fn publish(&mut self, job: u32) -> Result<()> {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    self.0.lock().unwrap().push(job);
                    Ok(())
                }
            }
            let mut queue = PublishQueue::new(Slow(Arc::clone(&published)));
            queue.publish_on_thread(true);
            for job in 0..10 {
                queue.submit(job);
            }
            drop(queue);
            assert_eq!(*published.lock().unwrap(), (0..10).collect::<Vec<_>>());
        });
    }

    #[test]
    fn waiting_sees_every_earlier_publish_in_the_state() {
        capped(4, || {
            let mut queue = queue(
                Log {
                    delay_first: true,
                    ..Log::default()
                },
                4,
            );
            queue.submit(0);
            queue.submit(1);
            queue.wait();
            assert_eq!(queue.state().published, vec![0, 1]);
        });
    }

    #[test]
    fn another_thread_can_wait_for_what_is_queued() {
        capped(4, || {
            let mut queue = queue(
                Log {
                    delay_first: true,
                    ..Log::default()
                },
                4,
            );
            queue.submit(0);
            queue.submit(1);
            let waiter = queue.waiter();
            std::thread::scope(|scope| scope.spawn(waiter).join().unwrap());
            assert_eq!(queue.state().published, vec![0, 1]);
        });
    }

    #[test]
    fn runs_inline_when_it_may_not_spawn() {
        capped(1, || {
            let mut queue = queue(Log::default(), 2);
            queue.submit(7);
            // Published before `submit` returned, with no wait.
            assert_eq!(queue.state().published, vec![7]);
            assert!(queue.worker.is_none());
        });
    }
}
