export function createClient(spawnWorker) {
  let worker;
  let sequence = 0;
  let active;
  let idleTimer;
  const queue = [];
  let errorFactory = (error) => error;

  function ensureWorker() {
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
      idleTimer = undefined;
    }
    if (worker) return worker;
    worker = spawnWorker();
    worker.onMessage(handleMessage);
    worker.onError((error) => {
      const failed = active;
      active = undefined;
      worker?.terminate();
      worker = undefined;
      if (failed) failed.reject(errorFactory({ code: "WORKER_FAILED", message: error.message }));
      runNext();
    });
    return worker;
  }

  function finish(task, callback) {
    if (task.signal && task.abort) task.signal.removeEventListener("abort", task.abort);
    active = undefined;
    callback();
    runNext();
    if (!active && queue.length === 0 && worker) {
      idleTimer = setTimeout(() => {
        worker?.terminate();
        worker = undefined;
        idleTimer = undefined;
      }, 30_000);
      idleTimer.unref?.();
    }
  }

  function handleMessage(message) {
    if (!active || message.id !== active.id) return;
    if (message.progress) {
      try {
        active.onProgress?.(message.progress);
      } catch (error) {
        const task = active;
        worker.terminate();
        worker = undefined;
        finish(task, () => task.reject(error));
      }
      return;
    }
    const task = active;
    if (message.error) {
      finish(task, () => task.reject(errorFactory(message.error)));
    } else {
      finish(task, () => task.resolve(message.result));
    }
  }

  function abortTask(task) {
    const abortError = new DOMException("The operation was aborted", "AbortError");
    if (active === task) {
      worker.terminate();
      worker = undefined;
      finish(task, () => task.reject(abortError));
      return;
    }
    const index = queue.indexOf(task);
    if (index >= 0) queue.splice(index, 1);
    task.reject(abortError);
  }

  function runNext() {
    if (active || queue.length === 0) return;
    active = queue.shift();
    if (active.signal?.aborted) {
      const task = active;
      active = undefined;
      task.reject(new DOMException("The operation was aborted", "AbortError"));
      runNext();
      return;
    }
    active.abort = () => abortTask(active);
    active.signal?.addEventListener("abort", active.abort, { once: true });
    ensureWorker().post({ id: active.id, operation: active.operation, payload: active.payload });
  }

  return {
    setErrorFactory(factory) { errorFactory = factory; },
    request(operation, payload, options = {}) {
      return new Promise((resolve, reject) => {
        queue.push({
          id: ++sequence,
          operation,
          payload,
          resolve,
          reject,
          signal: options.signal,
          onProgress: options.onProgress,
        });
        runNext();
      });
    },
  };
}
