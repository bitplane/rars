export function createClient(spawnWorker) {
  let worker;
  let sequence = 0;
  let active;
  let idleTimer;
  const queue = [];
  let errorFactory = (error) => error;

  function stopWorker() {
    const stopped = worker;
    worker = undefined;
    stopped?.terminate();
  }

  function detach(task) {
    if (task.signal && task.abort) task.signal.removeEventListener("abort", task.abort);
  }

  function ensureWorker() {
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
      idleTimer = undefined;
    }
    if (worker) return worker;
    const current = spawnWorker();
    worker = current;
    current.onMessage((message) => {
      if (worker === current) handleMessage(message);
    });
    current.onError((error) => {
      if (worker !== current) return;
      const failed = active;
      stopWorker();
      if (failed) finish(failed, () => failed.reject(errorFactory({ code: "WORKER_FAILED", message: error.message })));
    });
    return worker;
  }

  function finish(task, callback) {
    detach(task);
    active = undefined;
    callback();
    runNext();
    if (!active && queue.length === 0 && worker) {
      idleTimer = setTimeout(() => {
        stopWorker();
        idleTimer = undefined;
      }, 30_000);
      idleTimer.unref?.();
    }
  }

  function handleMessage(message) {
    if (!active || message.id !== active.id) return;
    const task = active;
    if (message.progress) {
      try {
        task.onProgress?.(message.progress);
      } catch (error) {
        if (active === task) {
          stopWorker();
          finish(task, () => task.reject(error));
        }
      }
      return;
    }
    if (message.error) {
      finish(task, () => task.reject(errorFactory(message.error)));
    } else {
      finish(task, () => task.resolve(message.result));
    }
  }

  function abortTask(task) {
    const abortError = new DOMException("The operation was aborted", "AbortError");
    if (active === task) {
      stopWorker();
      finish(task, () => task.reject(abortError));
      return;
    }
    const index = queue.indexOf(task);
    if (index >= 0) queue.splice(index, 1);
    detach(task);
    task.reject(abortError);
  }

  function runNext() {
    while (!active && queue.length > 0) {
      const task = queue.shift();
      active = task;
      try {
        ensureWorker().post({ id: task.id, operation: task.operation, payload: task.payload });
      } catch (error) {
        if (active !== task) continue;
        stopWorker();
        detach(task);
        active = undefined;
        task.reject(errorFactory({ code: "WORKER_FAILED", message: error.message }));
      }
    }
  }

  return {
    setErrorFactory(factory) { errorFactory = factory; },
    request(operation, payload, options = {}) {
      return new Promise((resolve, reject) => {
        const task = {
          id: ++sequence,
          operation,
          payload,
          resolve,
          reject,
          signal: options.signal,
          onProgress: options.onProgress,
        };
        if (task.signal?.aborted) {
          reject(new DOMException("The operation was aborted", "AbortError"));
          return;
        }
        task.abort = () => abortTask(task);
        task.signal?.addEventListener("abort", task.abort, { once: true });
        queue.push(task);
        runNext();
      });
    },
  };
}
