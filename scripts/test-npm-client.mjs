// Deterministic cancellation and worker lifetime tests, without codec timing.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { getEventListeners } from "node:events";

const source = await readFile(new URL("../npm-src/client.js", import.meta.url));
const { createClient } = await import(`data:text/javascript;base64,${source.toString("base64")}`);
const aborted = (error) => error.name === "AbortError";
const detached = (controller) => assert.equal(getEventListeners(controller.signal, "abort").length, 0);

function fakeWorker() {
  return {
      posts: [], terminations: 0,
      onMessage(callback) { this.message = callback; },
      onError(callback) { this.error = callback; },
      post(message) { this.posts.push(message); },
      terminate() { this.terminations += 1; },
      complete(result) { this.message({ id: this.posts.at(-1).id, result }); },
      progress() { this.message({ id: this.posts.at(-1).id, progress: { phase: "running" } }); },
  };
}

function harness() {
  const workers = [];
  const client = createClient(() => {
    const current = fakeWorker();
    workers.push(current);
    return current;
  });
  return { client, workers };
}

{
  const { client, workers } = harness();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client.request("test", {}, { signal: controller.signal }), aborted);
  assert.equal(workers.length, 0);
  detached(controller);
}

{
  const { client, workers } = harness();
  const activeController = new AbortController();
  const queuedController = new AbortController();
  const first = client.request("test", {}, { signal: activeController.signal });
  const queued = client.request("read", {}, { signal: queuedController.signal });
  const rejection = assert.rejects(queued, aborted);
  queuedController.abort();
  // No completion or cancellation of the active request is needed.
  await rejection;
  detached(queuedController);
  assert.equal(workers[0].terminations, 0);
  assert.equal(workers[0].posts.length, 1);
  workers[0].complete("first");
  assert.equal(await first, "first");
  detached(activeController);
}

{
  const { client, workers } = harness();
  const controller = new AbortController();
  const first = client.request("test", {}, { signal: controller.signal });
  const rejection = assert.rejects(first, aborted);
  const second = client.request("read", {});
  controller.abort();
  await rejection;
  detached(controller);
  assert.equal(workers.length, 2);
  assert.equal(workers[0].terminations, 1);
  workers[0].error(new Error("late error from terminated worker"));
  workers[0].complete("late result");
  assert.equal(workers[1].terminations, 0);
  workers[1].complete("second");
  assert.equal(await second, "second");
}

for (const failure of ["worker", "progress", "abort-in-progress"]) {
  const { client, workers } = harness();
  const controller = new AbortController();
  const original = new Error("callback failed");
  const first = client.request("test", {}, {
    signal: controller.signal,
    onProgress() {
      if (failure === "abort-in-progress") controller.abort();
      throw original;
    },
  });
  const rejection = assert.rejects(first, (error) => failure === "worker"
    ? error.code === "WORKER_FAILED"
    : failure === "progress" ? error === original : aborted(error));
  const second = client.request("read", {});
  if (failure === "worker") workers[0].error(new Error("worker crashed"));
  else workers[0].progress();
  await rejection;
  detached(controller);
  assert.equal(workers[0].terminations, 1);
  assert.equal(workers[1].terminations, 0);
  workers[1].complete("recovered");
  assert.equal(await second, "recovered");
}

for (const failure of ["spawn", "post"]) {
  const replacement = fakeWorker();
  let first = true;
  const client = createClient(() => {
    if (first) {
      first = false;
      if (failure === "spawn") throw new Error("spawn failed");
      return { onMessage() {}, onError() {}, terminate() {}, post() { throw new Error("post failed"); } };
    }
    return replacement;
  });
  const controller = new AbortController();
  await assert.rejects(client.request("test", {}, { signal: controller.signal }),
    (error) => error.code === "WORKER_FAILED");
  detached(controller);
  const next = client.request("test", {});
  replacement.complete("recovered");
  assert.equal(await next, "recovered");
}

console.log("npm queued/active cancellation and worker recovery checks passed");
