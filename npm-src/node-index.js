import { MessageChannel, Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createApi } from "./api.js";
import { createClient } from "./client.js";

function spawnWorker() {
  const worker = new Worker(new URL("./worker.cjs", import.meta.url), { name: "rars" });
  return {
    post(message, transfer = []) { worker.ref(); worker.postMessage(message, transfer); },
    onMessage(callback) {
      worker.on("message", (message) => {
        // The callback can start and ref the next queued operation; progress and
        // member reports come while the operation still runs.
        if (!message.progress && !message.memberError) worker.unref();
        callback(message);
      });
    },
    onError: (callback) => worker.on("error", callback),
    terminate: () => worker.terminate(),
  };
}

function pathValue(value) {
  if (typeof value === "string") return value;
  if (value instanceof URL && value.protocol === "file:") return fileURLToPath(value);
  throw new TypeError("path must be a string or file URL");
}

function binaryBlob(value) {
  if (value instanceof Blob) return value;
  if (value instanceof ArrayBuffer) return new Blob([value.slice(0)]);
  if (ArrayBuffer.isView(value)) {
    return new Blob([value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)]);
  }
  throw new TypeError("archive input must be a path, file URL, Blob, ArrayBuffer, or typed array");
}

function archiveSource(value) {
  return typeof value === "string" || value instanceof URL
    ? { kind: "path", path: pathValue(value) }
    : binaryBlob(value);
}

const runtime = Object.assign(createClient(spawnWorker), {
  version: "__RARS_VERSION__",
  async prepareArchiveSources(input) {
    const inputs = Array.isArray(input) ? input : [input];
    if (inputs.length === 0) throw new TypeError("a volume set must not be empty");
    return inputs.map(archiveSource);
  },
  prepareEntryData(data) {
    if (data?.kind === "file") return data;
    return typeof data === "string" ? data : binaryBlob(data);
  },
  prepareFile(path) { return { kind: "file", path: pathValue(path) }; },
  prepareOutputPath: pathValue,
  /**
   * A channel the worker pulls a set's later volumes through, from `volumes`, an
   * iterable or async iterable of paths and bytes. The worker blocks on `flag` until
   * a reply is posted; `failure` keeps what the iterator threw, to raise in its place.
   */
  volumeFeed(volumes) {
    const iterator = volumes?.[Symbol.asyncIterator]?.call(volumes) ?? volumes?.[Symbol.iterator]?.call(volumes);
    if (iterator === undefined || typeof volumes === "string") {
      throw new TypeError("volumes must be an iterable or async iterable of paths or bytes");
    }
    const { port1, port2 } = new MessageChannel();
    const flag = new Int32Array(new SharedArrayBuffer(4));
    const feed = {
      channel: { port: port2, flag },
      transfer: [port2],
      failure: undefined,
      close() {
        port1.close();
        Promise.resolve().then(() => iterator.return?.()).catch(() => {});
      },
    };
    port1.on("message", async () => {
      let reply;
      try {
        const { value, done } = await iterator.next();
        if (done) reply = { done: true };
        else if (typeof value === "string" || value instanceof URL) reply = { path: pathValue(value) };
        else reply = { bytes: new Uint8Array(await binaryBlob(value).arrayBuffer()) };
      } catch (error) {
        feed.failure = error;
        reply = { error: true };
      }
      port1.postMessage(reply);
      Atomics.store(flag, 0, 1);
      Atomics.notify(flag, 0);
    });
    return feed;
  },
});

export const {
  RarArchive, RarEntry, RarError, RarWriter, repair, isRarFile, isRarFileSfx, checkPassword, archiveVersions, version,
} = createApi(runtime);
