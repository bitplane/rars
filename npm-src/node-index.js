import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createApi } from "./api.js";
import { createClient } from "./client.js";

function spawnWorker() {
  const worker = new Worker(new URL("./worker.cjs", import.meta.url), { name: "rars" });
  return {
    post(message) { worker.ref(); worker.postMessage(message); },
    onMessage(callback) {
      worker.on("message", (message) => {
        // The callback can start and ref the next queued operation.
        if (!message.progress) worker.unref();
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
});

export const {
  RarArchive, RarEntry, RarError, RarWriter, repair, isRarFile, isRarFileSfx, checkPassword, archiveVersions, version,
} = createApi(runtime);
