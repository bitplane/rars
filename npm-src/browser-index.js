import { createApi } from "./api.js";
import { createClient } from "./client.js";

const workerModule = new URL("./worker.js", import.meta.url);

function spawnWorker() {
  if (typeof location !== "undefined" && workerModule.origin !== location.origin) {
    const bootstrap = new Blob([`import ${JSON.stringify(workerModule.href)};`], {
      type: "text/javascript",
    });
    const url = URL.createObjectURL(bootstrap);
    const worker = new Worker(url, { type: "module", name: "rars" });
    return wrapWorker(worker);
  }
  const worker = new Worker(new URL("./worker.js", import.meta.url), {
    type: "module",
    name: "rars",
  });
  return wrapWorker(worker);
}

function wrapWorker(worker) {
  return {
    post: (message) => worker.postMessage(message),
    onMessage: (callback) => worker.addEventListener("message", (event) => callback(event.data)),
    onError: (callback) => worker.addEventListener("error", callback),
    terminate: () => worker.terminate(),
  };
}

function binaryBlob(value) {
  if (value instanceof Blob) return value;
  if (value instanceof ArrayBuffer) return new Blob([value.slice(0)]);
  if (ArrayBuffer.isView(value)) {
    return new Blob([value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)]);
  }
  throw new TypeError("archive input must be a Blob, ArrayBuffer, or typed array");
}

const runtime = Object.assign(createClient(spawnWorker), {
  version: "__RARS_VERSION__",
  async prepareArchiveSources(input) {
    const inputs = Array.isArray(input) ? input : [input];
    if (inputs.length === 0) throw new TypeError("a volume set must not be empty");
    return inputs.map(binaryBlob);
  },
  prepareEntryData(data) {
    return typeof data === "string" ? data : binaryBlob(data);
  },
  prepareOutputPath() {
    throw new TypeError("filesystem output is only available in Node");
  },
});

export const {
  RarArchive, RarEntry, RarError, RarWriter, repair, formats, version,
} = createApi(runtime);
