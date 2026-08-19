import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { createApi } from "./api.js";
import { createClient } from "./client.js";

function spawnWorker() {
  const worker = new Worker(new URL("./worker.cjs", import.meta.url), { name: "rars" });
  return {
    post(message) { worker.ref(); worker.postMessage(message); },
    onMessage(callback) {
      worker.on("message", (message) => {
        callback(message);
        if (!message.progress) worker.unref();
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

async function discoverVolumes(source) {
  if (source?.kind !== "path") return [source];
  const parsed = path.parse(source.path);
  const lower = parsed.base.toLowerCase();
  let pattern;
  let order;
  const part = /^(.*)\.part(\d+)\.rar$/i.exec(parsed.base);
  if (part) {
    pattern = new RegExp(`^${part[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.part(\\d+)\\.rar$`, "i");
    order = (match) => Number(match[1]);
  } else if (/\.(rar|r\d\d)$/i.test(lower)) {
    const stem = lower.endsWith(".rar") ? parsed.name : parsed.base.slice(0, -4);
    pattern = new RegExp(`^${stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.(rar|r(\\d\d))$`, "i");
    order = (match) => match[1].toLowerCase() === "rar" ? 0 : Number(match[2]) + 1;
  } else {
    return [source];
  }
  let names;
  try { names = await readdir(parsed.dir || "."); } catch { return [source]; }
  const matches = names.flatMap((name) => {
    const match = pattern.exec(name);
    return match ? [{ name, order: order(match) }] : [];
  }).sort((left, right) => left.order - right.order);
  return matches.length > 1
    ? matches.map(({ name }) => ({ kind: "path", path: path.join(parsed.dir, name) }))
    : [source];
}

const runtime = Object.assign(createClient(spawnWorker), {
  version: "__RARS_VERSION__",
  async prepareArchiveSources(input) {
    const inputs = Array.isArray(input) ? input : [input];
    if (inputs.length === 0) throw new TypeError("a volume set must not be empty");
    const sources = inputs.map(archiveSource);
    return inputs.length === 1 ? discoverVolumes(sources[0]) : sources;
  },
  prepareEntryData(data) {
    if (data?.kind === "file") return data;
    return typeof data === "string" ? data : binaryBlob(data);
  },
  prepareFile(path) { return { kind: "file", path: pathValue(path) }; },
  prepareOutputPath: pathValue,
});

export const {
  RarArchive, RarEntry, RarError, RarWriter, repair, repairDetailed, formats, version,
} = createApi(runtime);
