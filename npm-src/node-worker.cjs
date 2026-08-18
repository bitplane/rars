const { parentPort } = require("node:worker_threads");
const fs = require("node:fs/promises");
const path = require("node:path");
const wasm = require("./wasm/rars_wasm.js");
const { startWorker } = require("./worker-engine.cjs");

function volumePath(firstPath, index, total, format) {
  if (format === "rar50" || format === "rar70") {
    const parsed = path.parse(firstPath);
    const stem = parsed.name.replace(/\.part\d+$/i, "");
    const width = Math.max(2, String(total).length);
    return path.join(parsed.dir, `${stem}.part${String(index + 1).padStart(width, "0")}.rar`);
  }
  if (index === 0) return firstPath;
  return firstPath.replace(/\.[^.]*$/, `.r${String(index - 1).padStart(2, "0")}`);
}

async function writeAtomic(target, bytes) {
  const temporary = `${target}.rars-${process.pid}-${Date.now()}.tmp`;
  try {
    await fs.writeFile(temporary, bytes);
    await fs.rename(temporary, target);
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

startWorker({
  onMessage(callback) { parentPort.on("message", callback); },
  post(message, transfers = []) { parentPort.postMessage(message, transfers); },
}, wasm, {
  readFile: async (file) => new Uint8Array(await fs.readFile(file)),
  writeAtomic,
  async writeVolumes(firstPath, parts, format) {
    const paths = parts.map((_, index) => volumePath(firstPath, index, parts.length, format));
    await Promise.all(parts.map((part, index) => writeAtomic(paths[index], part)));
    return paths;
  },
});
