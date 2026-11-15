const { parentPort } = require("node:worker_threads");
const fs = require("node:fs/promises");
const path = require("node:path");
const wasm = require("./wasm/rars_wasm.js");
const { startWorker } = require("./worker-engine.cjs");

function volumePath(firstPath, index, total, format) {
  const parsed = path.parse(firstPath);
  if (format === "rar50" || format === "rar70") {
    const stem = parsed.name.replace(/\.part\d+$/i, "");
    const width = Math.max(2, String(total).length);
    // Keep the first name's ".rar" as written, as RAR does: A.RAR, A.part01.RAR.
    const suffix = /^\.rar$/i.test(parsed.ext) ? parsed.ext : ".rar";
    return path.join(parsed.dir, `${stem}.part${String(index + 1).padStart(width, "0")}${suffix}`);
  }
  if (index === 0) return firstPath;
  // RAR follows the case of the first extension: A.RAR, A.R00; a.rar, a.r00.
  // RAR 4 rolls .r99 on to .s00, and so on up to .z99.
  const number = index - 1;
  const letter = String.fromCharCode((parsed.ext.startsWith(".R") ? 82 : 114) + Math.floor(number / 100));
  return path.join(parsed.dir, `${parsed.name}.${letter}${String(number % 100).padStart(2, "0")}`);
}

function volumePaths(firstPath, total, format) {
  if (!path.parse(firstPath).base) {
    throw new TypeError("volume output needs a file name");
  }
  if (format !== "rar50" && format !== "rar70" && total > 901) {
    throw new RangeError("old-style volume names run out after .z99");
  }
  const paths = Array.from({ length: total }, (_, index) => volumePath(firstPath, index, total, format));
  // Volume discovery is case insensitive, and these names must also remain
  // distinct on case-insensitive filesystems (e.g. archive.R00 vs archive.r00).
  if (new Set(paths.map((file) => path.resolve(file).toLowerCase())).size !== paths.length) {
    throw new TypeError("volume output paths must be distinct");
  }
  return paths;
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
    // Validate the whole set before publishing any volume.
    const paths = volumePaths(firstPath, parts.length, format);
    await Promise.all(parts.map((part, index) => writeAtomic(paths[index], part)));
    return paths;
  },
});
