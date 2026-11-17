const { parentPort } = require("node:worker_threads");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const wasm = require("./wasm/rars_wasm.js");
const { startWorker } = require("./worker-engine.cjs");

function volumePaths(firstPath, total, format) {
  if (!path.parse(firstPath).base) {
    throw new TypeError("volume output needs a file name");
  }
  // The core names them, as the CLI and Python do.
  const directory = path.dirname(firstPath);
  const paths = wasm.volumeNames(path.basename(firstPath), total, format)
    .map((name) => path.join(directory, name));
  // Volume discovery is case insensitive, and these names must also remain
  // distinct on case-insensitive filesystems (e.g. archive.R00 vs archive.r00).
  if (new Set(paths.map((file) => path.resolve(file).toLowerCase())).size !== paths.length) {
    throw new TypeError("volume output paths must be distinct");
  }
  return paths;
}

// What writeTo() raises for an existing file without { overwrite: true }, shaped as
// Node's own EEXIST so it reaches callers as an IO RarError like any other.
function alreadyExists(target) {
  return Object.assign(
    new Error(`${target} already exists; pass { overwrite: true } to replace it`),
    { code: "EEXIST", errno: -os.constants.errno.EEXIST, syscall: "open", path: target },
  );
}

async function refuseExisting(target) {
  try {
    await fs.lstat(target);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  throw alreadyExists(target);
}

async function writeAtomic(target, bytes, overwrite) {
  if (!overwrite) await refuseExisting(target);
  const temporary = `${target}.rars-${process.pid}-${Date.now()}.tmp`;
  try {
    await fs.writeFile(temporary, bytes);
    if (overwrite) {
      await fs.rename(temporary, target);
      return;
    }
    // A hard link publishes only where nothing is, so a file that appears meanwhile survives.
    try {
      await fs.link(temporary, target);
    } catch (error) {
      if (error.code === "EEXIST") throw alreadyExists(target);
      // Filesystems without hard links: an exclusive copy keeps the guarantee.
      await fs.copyFile(temporary, target, fs.constants.COPYFILE_EXCL).catch((copyError) => {
        throw copyError.code === "EEXIST" ? alreadyExists(target) : copyError;
      });
    }
    await fs.unlink(temporary);
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
  async isFile(file) {
    return fs.stat(file).then((stats) => stats.isFile(), () => false);
  },
  baseName: (file) => path.basename(file),
  sibling: (file, name) => path.join(path.dirname(file), name),
  async readPrefix(file, limit) {
    const handle = await fs.open(file, "r");
    try {
      const buffer = new Uint8Array(limit);
      const { bytesRead } = await handle.read(buffer, 0, limit, 0);
      return buffer.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  },
  writeAtomic,
  refuseExisting,
  async writeVolumes(firstPath, parts, format, overwrite) {
    // Validate the whole set before publishing any volume.
    const paths = volumePaths(firstPath, parts.length, format);
    if (!overwrite) for (const file of paths) await refuseExisting(file);
    await Promise.all(parts.map((part, index) => writeAtomic(paths[index], part, overwrite)));
    return paths;
  },
});
