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

// Writes verified entries under `directory`, as Python's extractall does: an existing file
// is refused unless overwrite is true, or kept with the new one beside it as name(N).ext
// under "rename". Directory times are set last, after their contents are written.
function extractor(directory, { overwrite, restoreTimes }) {
  const root = path.resolve(directory);
  const written = [];
  const directories = [];
  const skipped = [];
  // Where each stored path went, for hard links and copies that name an earlier member.
  const created = new Map();
  const fsSync = require("node:fs");
  const under = (relative) => path.join(root, ...relative.split("/"));
  // Places something new at `target` under the overwrite policy, by calling `make(path)`,
  // which must fail with EEXIST when something is already there.
  function place(target, make) {
    if (overwrite === true) {
      fsSync.rmSync(target, { force: true });
      make(target);
      return target;
    }
    const parsed = path.parse(target);
    for (let number = 0; ; number++) {
      const candidate = number === 0 ? target
        : path.join(parsed.dir, `${parsed.name}(${number})${parsed.ext}`);
      try {
        make(candidate);
        return candidate;
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        if (overwrite !== "rename") throw alreadyExists(candidate);
      }
    }
  }
  function link(entry, target) {
    const { kind, target: to, directory } = entry.link;
    if (kind === "hardlink" || kind === "copy") {
      const source = created.get(to);
      if (source === undefined) {
        throw Object.assign(new Error(`${entry.path} links to ${to}, which was not extracted`),
          { code: "INVALID_ARCHIVE" });
      }
      return place(target, (file) => kind === "hardlink"
        ? fsSync.linkSync(source, file)
        : fsSync.copyFileSync(source, file, fsSync.constants.COPYFILE_EXCL));
    }
    // A junction is a directory link; elsewhere than Windows it is made as a symlink.
    const type = process.platform === "win32" ? (kind === "junction" ? "junction" : directory ? "dir" : "file")
      : undefined;
    return place(target, (file) => fsSync.symlinkSync(to.split("/").join(path.sep), file, type));
  }
  function setTime(file, mtime) {
    if (restoreTimes && mtime !== undefined) fsSync.utimesSync(file, mtime, mtime);
  }
  function publish(temporary, target) {
    if (overwrite === true) {
      fsSync.renameSync(temporary, target);
      return target;
    }
    const parsed = path.parse(target);
    for (let number = 0; ; number++) {
      const candidate = number === 0 ? target
        : path.join(parsed.dir, `${parsed.name}(${number})${parsed.ext}`);
      try {
        fsSync.linkSync(temporary, candidate);
        fsSync.unlinkSync(temporary);
        return candidate;
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        if (overwrite !== "rename") throw alreadyExists(candidate);
      }
    }
  }
  return {
    deliver(entry, bytes) {
      const target = under(entry.path);
      const relative = path.relative(root, target);
      if (relative.startsWith("..") || path.isAbsolute(relative)) {
        throw Object.assign(new Error(`unsafe archive path: ${entry.path}`), { code: "UNSAFE_ENTRY_NAME" });
      }
      if (entry.skipped) {
        skipped.push({ name: entry.stored, target: entry.target });
        return;
      }
      if (entry.link) {
        fsSync.mkdirSync(path.dirname(target), { recursive: true });
        const placed = link(entry, target);
        created.set(entry.stored, placed);
        written.push(placed);
        return;
      }
      if (entry.isDirectory) {
        fsSync.mkdirSync(target, { recursive: true });
        directories.push([target, entry.mtime]);
        return;
      }
      fsSync.mkdirSync(path.dirname(target), { recursive: true });
      const temporary = `${target}.rars-${process.pid}-${Date.now()}.tmp`;
      try {
        fsSync.writeFileSync(temporary, bytes, { flag: "wx" });
        setTime(temporary, entry.mtime);
        const placed = publish(temporary, target);
        created.set(entry.stored, placed);
        written.push(placed);
      } catch (error) {
        try { fsSync.unlinkSync(temporary); } catch {}
        throw error;
      }
    },
    // The engine's question for its containment check: the target of the link already at
    // this relative path, or undefined.
    readLink(relative) {
      const file = under(relative);
      try {
        if (!fsSync.lstatSync(file).isSymbolicLink()) return undefined;
        return fsSync.readlinkSync(file).split(path.sep).join("/");
      } catch (error) {
        if (error.code === "ENOENT" || error.code === "ENOTDIR") return undefined;
        throw error;
      }
    },
    finish() {
      for (const [target, mtime] of directories.reverse()) setTime(target, mtime);
      return { written, skipped };
    },
  };
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
  extractor,
  posix: process.platform !== "win32",
  async writeVolumes(firstPath, parts, format, overwrite) {
    // Validate the whole set before publishing any volume.
    const paths = volumePaths(firstPath, parts.length, format);
    if (!overwrite) for (const file of paths) await refuseExisting(file);
    await Promise.all(parts.map((part, index) => writeAtomic(paths[index], part, overwrite)));
    return paths;
  },
});
