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
// A file takes its mode through its own descriptor before it is published; a mode denying
// its owner read waits for the end, as do directories', set deepest first.
function extractor(directory, { overwrite, restoreTimes, restoreModes }) {
  const root = path.resolve(directory);
  const written = [];
  const directories = [];
  const modes = restoreModes && process.platform !== "win32";
  const lateModes = [];
  const skipped = [];
  // Where each stored path went, for hard links and copies that name an earlier member.
  const created = new Map();
  // Symlinks and junctions this call made, by output path.
  const madeLinks = new Set();
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
  // As unrar does, a link this call made gives way to a directory when a later member is
  // stored under it, so nothing is ever written through one.
  function replaceMadeLinks(relative, isDirectory) {
    if (madeLinks.size === 0) return;
    const parts = relative.split("/");
    for (let end = 1; end <= parts.length - (isDirectory ? 0 : 1); end++) {
      const above = parts.slice(0, end).join("/");
      if (!madeLinks.delete(above)) continue;
      const file = under(above);
      try {
        if (!fsSync.lstatSync(file).isSymbolicLink()) continue;
      } catch (error) {
        if (error.code === "ENOENT") continue;
        throw error;
      }
      // A directory link on Windows is removed as a directory.
      try { fsSync.unlinkSync(file); } catch { fsSync.rmdirSync(file); }
    }
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
      replaceMadeLinks(entry.path, entry.isDirectory === true);
      const mode = modes ? entry.mode : undefined;
      if (entry.link) {
        fsSync.mkdirSync(path.dirname(target), { recursive: true });
        const placed = link(entry, target);
        if (entry.link.kind === "symlink" || entry.link.kind === "junction") {
          madeLinks.add(path.relative(root, placed).split(path.sep).join("/"));
        }
        // A hard link shares its source's mode; a copy has its own.
        if (entry.link.kind === "copy" && mode !== undefined) {
          if (entry.modeEarly) {
            const descriptor = fsSync.openSync(placed, "r+");
            try { fsSync.fchmodSync(descriptor, mode); } finally { fsSync.closeSync(descriptor); }
          } else {
            lateModes.push([placed, mode]);
          }
        }
        created.set(entry.stored, placed);
        written.push(placed);
        return;
      }
      if (entry.isDirectory) {
        fsSync.mkdirSync(target, { recursive: true });
        directories.push([target, entry.mtime, mode]);
        return;
      }
      fsSync.mkdirSync(path.dirname(target), { recursive: true });
      const temporary = `${target}.rars-${process.pid}-${Date.now()}.tmp`;
      try {
        const descriptor = fsSync.openSync(temporary, "wx");
        try {
          fsSync.writeFileSync(descriptor, bytes);
          if (mode !== undefined && entry.modeEarly) fsSync.fchmodSync(descriptor, mode);
        } finally {
          fsSync.closeSync(descriptor);
        }
        setTime(temporary, entry.mtime);
        const placed = publish(temporary, target);
        if (mode !== undefined && !entry.modeEarly) lateModes.push([placed, mode]);
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
      const depth = (directory) => directory.split(path.sep).length;
      directories.sort(([left], [right]) => depth(right) - depth(left));
      for (const [target, mtime] of directories) setTime(target, mtime);
      for (const [file, mode] of lateModes) fsSync.chmodSync(file, mode);
      for (const [target, , mode] of directories) if (mode !== undefined) fsSync.chmodSync(target, mode);
      return { written, skipped };
    },
  };
}

// The next volume of a set, waited for while the main thread pulls it from the caller's
// iterator: the engine runs synchronously, so this blocks the worker until it arrives.
function nextVolume(feed) {
  if (feed === undefined) return undefined;
  const { receiveMessageOnPort } = require("node:worker_threads");
  const fsSync = require("node:fs");
  return () => {
    Atomics.store(feed.flag, 0, 0);
    feed.port.postMessage("next");
    for (;;) {
      Atomics.wait(feed.flag, 0, 0);
      const received = receiveMessageOnPort(feed.port);
      if (received !== undefined) {
        const reply = received.message;
        if (reply.error) throw new Error("volumes raised an exception");
        if (reply.done) return undefined;
        return reply.path !== undefined ? new Uint8Array(fsSync.readFileSync(reply.path)) : reply.bytes;
      }
      // The reply is posted before the flag is set, but may not be readable yet.
      Atomics.wait(feed.flag, 0, 1, 5);
    }
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
  nextVolume,
  posix: process.platform !== "win32",
  async writeVolumes(firstPath, parts, format, overwrite) {
    // Validate the whole set before publishing any volume.
    const paths = volumePaths(firstPath, parts.length, format);
    if (!overwrite) for (const file of paths) await refuseExisting(file);
    await Promise.all(parts.map((part, index) => writeAtomic(paths[index], part, overwrite)));
    return paths;
  },
});
