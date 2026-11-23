function codedError(code, message) {
  return Object.assign(new Error(message), { code });
}

function errorRecord(error) {
  const message = error?.message ?? String(error);
  // Native Node filesystem errors carry errno/syscall. Keep the public category
  // consistent with WASM I/O errors and retain the platform-specific cause.
  if (typeof error?.errno === "number" && typeof error?.syscall === "string") {
    return { code: "IO", message, details: {
      systemCode: error.code, errno: error.errno, syscall: error.syscall,
      ...(error.path === undefined ? {} : { path: error.path }),
    } };
  }
  if (typeof error?.code === "string") {
    return { code: error.code, message, ...(error.details === undefined ? {} : { details: error.details }) };
  }
  if (error instanceof TypeError || error instanceof RangeError) {
    return { code: "INVALID_OPTION", message };
  }
  return { code: "INTERNAL", message };
}

async function sourceBytes(source, platform) {
  if (source?.kind === "path") return platform.readFile(source.path);
  if (typeof Blob !== "undefined" && source instanceof Blob) {
    return new Uint8Array(await source.arrayBuffer());
  }
  if (source instanceof Uint8Array) return source;
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  throw new TypeError("unsupported binary source");
}

// The first `limit` bytes, read no further than that.
async function sourcePrefix(source, platform, limit) {
  if (source?.kind === "path") return platform.readPrefix(source.path, limit);
  if (typeof Blob !== "undefined" && source instanceof Blob) {
    return new Uint8Array(await source.slice(0, limit).arrayBuffer());
  }
  return (await sourceBytes(source, platform)).subarray(0, limit);
}

function metadata(archive, password, options) {
  const entries = archive.entries().map((info, index) => {
    if (!Number.isSafeInteger(info.size) || !Number.isSafeInteger(info.packedSize)) {
      throw codedError("RESOURCE_LIMIT", `entry ${index} is too large for exact JavaScript number metadata`);
    }
    const entry = {
      index,
      name: info.name,
      nameBytes: info.nameBytes,
      size: info.size,
      compressedSize: info.packedSize,
      mtime: info.mtime === undefined ? undefined : info.mtime * 1000,
      atime: info.atime === undefined ? undefined : info.atime * 1000,
      birthtime: info.birthtime === undefined ? undefined : info.birthtime * 1000,
      crc32: info.crc,
      isDirectory: info.isDirectory,
      isEncrypted: info.isEncrypted,
      isStored: info.isStored,
      isSolid: info.isSolid,
      isSplitBefore: info.isSplitBefore,
      isSplitAfter: info.isSplitAfter,
      volumeIndex: info.volumeIndex,
      isLink: info.isLink,
    };
    info.free();
    return entry;
  });
  return {
    entries,
    family: archive.family,
    sfxOffset: archive.sfxOffset,
    needsPassword: archive.needsPassword,
    isVolume: archive.isVolume,
    volumeIndex: archive.volumeIndex,
    isFirstVolume: archive.isFirstVolume,
    volumeNaming: archive.volumeNaming,
    comment: archive.readComment(password, options),
  };
}

// A set opened from its first volume's path finds the later ones by the names the core
// gives them, as Python and the CLI do, and stops at the first that isn't there.
async function discoverVolumes(wasm, source, password, platform, options) {
  const first = new wasm.RarFile(await platform.readFile(source.path), password, options);
  try {
    // Undefined when the headers can't tell, as in RAR 1.3 to 2.0 sets.
    if (!first.isVolume || first.isFirstVolume === false) return [source];
    const found = [source];
    const seen = new Set([source.path]);
    const name = platform.baseName(source.path);
    for (let index = 1; ; index++) {
      const next = first.volumeName(name, index);
      if (next === undefined) break;
      const file = platform.sibling(source.path, next);
      if (seen.has(file) || !(await platform.isFile(file))) break;
      seen.add(file);
      found.push({ kind: "path", path: file });
    }
    return found;
  } finally {
    first.free();
  }
}

async function openArchive(wasm, sources, password, platform, options) {
  const volumes = [];
  for (const source of sources) volumes.push(await sourceBytes(source, platform));
  return volumes.length === 1
    ? new wasm.RarFile(volumes[0], password, options)
    : wasm.RarFile.openVolumes(volumes, password, options);
}

// The builder that writes `rewrite`'s archive again, from its sources.
async function rewriteBuilder(wasm, rewrite, platform) {
  const archive = await openArchive(wasm, rewrite.sources, rewrite.password, platform, rewrite.readOptions);
  try {
    return wasm.RarBuilder.fromArchive(archive, rewrite.preserve, rewrite.password,
      rewrite.readOptions, rewrite.maxStagedBytes);
  } finally {
    archive.free();
  }
}

const sameBytes = (left, right) =>
  left.length === right.length && left.every((value, index) => value === right[index]);

async function build(wasm, payload, platform, volumes, report) {
  const options = payload.writerOptions;
  const builder = payload.rewrite ? await rewriteBuilder(wasm, payload.rewrite, platform) : new wasm.RarBuilder({
    format: options.version,
    compression: options.level,
    store: options.level === 0,
    solid: options.solid,
    password: options.password,
    encryptHeaders: options.encryptHeaders,
    blake2sp: options.blake2sp,
    comment: options.comment,
    recoveryPercent: options.recoveryPercent,
    maxMemoryBytes: options.maxMemoryBytes,
    volumeSize: options.volumeSize,
  });
  try {
    const bytes = (value) => typeof value === "string" ? new TextEncoder().encode(value) : value;
    if (payload.rewrite) {
      // The archive's own members keep their ids through the writer's edits.
      const kept = new Map(payload.entries.filter((entry) => entry.kind === "archived")
        .map((entry) => [entry.id, entry]));
      for (const id of builder.memberIds()) {
        const entry = kept.get(id);
        if (entry === undefined) builder.removeId(id);
        else if (!sameBytes(bytes(entry.name), entry.stored)) builder.renameId(id, bytes(entry.name));
      }
    }
    for (const entry of payload.entries) {
      if (entry.kind === "archived") continue;
      const entryOptions = { ...entry.options };
      if (entry.kind === "directory") {
        builder.addDirectory(bytes(entry.name), entryOptions);
        continue;
      }
      if (entry.kind === "symlink") {
        builder.addSymlink(bytes(entry.name), bytes(entry.target), entryOptions);
        continue;
      }
      const data = entry.data?.kind === "file"
        ? await platform.readFile(entry.data.path)
        : typeof entry.data === "string"
          ? new TextEncoder().encode(entry.data)
          : await sourceBytes(entry.data, platform);
      if (typeof entry.name === "string") builder.addBytes(entry.name, data, entryOptions);
      else builder.addBytesRaw(entry.name, data, entryOptions);
    }
    return volumes ? builder.toVolumes(report) : builder.toBytes(report);
  } finally {
    builder.free();
  }
}

// The phase names Python's ProgressPhase uses, plus repairing, which Python reports none for.
const PHASES = {
  open: "reading", read: "reading", readMany: "reading", readComment: "reading",
  readMemberComment: "reading", readLink: "reading", extract: "extracting",
  test: "testing", build: "compressing", buildVolumes: "compressing", writeTo: "compressing",
  repair: "repairing", probe: "reading", checkPassword: "testing", rewritePlan: "reading",
};

// Bytes the call produced, where its result is bytes.
function producedBytes(result) {
  if (result instanceof Uint8Array) return result.length;
  if (Array.isArray(result) && result.every((part) => part instanceof Uint8Array)) {
    return result.reduce((sum, part) => sum + part.length, 0);
  }
  if (result?.data instanceof Uint8Array) return result.data.length;
  return 0;
}

export function startWorker(port, wasm, platform) {
  port.onMessage(async (message) => {
    const { id, operation, payload } = message;
    // The engine calls this while it works, a mebibyte or a stage at a time.
    const report = message.progress
      ? (phase, completed, total) => port.post({ id, progress: { operation, phase, completed, total } })
      : undefined;
    try {
      const phase = PHASES[operation];
      // The engine reports nothing while it runs, so the total is unknown until it ends.
      port.post({ id, progress: { operation, phase, completed: 0 } });
      let result;
      if (operation === "open" || operation === "read" || operation === "readMany"
          || operation === "test" || operation === "readComment" || operation === "readMemberComment"
          || operation === "extract" || operation === "readLink") {
        if (operation === "open" && payload.sources.length === 1 && payload.sources[0]?.kind === "path") {
          payload.sources = await discoverVolumes(wasm, payload.sources[0], payload.password, platform, payload.readOptions);
        }
        const archive = await openArchive(wasm, payload.sources, payload.password, platform, payload.readOptions);
        try {
          switch (operation) {
            case "open":
              result = { ...metadata(archive, payload.password, payload.readOptions), sources: payload.sources };
              break;
            case "read": result = archive.readAt(payload.index, payload.password, payload.readOptions, report); break;
            case "readMany": result = archive.readMany(payload.indices, payload.password, payload.readOptions, report); break;
            case "test":
              archive.test(payload.password, payload.readOptions, report, platform.nextVolume?.(payload.volumeFeed));
              break;
            case "readComment": result = archive.readComment(payload.password, payload.readOptions); break;
            case "readMemberComment": result = archive.readMemberComment(payload.index, payload.password, payload.readOptions); break;
            case "readLink": result = archive.readLink(payload.index, payload.password, payload.readOptions); break;
            case "extract": {
              const output = platform.extractor(payload.directory, payload);
              archive.extractEach(payload.indices, payload.password, payload.readOptions,
                payload.flatten, platform.posix, output.deliver, output.readLink,
                platform.nextVolume?.(payload.volumeFeed), report);
              result = output.finish();
              break;
            }
          }
        } finally {
          archive.free();
        }
      } else if (operation === "checkPassword") {
        const bytes = await sourceBytes(payload.sources[0], platform);
        result = wasm.checkPassword(bytes, payload.candidates, payload.readOptions);
      } else if (operation === "probe") {
        // Only the signature at offset 0, or an archive start within the SFX scan; a
        // source that can't be read is not RAR, as Python's is_rarfile has it.
        const limit = payload.sfx ? wasm.sfxProbeBytes() : 8;
        let prefix;
        try {
          prefix = await sourcePrefix(payload.sources[0], platform, limit);
        } catch (error) {
          if (typeof error?.errno !== "number") throw error;
        }
        result = prefix !== undefined
          && (payload.sfx ? wasm.isRarFileSfx(prefix) : wasm.isRarFile(prefix));
      } else if (operation === "repair") {
        // An existing output is refused before the work, not after it.
        if (payload.output !== undefined && !payload.overwrite) {
          await platform.refuseExisting(payload.output);
        }
        const bytes = await sourceBytes(payload.sources[0], platform);
        const detailed = wasm.repairDetailed(bytes, payload.password);
        const report = detailed.report;
        try {
          result = { data: detailed.data, report: {
            changed: report.changed,
            dataRepaired: report.dataRepaired,
            recoveryRecordRebuilt: report.recoveryRecordRebuilt,
            endRecordRebuilt: report.endRecordRebuilt,
            availableRecoveryShards: report.availableRecoveryShards,
            expectedRecoveryShards: report.expectedRecoveryShards,
          } };
        } finally {
          report.free();
          detailed.free();
        }
        if (payload.output !== undefined) {
          await platform.writeAtomic(payload.output, result.data, payload.overwrite);
          result.data = undefined;
        }
      } else if (operation === "rewritePlan") {
        const builder = await rewriteBuilder(wasm, payload.rewrite, platform);
        try {
          result = { names: builder.rawNames(), ids: Array.from(builder.memberIds()) };
        } finally {
          builder.free();
        }
      } else if (operation === "build") {
        result = await build(wasm, payload, platform, false, report);
      } else if (operation === "buildVolumes") {
        result = await build(wasm, payload, platform, true, report);
      } else if (operation === "writeTo") {
        if (payload.writerOptions.volumeSize === undefined) {
          const bytes = await build(wasm, payload, platform, false, report);
          await platform.writeAtomic(payload.path, bytes, payload.overwrite);
          result = [payload.path];
        } else {
          const parts = await build(wasm, payload, platform, true, report);
          result = await platform.writeVolumes(payload.path, parts, payload.writerOptions.version, payload.overwrite);
        }
      } else {
        throw new Error(`unknown worker operation: ${operation}`);
      }
      const produced = producedBytes(result);
      port.post({ id, progress: { operation, phase, completed: produced, total: produced } });
      const transfers = [];
      if (result instanceof Uint8Array) transfers.push(result.buffer);
      else if (Array.isArray(result)) {
        for (const value of result) if (value instanceof Uint8Array) transfers.push(value.buffer);
      }
      port.post({ id, result }, transfers);
    } catch (error) {
      port.post({ id, error: errorRecord(error) });
    }
  });
}
