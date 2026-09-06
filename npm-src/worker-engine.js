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

function dosDate(value) {
  if (value === undefined) return undefined;
  const date = value >>> 16;
  const time = value & 0xffff;
  const day = date & 0x1f;
  const month = (date >>> 5) & 0x0f;
  const year = ((date >>> 9) & 0x7f) + 1980;
  const second = (time & 0x1f) * 2;
  const minute = (time >>> 5) & 0x3f;
  const hour = (time >>> 11) & 0x1f;
  return Date.UTC(year, month - 1, day, hour, minute, second);
}

function toDosDate(milliseconds) {
  if (milliseconds === undefined) return undefined;
  const date = new Date(milliseconds);
  const year = Math.min(2107, Math.max(1980, date.getUTCFullYear()));
  const time = (date.getUTCHours() << 11) |
    (date.getUTCMinutes() << 5) |
    Math.floor(date.getUTCSeconds() / 2);
  const day = ((year - 1980) << 9) |
    ((date.getUTCMonth() + 1) << 5) |
    date.getUTCDate();
  return ((day << 16) | time) >>> 0;
}

function metadata(archive) {
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
      modifiedAt: dosDate(info.fileTime),
      crc32: info.crc,
      isDirectory: info.isDirectory,
      isEncrypted: info.isEncrypted,
      isStored: info.isStored,
      isSolid: info.isSolid,
      isSplitBefore: info.isSplitBefore,
      isSplitAfter: info.isSplitAfter,
    };
    info.free();
    return entry;
  });
  return {
    entries,
    family: archive.family,
    sfxOffset: archive.sfxOffset,
    needsPassword: archive.needsPassword,
    comment: archive.comment,
  };
}

async function openArchive(wasm, sources, password, platform) {
  const volumes = [];
  for (const source of sources) volumes.push(await sourceBytes(source, platform));
  return volumes.length === 1
    ? new wasm.RarFile(volumes[0], password)
    : wasm.RarFile.openVolumes(volumes, password);
}

async function build(wasm, payload, platform, volumes) {
  const options = payload.writerOptions;
  const builder = new wasm.RarBuilder({
    format: options.format,
    compression: options.level,
    store: options.level === 0,
    solid: options.solid,
    password: options.password,
    encryptHeaders: options.encryptHeaders,
    comment: options.comment,
    recoveryPercent: options.recoveryPercent,
    volumeSize: volumes ? payload.size : undefined,
  });
  try {
    for (const entry of payload.entries) {
      const data = entry.data?.kind === "file"
        ? await platform.readFile(entry.data.path)
        : typeof entry.data === "string"
          ? new TextEncoder().encode(entry.data)
          : await sourceBytes(entry.data, platform);
      const entryOptions = {
        mtime: toDosDate(entry.options.modifiedAt),
        mode: entry.options.mode,
      };
      if (typeof entry.name === "string") builder.addBytes(entry.name, data, entryOptions);
      else builder.addBytesRaw(entry.name, data, entryOptions);
    }
    return volumes ? builder.toVolumes() : builder.toBytes();
  } finally {
    builder.free();
  }
}

export function startWorker(port, wasm, platform) {
  port.onMessage(async (message) => {
    const { id, operation, payload } = message;
    try {
      port.post({ id, progress: { operation, phase: "working", completed: 0 } });
      let result;
      if (operation === "open") {
        const archive = await openArchive(wasm, payload.sources, payload.password, platform);
        try { result = metadata(archive); } finally { archive.free(); }
      } else if (operation === "read") {
        const archive = await openArchive(wasm, payload.sources, payload.password, platform);
        try { result = archive.readAt(payload.index, payload.password); } finally { archive.free(); }
      } else if (operation === "test") {
        const archive = await openArchive(wasm, payload.sources, payload.password, platform);
        try { archive.test(payload.password); result = undefined; } finally { archive.free(); }
      } else if (operation === "repair") {
        const bytes = await sourceBytes(payload.sources[0], platform);
        result = wasm.repair(bytes, payload.password);
      } else if (operation === "repairDetailed") {
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
      } else if (operation === "build") {
        result = await build(wasm, payload, platform, false);
      } else if (operation === "buildVolumes") {
        result = await build(wasm, payload, platform, true);
      } else if (operation === "writeTo") {
        const bytes = await build(wasm, payload, platform, false);
        await platform.writeAtomic(payload.path, bytes);
        result = undefined;
      } else if (operation === "writeVolumesTo") {
        const parts = await build(wasm, payload, platform, true);
        result = await platform.writeVolumes(payload.path, parts, payload.writerOptions.format);
      } else {
        throw new Error(`unknown worker operation: ${operation}`);
      }
      port.post({ id, progress: { operation, phase: "complete", completed: 1, total: 1 } });
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
