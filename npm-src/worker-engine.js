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
      modifiedAt: info.mtime === undefined ? undefined : info.mtime * 1000,
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
    comment: archive.readComment(password, options),
  };
}

async function openArchive(wasm, sources, password, platform, options) {
  const volumes = [];
  for (const source of sources) volumes.push(await sourceBytes(source, platform));
  return volumes.length === 1
    ? new wasm.RarFile(volumes[0], password, options)
    : wasm.RarFile.openVolumes(volumes, password, options);
}

async function build(wasm, payload, platform, volumes) {
  const options = payload.writerOptions;
  const builder = new wasm.RarBuilder({
    format: options.version,
    compression: options.level,
    store: options.level === 0,
    solid: options.solid,
    password: options.password,
    encryptHeaders: options.encryptHeaders,
    comment: options.comment,
    recoveryPercent: options.recoveryPercent,
    maxMemoryBytes: options.maxMemoryBytes,
    volumeSize: options.volumeSize,
  });
  try {
    for (const entry of payload.entries) {
      const data = entry.data?.kind === "file"
        ? await platform.readFile(entry.data.path)
        : typeof entry.data === "string"
          ? new TextEncoder().encode(entry.data)
          : await sourceBytes(entry.data, platform);
      const entryOptions = {
        mtime: entry.options.modifiedAt === undefined ? undefined : entry.options.modifiedAt / 1000,
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
      if (operation === "open" || operation === "read" || operation === "readMany"
          || operation === "test" || operation === "readComment") {
        const archive = await openArchive(wasm, payload.sources, payload.password, platform, payload.readOptions);
        try {
          switch (operation) {
            case "open": result = metadata(archive, payload.password, payload.readOptions); break;
            case "read": result = archive.readAt(payload.index, payload.password, payload.readOptions); break;
            case "readMany": result = archive.readMany(payload.indices, payload.password, payload.readOptions); break;
            case "test": archive.test(payload.password, payload.readOptions); break;
            case "readComment": result = archive.readComment(payload.password, payload.readOptions); break;
          }
        } finally {
          archive.free();
        }
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
      } else if (operation === "build") {
        result = await build(wasm, payload, platform, false);
      } else if (operation === "buildVolumes") {
        result = await build(wasm, payload, platform, true);
      } else if (operation === "writeTo") {
        if (payload.writerOptions.volumeSize === undefined) {
          const bytes = await build(wasm, payload, platform, false);
          await platform.writeAtomic(payload.path, bytes, payload.overwrite);
          result = [payload.path];
        } else {
          const parts = await build(wasm, payload, platform, true);
          result = await platform.writeVolumes(payload.path, parts, payload.writerOptions.version, payload.overwrite);
        }
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
