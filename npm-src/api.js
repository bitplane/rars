const FORMATS = Object.freeze([
  "rar13", "rar14", "rar15", "rar20", "rar29",
  "rar30", "rar40", "rar50", "rar70",
]);

export function createApi(runtime) {
  class RarError extends Error {
    constructor(code, message, details) {
      super(message);
      this.name = "RarError";
      this.code = code;
      if (details !== undefined) this.details = details;
    }
  }

  function assertOpen(value) {
    if (value._closed) throw new RarError("CLOSED", "the RAR object is closed");
  }

  function operationOptions(options) {
    if (options == null) return {};
    if (typeof options !== "object") {
      throw new TypeError("operation options must be an object");
    }
    return options;
  }

  function sameName(left, right) {
    if (typeof left === "string" || typeof right === "string") return left === right;
    if (left.length !== right.length) return false;
    return left.every((value, index) => value === right[index]);
  }

  class RarEntry {
    constructor(archive, metadata) {
      this._archive = archive;
      if (metadata.modifiedAt !== undefined) metadata.modifiedAt = new Date(metadata.modifiedAt);
      Object.assign(this, metadata);
    }

    async bytes(options) {
      assertOpen(this._archive);
      if (this.isDirectory) {
        throw new RarError("ENTRY_IS_DIRECTORY", `cannot read directory entry: ${this.name}`);
      }
      const operation = operationOptions(options);
      return this._archive._request("read", {
        index: this.index,
        password: operation.password ?? this._archive._password,
      }, operation);
    }
  }

  class RarArchive {
    static async open(input, options) {
      const operation = operationOptions(options);
      const sources = await runtime.prepareArchiveSources(input);
      const result = await runtime.request("open", {
        sources,
        password: operation.password,
      }, operation);
      return new RarArchive(sources, operation.password, result);
    }

    constructor(sources, password, metadata) {
      this._sources = sources;
      this._password = password;
      this._closed = false;
      this.family = metadata.family;
      this.sfxOffset = metadata.sfxOffset;
      this.comment = metadata.comment;
      this.needsPassword = metadata.needsPassword;
      this.entries = Object.freeze(metadata.entries.map(
        (entry) => Object.freeze(new RarEntry(this, entry)),
      ));
    }

    _request(operation, payload, options) {
      assertOpen(this);
      return runtime.request(operation, { ...payload, sources: this._sources }, options);
    }

    get(name) {
      assertOpen(this);
      return this.entries.find((entry) => sameName(
        typeof name === "string" ? entry.name : entry.nameBytes,
        name,
      ));
    }

    getAll(name) {
      assertOpen(this);
      return this.entries.filter((entry) => sameName(
        typeof name === "string" ? entry.name : entry.nameBytes,
        name,
      ));
    }

    async test(options) {
      const operation = operationOptions(options);
      await this._request("test", {
        password: operation.password ?? this._password,
      }, operation);
    }

    close() {
      if (this._closed) return;
      this._closed = true;
      this._sources = [];
    }
  }

  function validateName(name) {
    if (typeof name === "string") {
      if (name.length === 0) throw new TypeError("entry name must not be empty");
      const bytes = new TextEncoder().encode(name);
      validateSafePath(bytes);
      return name;
    }
    if (name instanceof Uint8Array && name.length > 0) {
      const copy = Uint8Array.from(name);
      validateSafePath(copy);
      return copy;
    }
    throw new TypeError("entry name must be a non-empty string or Uint8Array");
  }

  function validateSafePath(bytes) {
    if (bytes[0] === 47 || bytes[0] === 92 ||
        (bytes.length >= 2 && ((bytes[0] | 32) >= 97 && (bytes[0] | 32) <= 122) && bytes[1] === 58)) {
      throw new RarError("UNSAFE_ENTRY_NAME", "unsafe archive entry path");
    }
    const text = new TextDecoder().decode(bytes).replaceAll("\\", "/");
    if (text.split("/").some((part) => part === "..")) {
      throw new RarError("UNSAFE_ENTRY_NAME", "unsafe archive entry path");
    }
  }

  function validateWriterOptions(options = {}) {
    if (options == null || typeof options !== "object") {
      throw new TypeError("writer options must be an object");
    }
    const format = options.format ?? "rar50";
    if (!FORMATS.includes(format)) throw new TypeError(`unsupported RAR format: ${format}`);
    const level = options.level ?? 3;
    if (!Number.isInteger(level) || level < 0 || level > 5) {
      throw new TypeError("level must be an integer from 0 to 5");
    }
    for (const key of ["solid", "encryptHeaders"]) {
      if (options[key] !== undefined && typeof options[key] !== "boolean") {
        throw new TypeError(`${key} must be a boolean`);
      }
    }
    if (options.recoveryPercent !== undefined &&
        (!Number.isInteger(options.recoveryPercent) ||
         options.recoveryPercent < 1 || options.recoveryPercent > 100)) {
      throw new TypeError("recoveryPercent must be an integer from 1 to 100");
    }
    return { ...options, format, level };
  }

  function validateEntryOptions(options = {}) {
    if (options == null || typeof options !== "object") {
      throw new TypeError("entry options must be an object");
    }
    if (options.modifiedAt !== undefined &&
        (!(options.modifiedAt instanceof Date) || Number.isNaN(options.modifiedAt.valueOf()))) {
      throw new TypeError("modifiedAt must be a valid Date");
    }
    if (options.mode !== undefined &&
        (!Number.isSafeInteger(options.mode) || options.mode < 0)) {
      throw new TypeError("mode must be a non-negative safe integer");
    }
    return {
      modifiedAt: options.modifiedAt?.valueOf(),
      mode: options.mode,
    };
  }

  class RarWriter {
    constructor(options) {
      this._options = validateWriterOptions(options);
      this._entries = [];
      this._closed = false;
    }

    add(name, data, options) {
      assertOpen(this);
      const checkedName = validateName(name);
      if (this._entries.some((entry) => sameName(entry.name, checkedName))) {
        throw new RarError("DUPLICATE_ENTRY", "duplicate archive entry name");
      }
      this._entries.push({
        name: checkedName,
        data: runtime.prepareEntryData(data),
        options: validateEntryOptions(options),
      });
      return this;
    }

    addFile(name, path, options) {
      assertOpen(this);
      if (!runtime.prepareFile) {
        throw new RarError("UNSUPPORTED_FEATURE", "addFile is only available in Node");
      }
      return this.add(name, runtime.prepareFile(path), options);
    }

    remove(name) {
      assertOpen(this);
      const checked = validateName(name);
      const index = this._entries.findIndex((entry) => sameName(entry.name, checked));
      if (index < 0) throw new RarError("ENTRY_NOT_FOUND", "no such queued entry");
      this._entries.splice(index, 1);
      return this;
    }

    rename(from, to) {
      assertOpen(this);
      const oldName = validateName(from);
      const newName = validateName(to);
      const entry = this._entries.find((candidate) => sameName(candidate.name, oldName));
      if (!entry) throw new RarError("ENTRY_NOT_FOUND", "no such queued entry");
      if (this._entries.some((candidate) => candidate !== entry && sameName(candidate.name, newName))) {
        throw new RarError("DUPLICATE_ENTRY", "duplicate archive entry name");
      }
      entry.name = newName;
      return this;
    }

    get names() {
      assertOpen(this);
      return this._entries.map((entry) =>
        typeof entry.name === "string" ? entry.name : Uint8Array.from(entry.name));
    }

    _build(operation, extra, options) {
      assertOpen(this);
      if (this._entries.length === 0) {
        return Promise.reject(new RarError("INVALID_OPTION", "the writer has no entries"));
      }
      return runtime.request(operation, {
        writerOptions: this._options,
        entries: this._entries.slice(),
        ...extra,
      }, operationOptions(options));
    }

    bytes(options) {
      return this._build("build", {}, options);
    }

    volumes(size, options) {
      if (!Number.isSafeInteger(size) || size <= 0) {
        return Promise.reject(new TypeError("volume size must be a positive safe integer"));
      }
      return this._build("buildVolumes", { size }, options);
    }

    writeTo(path, options) {
      return this._build("writeTo", { path: runtime.prepareOutputPath(path) }, options);
    }

    writeVolumesTo(firstPath, size, options) {
      if (!Number.isSafeInteger(size) || size <= 0) {
        return Promise.reject(new TypeError("volume size must be a positive safe integer"));
      }
      return this._build("writeVolumesTo", {
        path: runtime.prepareOutputPath(firstPath), size,
      }, options);
    }

    close() {
      if (this._closed) return;
      this._closed = true;
      this._entries = [];
    }
  }

  async function repair(input, options) {
    const operation = operationOptions(options);
    const sources = await runtime.prepareArchiveSources(input);
    if (sources.length !== 1) {
      throw new RarError("UNSUPPORTED_FEATURE", "repair currently accepts one archive volume");
    }
    return runtime.request("repair", {
      sources,
      password: operation.password,
    }, operation);
  }

  async function repairDetailed(input, options) {
    const operation = operationOptions(options);
    const sources = await runtime.prepareArchiveSources(input);
    if (sources.length !== 1) {
      throw new RarError("UNSUPPORTED_FEATURE", "repair currently accepts one archive volume");
    }
    return runtime.request("repairDetailed", { sources, password: operation.password }, operation);
  }

  runtime.setErrorFactory((error) => {
    if (error?.name === "AbortError") return error;
    return new RarError(error?.code ?? "INTERNAL", error?.message ?? String(error), error?.details);
  });

  return {
    RarArchive,
    RarEntry,
    RarError,
    RarWriter,
    repair, repairDetailed,
    formats: FORMATS,
    version: runtime.version,
  };
}
