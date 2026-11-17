const ARCHIVE_VERSIONS = Object.freeze([
  "rar13", "rar14", "rar15", "rar20", "rar29",
  "rar30", "rar40", "rar50", "rar70",
]);

// Unknown keys are refused, so a misspelt or renamed setting can't be silently ignored.
const WRITER_OPTIONS = Object.freeze([
  "version", "level", "solid", "password", "encryptHeaders", "comment",
  "recoveryPercent", "maxMemoryBytes", "volumeSize",
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

  function readOptions(options) {
    const limits = {};
    if (options.legacyNameEncoding != null) {
      const encoding = options.legacyNameEncoding;
      if (typeof encoding !== "string" || !["cp437", "cp850", "cp852", "cp866", "cp1251", "cp1252", "windows-1251", "windows-1252", "utf8", "utf-8"].includes(encoding.toLowerCase())) {
        throw new RarError("INVALID_OPTION", "unsupported legacyNameEncoding");
      }
      limits.legacyNameEncoding = encoding;
    }
    for (const key of ["maxHeaderCount", "maxHeaderBytes", "maxMemberOutputBytes", "maxTotalOutputBytes", "maxReaderWorkspaceBytes", "maxRar50DictionaryBytes", "maxRar50BufferedMemberBytes"]) {
      const value = options[key];
      if (value == null) continue;
      if (!(typeof value === "number" && Number.isSafeInteger(value) && value >= 0) &&
          !(typeof value === "bigint" && value >= 0n && value <= (1n << 64n) - 1n)) {
        throw new RarError("INVALID_OPTION", `${key} must be a nonnegative safe integer or a bigint through 2**64 - 1`);
      }
      limits[key] = value;
    }
    if (options.allowRar3VmPrograms != null) {
      if (typeof options.allowRar3VmPrograms !== "boolean") {
        throw new RarError("INVALID_OPTION", "allowRar3VmPrograms must be a boolean");
      }
      limits.allowRar3VmPrograms = options.allowRar3VmPrograms;
    }
    return limits;
  }

  function sameName(left, right) {
    if (typeof left === "string" || typeof right === "string") return left === right;
    if (left.length !== right.length) return false;
    return left.every((value, index) => value === right[index]);
  }

  class RarEntry {
    constructor(archive, metadata) {
      this._archive = archive;
      for (const key of ["mtime", "atime", "birthtime"]) {
        if (metadata[key] !== undefined) metadata[key] = new Date(metadata[key]);
      }
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
        readOptions: this._archive._readOptions(operation),
        password: operation.password ?? this._archive._password,
      }, operation);
    }

    /** The comment attached to this entry, or undefined; Python's member_comment(). */
    async readComment(options) {
      assertOpen(this._archive);
      const operation = operationOptions(options);
      return this._archive._request("readMemberComment", {
        index: this.index,
        readOptions: this._archive._readOptions(operation),
        password: operation.password ?? this._archive._password,
      }, operation);
    }
  }

  class RarArchive {
    #nameEntries = new Map();
    #indexedEntries;

    static async open(input, options) {
      const operation = operationOptions(options);
      const sources = await runtime.prepareArchiveSources(input);
      const result = await runtime.request("open", {
        sources,
        readOptions: readOptions(operation),
        password: operation.password,
      }, operation);
      return new RarArchive(sources, operation.password, result, readOptions(operation));
    }

    constructor(sources, password, metadata, defaults) {
      this._defaults = defaults;
      this._legacyNameEncoding = defaults.legacyNameEncoding;
      this._sources = sources;
      this._password = password;
      this._closed = false;
      this.family = metadata.family;
      this.sfxOffset = metadata.sfxOffset;
      this.comment = metadata.comment;
      this.needsPassword = metadata.needsPassword;
      this.isVolume = metadata.isVolume;
      this.volumeIndex = metadata.volumeIndex;
      this.isFirstVolume = metadata.isFirstVolume;
      this.volumeNaming = metadata.volumeNaming;
      this.entries = Object.freeze(metadata.entries.map(
        (entry) => Object.freeze(new RarEntry(this, entry)),
      ));
      this.#indexedEntries = this.entries;
      for (const entry of this.entries) {
        const matches = this.#nameEntries.get(entry.name);
        if (matches) matches.push(entry);
        else this.#nameEntries.set(entry.name, [entry]);
      }
    }

    /** Options given to open() are defaults; a call's own fields override them one by one. */
    _readOptions(operation) {
      return { ...this._defaults, ...readOptions(operation) };
    }

    _request(operation, payload, options) {
      assertOpen(this);
      return runtime.request(operation, { ...payload, sources: this._sources }, options);
    }

    get(name) {
      const matches = this.#matchingEntries(name, false);
      if (this._legacyNameEncoding != null && typeof name === "string"
          && matches.some((entry) => !sameName(entry.nameBytes, matches[0].nameBytes))) {
        throw new RarError("AMBIGUOUS_ENTRY", "decoded name is ambiguous; use getAll() or an entry index");
      }
      return matches.at(-1);
    }

    getAll(name) {
      return this.#matchingEntries(name, true);
    }

    /** Whether the archive holds an entry with this name, as Python's `name in archive`. */
    has(name) {
      return this.#matchingEntries(name, false).length > 0;
    }

    #matchingEntries(name, copy) {
      assertOpen(this);
      if (typeof name === "string" && this.entries === this.#indexedEntries) {
        const matches = this.#nameEntries.get(name) ?? [];
        return copy ? matches.slice() : matches;
      }
      // Raw Uint8Array names remain mutable, even on frozen entries. Also
      // preserve traversal if a caller replaces the public entries property.
      return this.entries.filter((entry) => sameName(
        typeof name === "string" ? entry.name : entry.nameBytes,
        name,
      ));
    }

    async readMany(members, options) {
      assertOpen(this);
      const operation = operationOptions(options);
      const indices = [];
      for (const member of members) {
        const entry = member instanceof RarEntry ? member : this.get(member);
        if (!entry) throw new RarError("ENTRY_NOT_FOUND", "no such archive entry");
        if (entry._archive !== this || this.entries[entry.index] !== entry) {
          throw new RarError("INVALID_OPTION", "entry belongs to a different archive");
        }
        if (entry.isDirectory) {
          throw new RarError("ENTRY_IS_DIRECTORY", `cannot read directory entry: ${entry.name}`);
        }
        indices.push(entry.index);
      }
      return this._request("readMany", {
        indices,
        readOptions: this._readOptions(operation),
        password: operation.password ?? this._password,
      }, operation);
    }

    async readComment(options) {
      const operation = operationOptions(options);
      return this._request("readComment", {
        password: operation.password ?? this._password,
        readOptions: this._readOptions(operation),
      }, operation);
    }

    async test(options) {
      const operation = operationOptions(options);
      await this._request("test", {
        readOptions: this._readOptions(operation),
        password: operation.password ?? this._password,
      }, operation);
    }

    close() {
      if (this._closed) return;
      this._closed = true;
      this._sources = [];
      this.#nameEntries.clear();
      this.#indexedEntries = undefined;
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
    for (const key of Object.keys(options)) {
      if (!WRITER_OPTIONS.includes(key)) {
        throw new TypeError(`unknown writer option ${JSON.stringify(key)}`
          + (key === "format" ? "; it is now called version" : ""));
      }
    }
    const version = options.version ?? "rar50";
    if (!ARCHIVE_VERSIONS.includes(version)) {
      throw new TypeError(`unknown RAR version ${JSON.stringify(version)}; expected one of ${ARCHIVE_VERSIONS.join(", ")}`);
    }
    // A wrong type is a TypeError; a value the version can't write is refused here,
    // before anything is added, as an INVALID_OPTION RarError.
    const invalid = (message) => new RarError("INVALID_OPTION", message);
    const modern = version === "rar50" || version === "rar70";
    const level = options.level ?? 3;
    if (!Number.isInteger(level)) throw new TypeError("level must be an integer");
    if (level < 0 || level > 5) throw invalid("level must be from 0 to 5");
    for (const key of ["solid", "encryptHeaders"]) {
      if (options[key] !== undefined && typeof options[key] !== "boolean") {
        throw new TypeError(`${key} must be a boolean`);
      }
    }
    if (options.recoveryPercent !== undefined) {
      if (!Number.isInteger(options.recoveryPercent)) {
        throw new TypeError("recoveryPercent must be an integer");
      }
      if (!modern) throw invalid(`${version} cannot write a recovery record`);
      if (options.recoveryPercent < 1 || options.recoveryPercent > 100) {
        throw invalid("recoveryPercent must be from 1 to 100");
      }
    }
    if (options.encryptHeaders) {
      if (options.password == null) throw invalid("encryptHeaders needs a password");
      if (!["rar30", "rar40", "rar50", "rar70"].includes(version)) {
        throw invalid(`${version} cannot write header encryption`);
      }
    }
    if (options.volumeSize !== undefined) {
      if (!Number.isSafeInteger(options.volumeSize)) {
        throw new TypeError("volumeSize must be a safe integer");
      }
      if (options.volumeSize <= 0) throw invalid("volumeSize must be more than 0");
      if (options.comment != null) throw invalid(`${version} cannot write an archive comment in a volume set`);
    }
    if (options.maxMemoryBytes != null && !modern) {
      throw invalid(`${version} cannot write to a memory limit; only rar50 and rar70 can`);
    }
    return { ...options, version, level };
  }

  function validateEntryOptions(options = {}) {
    if (options == null || typeof options !== "object") {
      throw new TypeError("entry options must be an object");
    }
    // As fs.utimes takes it: a Date, or a number of Unix seconds.
    const mtime = options.mtime instanceof Date ? options.mtime.valueOf() / 1000 : options.mtime;
    if (mtime !== undefined && (typeof mtime !== "number" || !Number.isFinite(mtime))) {
      throw new TypeError("mtime must be a valid Date or a number of Unix seconds");
    }
    if (options.mode !== undefined &&
        (!Number.isSafeInteger(options.mode) || options.mode < 0)) {
      throw new TypeError("mode must be a non-negative safe integer");
    }
    if (options.comment !== undefined && typeof options.comment !== "string"
        && !(options.comment instanceof Uint8Array)) {
      throw new TypeError("comment must be a string or Uint8Array");
    }
    return {
      mtime,
      mode: options.mode,
      comment: options.comment,
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
      if (this._options.volumeSize !== undefined) {
        return Promise.reject(new RarError("INVALID_OPTION",
          "volumeSize is set, so use volumes() or writeTo()"));
      }
      return this._build("build", {}, options);
    }

    /** The parts of a volume set, in memory; needs `volumeSize`. */
    volumes(options) {
      if (this._options.volumeSize === undefined) {
        return Promise.reject(new RarError("INVALID_OPTION",
          "volumes() needs new RarWriter({ volumeSize })"));
      }
      return this._build("buildVolumes", {}, options);
    }

    /** Writes the archive, or with `volumeSize` every part of the set, and returns the paths written. */
    writeTo(path, options) {
      const overwrite = options?.overwrite ?? false;
      if (typeof overwrite !== "boolean") throw new TypeError("overwrite must be a boolean");
      return this._build("writeTo", { path: runtime.prepareOutputPath(path), overwrite }, options);
    }

    close() {
      if (this._closed) return;
      this._closed = true;
      this._entries = [];
    }
  }

  async function probe(input, sfx) {
    if (Array.isArray(input)) throw new TypeError("expected one archive source");
    const [source] = await runtime.prepareArchiveSources(input);
    return runtime.request("probe", { sources: [source], sfx }, {});
  }

  /** Whether the source starts with a RAR signature; an unreadable source is not RAR. */
  function isRarFile(input) {
    return probe(input, false);
  }

  /** Whether a RAR archive starts in the source, behind a self-extractor stub or not. */
  function isRarFileSfx(input) {
    return probe(input, true);
  }

  /** With `output` (Node), the repaired archive is written there and `data` is undefined. */
  async function repair(input, options) {
    const operation = operationOptions(options);
    const overwrite = operation.overwrite ?? false;
    if (typeof overwrite !== "boolean") throw new TypeError("overwrite must be a boolean");
    const output = operation.output == null ? undefined : runtime.prepareOutputPath(operation.output);
    const sources = await runtime.prepareArchiveSources(input);
    if (sources.length !== 1) {
      throw new RarError("UNSUPPORTED_FEATURE", "repair currently accepts one archive volume");
    }
    return runtime.request("repair", {
      sources,
      password: operation.password,
      output,
      overwrite,
    }, operation);
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
    repair, isRarFile, isRarFileSfx,
    archiveVersions: ARCHIVE_VERSIONS,
    version: runtime.version,
  };
}
