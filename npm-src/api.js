const ARCHIVE_VERSIONS = Object.freeze([
  "rar13", "rar14", "rar15", "rar20", "rar29",
  "rar30", "rar40", "rar50", "rar70",
]);

// Unknown keys are refused, so a misspelt or renamed setting can't be silently ignored.
const WRITER_OPTIONS = Object.freeze([
  "version", "level", "solid", "password", "encryptHeaders", "blake2sp", "comment",
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
      if (typeof encoding !== "string" || ![
        "cp437", "cp850", "cp852", "cp866", "cp1251", "cp1252", "windows-1251", "windows-1252", "utf8", "utf-8",
        "cp932", "shift_jis", "shift-jis", "sjis", "windows-31j", "cp936", "gbk", "cp949", "euc-kr", "uhc", "cp950", "big5", "detect", "auto",
      ].includes(encoding.toLowerCase())) {
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
    if (options.salvage != null) {
      if (typeof options.salvage !== "boolean") {
        throw new RarError("INVALID_OPTION", "salvage must be a boolean");
      }
      limits.salvage = options.salvage;
    }
    return limits;
  }

  /** A call's `onMemberError`, checked before any work starts. */
  function memberErrorCallback(operation) {
    const callback = operation.onMemberError;
    if (callback != null && typeof callback !== "function") {
      throw new TypeError("onMemberError must be a function");
    }
    return callback ?? undefined;
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
      memberErrorCallback(operation);
      return this._archive._request("read", {
        index: this.index,
        readOptions: this._archive._readOptions(operation),
        password: operation.password ?? this._archive._password,
      }, operation);
    }

    /** Extracts this entry under `directory` (Node) and returns the path written. */
    async extract(directory, options) {
      if (this.isDirectory) {
        throw new RarError("ENTRY_IS_DIRECTORY", `cannot extract directory entry as a file: ${this.name}`);
      }
      const [written] = await this._archive.extractAll(directory, { ...options, members: [this] });
      if (written === undefined) throw new RarError("ENTRY_NOT_FOUND", `${this.name} has no file data`);
      return written;
    }

    /** The raw target of this link, read from the headers and never followed; Python's readlink(). */
    async readLink(options) {
      assertOpen(this._archive);
      if (!this.isLink) throw new RarError("INVALID_OPTION", `${this.name} is not a link`);
      const operation = operationOptions(options);
      return this._archive._request("readLink", {
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
    #legacyNameEncoding;

    get legacyNameEncoding() {
      return this.#legacyNameEncoding;
    }

    static async open(input, options) {
      const operation = operationOptions(options);
      const sources = await runtime.prepareArchiveSources(input);
      const result = await runtime.request("open", {
        sources,
        readOptions: readOptions(operation),
        password: operation.password,
      }, operation);
      // A path to a set's first volume comes back with the later volumes found beside it.
      return new RarArchive(result.sources ?? sources, operation.password, result, readOptions(operation));
    }

    constructor(sources, password, metadata, defaults) {
      this._defaults = defaults;
      this.#legacyNameEncoding = metadata.legacyNameEncoding ?? null;
      this._sources = sources;
      // The volume a set opened by path stopped short of, to name if it turns out missing.
      this._volumeNotFound = metadata.volumeNotFound;
      if (sources.every((source) => source?.kind === "path")) {
        this.volumePaths = Object.freeze(sources.map((source) => source.path));
      }
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
      // What salvage read past or left out; see ReadOptions.salvage.
      this.truncation = metadata.truncation === undefined ? undefined : Object.freeze(metadata.truncation);
      this.headerDamage = Object.freeze((metadata.headerDamage ?? []).map(Object.freeze));
      this.incompleteMembers = Object.freeze((metadata.incompleteMembers ?? []).map(Object.freeze));
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

    /**
     * Options given to open() are defaults; a call's own fields override them one by one,
     * except `salvage`, which is the archive's: its parsing and every call read with it.
     */
    _readOptions(operation) {
      const call = readOptions(operation);
      if (call.salvage !== undefined && call.salvage !== (this._defaults.salvage ?? false)) {
        throw new RarError("INVALID_OPTION", "salvage is chosen when the archive is opened");
      }
      return { ...this._defaults, ...call };
    }

    _request(operation, payload, options) {
      assertOpen(this);
      return runtime.request(operation,
        { sources: this._sources, volumeNotFound: this._volumeNotFound, ...payload }, options);
    }

    /**
     * Runs `operation` with the set's later volumes pulled from `volumes` as the engine
     * reaches them, rather than those this archive was opened with, as Python's `volumes=`.
     */
    async _withVolumes(operation, payload, options) {
      if (options.volumes === undefined) return this._request(operation, payload, options);
      if (this._defaults.salvage) {
        throw new RarError("INVALID_OPTION",
          "an archive opened with salvage reads the volumes it was opened with; give every volume to open()");
      }
      if (!runtime.volumeFeed) {
        throw new RarError("UNSUPPORTED_FEATURE",
          "volumes as they arrive need Node; open the archive with every volume instead");
      }
      const feed = runtime.volumeFeed(options.volumes);
      try {
        return await this._request(operation, {
          ...payload, sources: this._sources.slice(0, 1), volumeFeed: feed.channel,
        }, { ...options, transfer: feed.transfer });
      } catch (error) {
        throw feed.failure ?? error;
      } finally {
        feed.close();
      }
    }

    get(name) {
      const matches = this.#matchingEntries(name, false);
      if (this.legacyNameEncoding !== null && typeof name === "string"
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
      memberErrorCallback(operation);
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

    /**
     * Extracts entries under `directory` (Node) in one pass and returns the files written.
     * `members` selects some; `overwrite` is false (refuse), true or "rename" (name(N).ext);
     * `flatten` drops stored directories; `restoreTimes` (default true) sets modification times.
     * `onMemberError` carries on past members that fail, writing none of their output, unless
     * `keepBroken`, which needs `salvage`, keeps what was delivered for each.
     */
    async extractAll(directory, options) {
      assertOpen(this);
      const operation = operationOptions(options);
      const overwrite = operation.overwrite ?? false;
      if (overwrite !== true && overwrite !== false && overwrite !== "rename") {
        throw new TypeError('overwrite must be true, false or "rename"');
      }
      const onMemberError = memberErrorCallback(operation);
      const keepBroken = operation.keepBroken ?? false;
      if (typeof keepBroken !== "boolean") throw new TypeError("keepBroken must be a boolean");
      if (keepBroken && !this._defaults.salvage) {
        throw new RarError("INVALID_OPTION", "keepBroken needs an archive opened with salvage: true");
      }
      if (keepBroken && onMemberError === undefined) {
        throw new RarError("INVALID_OPTION", "keepBroken needs onMemberError, which reports each member kept");
      }
      if (operation.members !== undefined && onMemberError !== undefined) {
        // Selection counts the outputs opened, which a member failing before its output would upset.
        throw new RarError("INVALID_OPTION",
          "onMemberError reads every member, so it can't be combined with members");
      }
      let indices;
      if (operation.members !== undefined) {
        indices = [];
        for (const member of operation.members) {
          const entry = member instanceof RarEntry ? member : this.get(member);
          if (!entry) throw new RarError("ENTRY_NOT_FOUND", "no such archive entry");
          if (entry._archive !== this) {
            throw new RarError("INVALID_OPTION", "entry belongs to a different archive");
          }
          indices.push(entry.index);
        }
      }
      const { written, skipped } = await this._withVolumes("extract", {
        directory: runtime.prepareOutputPath(directory),
        indices,
        overwrite,
        flatten: operation.flatten ?? false,
        restoreTimes: operation.restoreTimes ?? true,
        keepBroken,
        readOptions: this._readOptions(operation),
        password: operation.password ?? this._password,
      }, operation);
      // A link that could lead out of the directory is skipped, as Python warns with UnsafeLinkWarning.
      for (const link of skipped) {
        globalThis.process?.emitWarning?.(
          `skipped link ${link.name} -> ${link.target}: it could lead outside the output directory`,
          "UnsafeLinkWarning");
      }
      return written;
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
      memberErrorCallback(operation);
      await this._withVolumes("test", {
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
    for (const key of ["solid", "encryptHeaders", "blake2sp"]) {
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
      if (!["rar29", "rar30", "rar40", "rar50", "rar70"].includes(version)) {
        throw invalid(`${version} cannot write header encryption`);
      }
    }
    if (options.blake2sp && !modern) {
      throw invalid(`${version} cannot write BLAKE2sp file hashes`);
    }
    if (options.volumeSize !== undefined) {
      if (!Number.isSafeInteger(options.volumeSize)) {
        throw new TypeError("volumeSize must be a safe integer");
      }
      if (options.volumeSize <= 0) throw invalid("volumeSize must be more than 0");
      if (options.comment != null && !["rar29", "rar30", "rar40"].includes(version)) {
        throw invalid(`${version} cannot write an archive comment in a volume set`);
      }
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
    // As fs.utimes takes them: a Date, or a number of Unix seconds.
    const seconds = (key) => {
      const value = options[key] instanceof Date ? options[key].valueOf() / 1000 : options[key];
      if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
        throw new TypeError(`${key} must be a valid Date or a number of Unix seconds`);
      }
      return value;
    };
    const mtime = seconds("mtime");
    if (options.mode !== undefined &&
        (!Number.isSafeInteger(options.mode) || options.mode < 0)) {
      throw new TypeError("mode must be a non-negative safe integer");
    }
    if (options.comment !== undefined && typeof options.comment !== "string"
        && !(options.comment instanceof Uint8Array)) {
      throw new TypeError("comment must be a string or Uint8Array");
    }
    if (options.targetIsDirectory !== undefined && typeof options.targetIsDirectory !== "boolean") {
      throw new TypeError("targetIsDirectory must be a boolean");
    }
    // Access and creation times are kept by RAR 5 only; older versions refuse them.
    return {
      mtime,
      atime: seconds("atime"),
      birthtime: seconds("birthtime"),
      mode: options.mode,
      comment: options.comment,
      targetIsDirectory: options.targetIsDirectory,
    };
  }

  class RarWriter {
    constructor(options) {
      this._options = validateWriterOptions(options);
      this._entries = [];
      this._closed = false;
    }

    /**
     * A writer holding every member of `archive`, a volume set included, to edit and write
     * again, as Python's RarBuilder.from_archive(). `preserve` (default true) keeps the
     * source's format, settings and encryption, and refuses one whose settings can't be
     * kept; `preserve: false` writes RAR 5 at level 3. Members' data is decoded and
     * verified when the archive is written, so the source must still be readable then;
     * `maxStagedBytes` caps the decoded data held at once.
     */
    static async fromArchive(archive, options) {
      if (!(archive instanceof RarArchive)) throw new TypeError("archive must be a RarArchive");
      assertOpen(archive);
      const operation = operationOptions(options);
      const preserve = options?.preserve ?? true;
      if (typeof preserve !== "boolean") throw new TypeError("preserve must be a boolean");
      const maxStagedBytes = options?.maxStagedBytes;
      if (maxStagedBytes !== undefined && !(Number.isSafeInteger(maxStagedBytes) && maxStagedBytes >= 0)) {
        throw new RangeError("maxStagedBytes must be a non-negative safe integer");
      }
      const rewrite = {
        sources: archive._sources,
        password: operation.password ?? archive._password,
        readOptions: archive._readOptions(operation),
        preserve,
        maxStagedBytes,
      };
      const plan = await runtime.request("rewritePlan", { rewrite }, operation);
      const writer = new RarWriter();
      writer._rewrite = rewrite;
      const utf8 = new TextDecoder("utf-8", { fatal: true });
      writer._entries = plan.names.map((stored, index) => {
        let name;
        try { name = utf8.decode(stored); } catch { name = Uint8Array.from(stored); }
        return { name, kind: "archived", id: plan.ids[index], stored };
      });
      return writer;
    }

    add(name, data, options) {
      assertOpen(this);
      return this.#queue({
        name: validateName(name),
        data: runtime.prepareEntryData(data),
        options: validateEntryOptions(options),
      });
    }

    /** Queues an explicit, possibly empty directory. */
    addDirectory(name, options) {
      assertOpen(this);
      return this.#queue({ name: validateName(name), kind: "directory", options: validateEntryOptions(options) });
    }

    /** Queues a Unix symbolic link to `target`, stored as given and never followed. */
    addSymlink(name, target, options) {
      assertOpen(this);
      if (!((typeof target === "string" || target instanceof Uint8Array) && target.length > 0)) {
        throw new TypeError("link target must be a non-empty string or Uint8Array");
      }
      return this.#queue({
        name: validateName(name), kind: "symlink",
        target: typeof target === "string" ? target : Uint8Array.from(target),
        options: validateEntryOptions(options),
      });
    }

    #queue(entry) {
      if (this._entries.some((queued) => sameName(queued.name, entry.name))) {
        throw new RarError("DUPLICATE_ENTRY", "duplicate archive entry name");
      }
      this._entries.push(entry);
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
        rewrite: this._rewrite,
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
      this._rewrite = undefined;
    }
  }

  /**
   * Tries `candidates` in order against one volume and stops at the first proved
   * correct, as Python's check_password(). `archive` is opened with it, or without one
   * when the headers aren't encrypted; it is undefined only when they are and no
   * candidate opened them.
   */
  async function checkPassword(input, candidates, options) {
    const operation = operationOptions(options);
    const list = Array.from(candidates);
    for (const candidate of list) {
      if (typeof candidate !== "string" && !(candidate instanceof Uint8Array)) {
        throw new TypeError("each candidate must be a string or Uint8Array");
      }
    }
    const [source] = await runtime.prepareArchiveSources(input);
    const found = await runtime.request("checkPassword", {
      sources: [source], candidates: list, readOptions: readOptions(operation),
    }, operation);
    const correct = found.correct === undefined ? undefined : list[found.correct];
    const archive = correct !== undefined || !found.headersEncrypted
      ? await RarArchive.open(input, { ...operation, password: correct })
      : undefined;
    return {
      correct,
      undetermined: found.undetermined.map((index) => list[index]),
      needsPassword: found.needsPassword,
      archive,
    };
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
    const rarError = new RarError(error?.code ?? "INTERNAL", error?.message ?? String(error), error?.details);
    // Set on the errors onMemberError is given: the name of the member that failed.
    if (error?.member !== undefined) rarError.member = error.member;
    return rarError;
  });

  return {
    RarArchive,
    RarEntry,
    RarError,
    RarWriter,
    repair, isRarFile, isRarFileSfx, checkPassword,
    archiveVersions: ARCHIVE_VERSIONS,
    version: runtime.version,
  };
}
