export type ArchiveVersion =
  | "rar13" | "rar14" | "rar15" | "rar20" | "rar29"
  | "rar30" | "rar40" | "rar50" | "rar70";
export type ArchiveFamily = "rar13" | "rar15_40" | "rar50_plus" | "unknown";
export type RarInput = Blob | ArrayBuffer | ArrayBufferView;
export type RarData = string | RarInput;
export type RarName = string | Uint8Array;

export interface RarProgress {
  operation: "open" | "read" | "readMany" | "readComment" | "readMemberComment" | "readLink" | "checkPassword" | "extract" | "test" | "build" | "buildVolumes" | "writeTo" | "repair" | "rewritePlan";
  /** Python's ProgressPhase names, plus "repairing". */
  phase: "reading" | "extracting" | "testing" | "compressing" | "protecting" | "writing" | "repairing";
  /**
   * Bytes. Writing, testing and reading from one archive report as the engine goes;
   * reading selected entries of a volume set and repairing report only start and end.
   */
  completed: number;
  /** Absent while not known yet. */
  total?: number;
}

export interface OperationOptions {
  password?: string | Uint8Array;
  signal?: AbortSignal;
  onProgress?: (progress: RarProgress) => void;
}

/** Options given to `open()` are the defaults for later calls on that archive; a call's own fields override them one by one. Numbers must be safe integers; bigint supports all u64 values. */
export interface ReadOptions extends OperationOptions {
  /**
   * Source encoding for names without Unicode; open() retains the decoded entry view.
   * Use "detect" to guess one encoding from the legacy names across the archive or volume set.
   */
  legacyNameEncoding?:
    | "cp437" | "cp850" | "cp852" | "cp866" | "cp1251" | "cp1252" | "windows-1251" | "windows-1252" | "utf8" | "utf-8"
    | "cp932" | "shift_jis" | "cp936" | "gbk" | "cp949" | "euc-kr" | "cp950" | "big5" | "detect";
  maxHeaderCount?: number | bigint;
  maxHeaderBytes?: number | bigint;
  maxMemberOutputBytes?: number | bigint;
  maxTotalOutputBytes?: number | bigint;
  /** Aggregate reader workspace capacity per call; excludes sources and final output. */
  maxReaderWorkspaceBytes?: number | bigint;
  /** Refuse a compressed RAR 5 member whose dictionary is larger than this. */
  maxRar50DictionaryBytes?: number | bigint;
  /** The largest RAR 5 member decoded whole in memory; larger ones stream. */
  maxRar50BufferedMemberBytes?: number | bigint;
  /**
   * Run RAR 3 VM filter programs other than the six standard ones. Off by
   * default: they are arbitrary bytecode from the archive and can use a lot of
   * CPU time. Members that need one fail with UNSUPPORTED_FEATURE otherwise.
   */
  allowRar3VmPrograms?: boolean;
}

/** Options for `RarArchive.open()`: read options, the later calls' defaults, plus `salvage`. */
export interface OpenOptions extends ReadOptions {
  /**
   * Read what survives of a damaged archive. Off by default, when damage fails the call.
   * Opening reads past damaged headers, listed in `headerDamage`, and lists a member the
   * file is cut short inside, as `truncation` says. A volume set may begin late or end
   * early: the split members it holds only part of are left out and listed in
   * `incompleteMembers`. Every later call on the archive salvages too, so a damaged
   * member's bytes are delivered before its error goes to `onMemberError`, or fails the
   * call without one. It belongs to the archive, so a call can't change it.
   */
  salvage?: boolean;
}

/** Options for calls that can carry on past a member that fails. */
export interface MemberErrorOptions {
  /**
   * Called with each member that fails, instead of failing the call, which carries on
   * with the next. The error is the one the call would have thrown, with `member` set.
   * A member is verified when this was never called for it. A wrong password or an I/O
   * error still fails the call. Throwing from it fails the call with what it threw; the
   * engine runs in a worker and doesn't wait for the callback, so by then it may have
   * gone on to later members. Reads return what was delivered for a failed member:
   * everything decoded before the failure under `salvage`, and nothing otherwise.
   */
  onMemberError?: (error: RarError) => void;
}

/** Where an archive's file ends early. */
export interface Truncation {
  /** The block the file ends in, or the one that was due. */
  block: "member" | "recoveryRecord" | "service" | "comment" | "end" | "unknown";
  /** The stored name of a cut member or service block. */
  name?: Uint8Array;
  /** File offset of that block, in its volume. */
  offset: number;
  /** Whether any of that block is in the file. */
  started: boolean;
  /** Whether the cut can have lost no member: the file ends in or just before a block that only follows the members. */
  membersComplete: boolean;
  /** The volume cut short, counting the first opened as 0. */
  volumeIndex: number;
  /** The library's description. */
  message: string;
}

/** A damaged header that `salvage` read past. */
export interface HeaderDamage {
  /**
   * `checksum`: read as stored though its checksum fails; `droppedRecord`: a malformed
   * optional record was dropped; `unreadable`: the walk stopped there; `resynced`: the
   * walk scanned on to the next header that checks out; `quickOpenCopy`: the member was
   * read from its RAR 5 quick-open copy.
   */
  kind: "checksum" | "droppedRecord" | "unreadable" | "resynced" | "quickOpenCopy";
  /** File offset of the header, in its volume. */
  offset: number;
  /** The volume it is in, counting the first opened as 0. */
  volumeIndex: number;
  /** The library's description. */
  message: string;
}

/** A split member `salvage` left out of a volume set, as part of it is in a volume not given. */
export interface IncompleteMember {
  name: string;
  nameBytes: Uint8Array;
  /** The first volume holding part of it, counting the first opened as 0. */
  volumeIndex: number;
  /** Which ends are in volumes not given. */
  missing: "start" | "end" | "both";
}

export interface RepairReport {
  changed: boolean;
  dataRepaired: boolean;
  recoveryRecordRebuilt: boolean;
  endRecordRebuilt: boolean;
  availableRecoveryShards?: number;
  expectedRecoveryShards?: number;
}

export interface RepairResult {
  /** Undefined when `repair()` wrote it to `output`. */
  data?: Uint8Array;
  report: RepairReport;
}

export interface RarWriterOptions {
  version?: ArchiveVersion;
  level?: 0 | 1 | 2 | 3 | 4 | 5;
  solid?: boolean;
  password?: string | Uint8Array;
  encryptHeaders?: boolean;
  /** Store a BLAKE2sp hash of each member beside its CRC32, like rar's `-htb`. RAR 5 and later. */
  blake2sp?: boolean;
  comment?: string | Uint8Array;
  recoveryPercent?: number;
  /** Hard RAR5/7 managed writer capacity; caller inputs and runtime overhead are excluded. */
  maxMemoryBytes?: number | bigint;
  /** Split into volumes of at most this many bytes; write them with `volumes()` or `writeTo()`. */
  volumeSize?: number;
}

export interface RarEntryOptions {
  /** A Date, or Unix seconds as `fs.utimes` takes them. */
  mtime?: Date | number;
  /** A comment attached to this member. */
  comment?: string | Uint8Array;
  /** Access and creation times, as `mtime` takes them; only RAR 5 keeps them. */
  atime?: Date | number;
  birthtime?: Date | number;
  mode?: number;
}

export type RarErrorCode =
  | "INVALID_ARCHIVE" | "INVALID_OPTION" | "UNSUPPORTED_FORMAT"
  | "UNSUPPORTED_FEATURE" | "PASSWORD_REQUIRED" | "BAD_PASSWORD"
  | "CHECKSUM_MISMATCH"
  /** A volume the set needs wasn't given or found; details carry its `volumeIndex`, counting
   * the first as 0, and the `path` looked for when the set was opened by path. */
  | "MISSING_VOLUME"
  /** A volume came out of order; details carry the `volumeIndex` where the order broke. */
  | "VOLUME_ORDER"
  | "ENTRY_NOT_FOUND" | "ENTRY_IS_DIRECTORY" | "AMBIGUOUS_ENTRY"
  | "DUPLICATE_ENTRY" | "UNSAFE_ENTRY_NAME" | "IO" | "CLOSED"
  | "RESOURCE_LIMIT" | "CANCELLED" | "SOURCE_CHANGED"
  | "WRITE_FAILED" | "WORKER_FAILED" | "INTERNAL"
  /** Salvage only: the file ends partway through the member's data; details carry `packedBytes` and `presentBytes`. */
  | "MEMBER_CUT_SHORT"
  /** Salvage only: the member decodes past its declared size, `declaredBytes` in details, which is what it was given. */
  | "MEMBER_RAN_PAST_DECLARED_SIZE";

export class RarError extends Error {
  readonly code: RarErrorCode;
  /** Core context records retain raw entry-name bytes; byte counts and offsets
   * are decimal strings so values beyond Number.MAX_SAFE_INTEGER remain exact. */
  readonly details?: unknown;
  /** The member that failed, on the errors `onMemberError` is given. */
  readonly member?: string;
}

export class RarEntry {
  private constructor();
  readonly index: number;
  readonly name: string;
  readonly nameBytes: Uint8Array;
  readonly size: number;
  readonly compressedSize: number;
  /** Times named as `fs.Stats` names them; absent where the archive records none. */
  readonly mtime?: Date;
  readonly atime?: Date;
  readonly birthtime?: Date;
  readonly crc32?: number;
  readonly isDirectory: boolean;
  readonly isEncrypted: boolean;
  readonly isStored: boolean;
  readonly isSolid: boolean;
  readonly isSplitBefore: boolean;
  readonly isSplitAfter: boolean;
  /** The volume the entry starts in, counting the first as 0. */
  readonly volumeIndex: number;
  /** Whether the entry is a link, whose target `readLink()` reads. */
  readonly isLink: boolean;
  bytes(options?: ReadOptions & MemberErrorOptions): Promise<Uint8Array>;
  /** The comment attached to this entry, or undefined. */
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  /** The raw target of this link, read from the headers and never followed. */
  readLink(options?: ReadOptions): Promise<Uint8Array>;
  /** Node only: extracts this entry under `directory`, as `archive.extractAll()` does, and returns the path written. */
  extract(directory: string | URL, options?: ReadOptions & { overwrite?: boolean | "rename"; flatten?: boolean; restoreTimes?: boolean; restoreModes?: boolean; skipSymlinks?: boolean }): Promise<string>;
}

export class RarArchive {
  static open(input: RarInput | readonly RarInput[], options?: OpenOptions): Promise<RarArchive>;
  readonly entries: readonly RarEntry[];
  /** Resolved source encoding for legacy names, or null when raw bytes are used. */
  readonly legacyNameEncoding: string | null;
  readonly family: ArchiveFamily;
  readonly sfxOffset: number;
  readonly needsPassword: boolean;
  /** Whether the (first) archive opened is one volume of a set. */
  readonly isVolume: boolean;
  /** Its place in the set, counting the first as 0; undefined when its headers don't record it. */
  readonly volumeIndex?: number;
  /** Whether it starts its set; undefined when its headers can't tell. */
  readonly isFirstVolume?: boolean;
  /** How the set names its volume files. */
  readonly volumeNaming: "part" | "old";
  readonly comment?: Uint8Array;
  /** Where the file ends early, in the first volume that does; undefined when none does. */
  readonly truncation?: Truncation;
  /** The damaged headers `salvage` read past, in file order; always empty without it. */
  readonly headerDamage: readonly HeaderDamage[];
  /** The split members `salvage` left out of a volume set, in archive order. */
  readonly incompleteMembers: readonly IncompleteMember[];
  get(name: RarName): RarEntry | undefined;
  getAll(name: RarName): readonly RarEntry[];
  has(name: RarName): boolean;
  /** One session and shared output budgets; request order and duplicates are retained. */
  /** `onMemberError` can't be combined with a member in a later volume of a set. */
  readMany(members: Iterable<RarEntry | RarName>, options?: ReadOptions & MemberErrorOptions): Promise<Uint8Array[]>;
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  test(options?: ReadOptions & MemberErrorOptions): Promise<void>;
  close(): void;
}

export class RarWriter {
  constructor(options?: RarWriterOptions);
  /**
   * Every member of `archive`, a volume set included, to edit and write again. `preserve`
   * (default true) keeps the source's format, settings and encryption; `false` writes RAR 5
   * at level 3. Data is decoded and verified when written, `maxStagedBytes` at most at once.
   */
  static fromArchive(archive: RarArchive, options?: ReadOptions & { preserve?: boolean; maxStagedBytes?: number }): Promise<RarWriter>;
  readonly names: readonly RarName[];
  add(name: RarName, data: RarData, options?: RarEntryOptions): this;
  /** An explicit, possibly empty directory. */
  addDirectory(name: RarName, options?: RarEntryOptions): this;
  /** A Unix symbolic link to `target`, stored as given and never followed. */
  addSymlink(name: RarName, target: string | Uint8Array, options?: RarEntryOptions & { targetIsDirectory?: boolean }): this;
  remove(name: RarName): this;
  rename(from: RarName, to: RarName): this;
  bytes(options?: OperationOptions): Promise<Uint8Array>;
  volumes(options?: OperationOptions): Promise<readonly Uint8Array[]>;
  close(): void;
}

export interface PasswordCheck<Archive = RarArchive> {
  /** The first candidate proved correct, if any. */
  correct?: string | Uint8Array;
  /** Candidates the archive couldn't prove right or wrong without decoding data. */
  undetermined: (string | Uint8Array)[];
  needsPassword: boolean;
  /** Opened with `correct`, or without a password when the headers aren't encrypted. */
  archive?: Archive;
}

/** Tries candidates in order against one volume, stopping at the first proved correct. */
export function checkPassword(
  input: RarInput,
  candidates: Iterable<string | Uint8Array>,
  options?: OpenOptions,
): Promise<PasswordCheck>;
export function repair(input: RarInput, options?: OperationOptions): Promise<RepairResult>;
/** Whether the input starts with a RAR signature. */
export function isRarFile(input: RarInput): Promise<boolean>;
/** Whether a RAR archive starts in the input, at its start or behind a self-extractor stub. */
export function isRarFileSfx(input: RarInput): Promise<boolean>;
export const version: string;
export const archiveVersions: readonly ArchiveVersion[];
