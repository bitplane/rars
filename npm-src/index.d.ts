export type ArchiveVersion =
  | "rar13" | "rar14" | "rar15" | "rar20" | "rar29"
  | "rar30" | "rar40" | "rar50" | "rar70";
export type ArchiveFamily = "rar13" | "rar15_40" | "rar50_plus" | "unknown";
export type RarInput = Blob | ArrayBuffer | ArrayBufferView;
export type RarData = string | RarInput;
export type RarName = string | Uint8Array;

export interface RarProgress {
  operation: "open" | "read" | "readMany" | "readComment" | "readMemberComment" | "checkPassword" | "extract" | "test" | "build" | "buildVolumes" | "writeTo" | "repair";
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
  /** Source encoding for names without Unicode; open() retains the decoded entry view. */
  legacyNameEncoding?: "cp437" | "cp850" | "cp852" | "cp866" | "cp1251" | "cp1252" | "windows-1251" | "windows-1252" | "utf8" | "utf-8";
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
  mode?: number;
}

export type RarErrorCode =
  | "INVALID_ARCHIVE" | "INVALID_OPTION" | "UNSUPPORTED_FORMAT"
  | "UNSUPPORTED_FEATURE" | "PASSWORD_REQUIRED" | "BAD_PASSWORD"
  | "CHECKSUM_MISMATCH" | "MISSING_VOLUME" | "ENTRY_NOT_FOUND" | "ENTRY_IS_DIRECTORY"
  | "AMBIGUOUS_ENTRY"
  | "DUPLICATE_ENTRY" | "UNSAFE_ENTRY_NAME" | "IO" | "CLOSED"
  | "RESOURCE_LIMIT" | "CANCELLED" | "SOURCE_CHANGED"
  | "WRITE_FAILED" | "WORKER_FAILED" | "INTERNAL";

export class RarError extends Error {
  readonly code: RarErrorCode;
  /** Core context records retain raw entry-name bytes; byte counts and offsets
   * are decimal strings so values beyond Number.MAX_SAFE_INTEGER remain exact. */
  readonly details?: unknown;
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
  bytes(options?: ReadOptions): Promise<Uint8Array>;
  /** The comment attached to this entry, or undefined. */
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  /** Node only: extracts this entry under `directory`, as `archive.extractAll()` does, and returns the path written. */
  extract(directory: string | URL, options?: ReadOptions & { overwrite?: boolean | "rename"; flatten?: boolean; restoreTimes?: boolean }): Promise<string>;
}

export class RarArchive {
  static open(input: RarInput | readonly RarInput[], options?: ReadOptions): Promise<RarArchive>;
  readonly entries: readonly RarEntry[];
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
  get(name: RarName): RarEntry | undefined;
  getAll(name: RarName): readonly RarEntry[];
  has(name: RarName): boolean;
  /** One session and shared output budgets; request order and duplicates are retained. */
  readMany(members: Iterable<RarEntry | RarName>, options?: ReadOptions): Promise<Uint8Array[]>;
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  test(options?: ReadOptions): Promise<void>;
  close(): void;
}

export class RarWriter {
  constructor(options?: RarWriterOptions);
  readonly names: readonly RarName[];
  add(name: RarName, data: RarData, options?: RarEntryOptions): this;
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
  options?: ReadOptions,
): Promise<PasswordCheck>;
export function repair(input: RarInput, options?: OperationOptions): Promise<RepairResult>;
/** Whether the input starts with a RAR signature. */
export function isRarFile(input: RarInput): Promise<boolean>;
/** Whether a RAR archive starts in the input, at its start or behind a self-extractor stub. */
export function isRarFileSfx(input: RarInput): Promise<boolean>;
export const version: string;
export const archiveVersions: readonly ArchiveVersion[];
