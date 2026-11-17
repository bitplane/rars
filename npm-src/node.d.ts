export * from "./base.js";
import type {
  OperationOptions, ReadOptions, RarData, RarEntryOptions, RarInput, RarName,
  RarWriterOptions,
} from "./base.js";

export type NodeRarInput = RarInput | string | URL;
export type NodePath = string | URL;

export class RarArchive {
  static open(input: NodeRarInput | readonly NodeRarInput[], options?: ReadOptions): Promise<RarArchive>;
  readonly entries: readonly import("./base.js").RarEntry[];
  readonly family: import("./base.js").ArchiveFamily;
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
  /** The files opened, when opened from paths: a first volume's path brings the later ones found beside it. */
  readonly volumePaths?: readonly string[];
  readonly comment?: Uint8Array;
  get(name: RarName): import("./base.js").RarEntry | undefined;
  getAll(name: RarName): readonly import("./base.js").RarEntry[];
  has(name: RarName): boolean;
  /** One session and shared output budgets; request order and duplicates are retained. */
  readMany(
    members: Iterable<import("./base.js").RarEntry | RarName>,
    options?: ReadOptions,
  ): Promise<Uint8Array[]>;
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  test(options?: ReadOptions): Promise<void>;
  /**
   * Extracts entries under `directory` in one pass and returns the files written. Each is
   * written only once verified. `overwrite` is false (refuse an existing file), true, or
   * "rename" (write beside it as name(N).ext); `flatten` drops stored directories;
   * `restoreTimes` (default true) sets modification times. Links are skipped.
   */
  extractAll(directory: NodePath, options?: ReadOptions & {
    members?: Iterable<import("./base.js").RarEntry | RarName>;
    overwrite?: boolean | "rename";
    flatten?: boolean;
    restoreTimes?: boolean;
  }): Promise<readonly string[]>;
  close(): void;
}

export class RarWriter {
  constructor(options?: RarWriterOptions);
  readonly names: readonly RarName[];
  add(name: RarName, data: RarData, options?: RarEntryOptions): this;
  addFile(name: RarName, path: NodePath, options?: RarEntryOptions): this;
  /** An explicit, possibly empty directory. */
  addDirectory(name: RarName, options?: RarEntryOptions): this;
  /** A Unix symbolic link to `target`, stored as given and never followed. */
  addSymlink(name: RarName, target: string | Uint8Array, options?: RarEntryOptions & { targetIsDirectory?: boolean }): this;
  remove(name: RarName): this;
  rename(from: RarName, to: RarName): this;
  bytes(options?: OperationOptions): Promise<Uint8Array>;
  volumes(options?: OperationOptions): Promise<readonly Uint8Array[]>;
  /**
   * Writes the archive, or with `volumeSize` every part of the set, and returns the paths
   * written. An existing file is refused unless `overwrite: true`; a set checks every part
   * before writing any.
   */
  writeTo(path: NodePath, options?: OperationOptions & { overwrite?: boolean }): Promise<readonly string[]>;
  close(): void;
}

/**
 * With `output`, the repaired archive is written there and `data` is undefined; an
 * existing file is refused unless `overwrite: true`.
 */
/** Tries candidates in order against one volume, stopping at the first proved correct. */
export function checkPassword(
  input: NodeRarInput,
  candidates: Iterable<string | Uint8Array>,
  options?: ReadOptions,
): Promise<import("./base.js").PasswordCheck<RarArchive>>;
/** Whether the input starts with a RAR signature; an unreadable path is not RAR. */
export function isRarFile(input: NodeRarInput): Promise<boolean>;
/** Whether a RAR archive starts in the input, at its start or behind a self-extractor stub. */
export function isRarFileSfx(input: NodeRarInput): Promise<boolean>;
export function repair(
  input: NodeRarInput,
  options?: OperationOptions & { output?: NodePath; overwrite?: boolean },
): Promise<import("./base.js").RepairResult>;
