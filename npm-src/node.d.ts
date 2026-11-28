export * from "./base.js";
import type {
  MemberErrorOptions, OpenOptions, OperationOptions, ReadOptions, RarData, RarEntryOptions,
  RarInput, RarName, RarWriterOptions,
} from "./base.js";

export type NodeRarInput = RarInput | string | URL;
/** A set's later volumes, in order: what Python takes as `volumes=`. */
export type VolumeSource = Iterable<NodeRarInput> | AsyncIterable<NodeRarInput>;
export type NodePath = string | URL;

export class RarArchive {
  /** With `salvage`, a first volume's path brings the later volumes found beside it until one is missing. */
  static open(input: NodeRarInput | readonly NodeRarInput[], options?: OpenOptions): Promise<RarArchive>;
  readonly entries: readonly import("./base.js").RarEntry[];
  /** Resolved source encoding for legacy names, or null when raw bytes are used. */
  readonly legacyNameEncoding: string | null;
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
  /** Where the file ends early, in the first volume that does; undefined when none does. */
  readonly truncation?: import("./base.js").Truncation;
  /** The damaged headers `salvage` read past, in file order; always empty without it. */
  readonly headerDamage: readonly import("./base.js").HeaderDamage[];
  /** The split members `salvage` left out of a volume set, in archive order. */
  readonly incompleteMembers: readonly import("./base.js").IncompleteMember[];
  get(name: RarName): import("./base.js").RarEntry | undefined;
  getAll(name: RarName): readonly import("./base.js").RarEntry[];
  has(name: RarName): boolean;
  /**
   * One session and shared output budgets; request order and duplicates are retained.
   * `onMemberError` can't be combined with a member in a later volume of a set.
   */
  readMany(
    members: Iterable<import("./base.js").RarEntry | RarName>,
    options?: ReadOptions & MemberErrorOptions,
  ): Promise<Uint8Array[]>;
  readComment(options?: ReadOptions): Promise<Uint8Array | undefined>;
  /**
   * `volumes` gives the set's later parts, paths or bytes, pulled one at a time as the
   * engine reaches them, so a set can be checked while it is still arriving; not on an
   * archive opened with `salvage`, which reads the volumes it was opened with.
   */
  test(options?: ReadOptions & MemberErrorOptions & { volumes?: VolumeSource }): Promise<void>;
  /**
   * Extracts entries under `directory` in one pass and returns the files written. Each is
   * written only once verified. `overwrite` is false (refuse an existing file), true, or
   * "rename" (write beside it as name(N).ext); `flatten` drops stored directories;
   * `restoreTimes` (default true) sets modification times. `restoreModes` (default true)
   * sets the Unix modes the archive records, and 0o444 on a DOS read-only file; off Windows
   * only. Links are written too; one that could lead outside `directory` is skipped with an
   * `UnsafeLinkWarning` process warning. `skipSymlinks` leaves symlinks and junctions out,
   * without a warning; a hard link or copy to one fails.
   * `volumes` gives the set's later parts as they arrive, as for `test()`.
   *
   * `onMemberError` carries on past members that fail and writes none of their output; it
   * can't be combined with `members`. `keepBroken`, on an archive opened with `salvage` and
   * with `onMemberError`, keeps each failed member's file under its own name, holding what
   * was delivered for it, unless it failed on its password.
   */
  extractAll(directory: NodePath, options?: ReadOptions & MemberErrorOptions & {
    keepBroken?: boolean;
    volumes?: VolumeSource;
    members?: Iterable<import("./base.js").RarEntry | RarName>;
    overwrite?: boolean | "rename";
    flatten?: boolean;
    restoreTimes?: boolean;
    restoreModes?: boolean;
    skipSymlinks?: boolean;
  }): Promise<readonly string[]>;
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
  options?: OpenOptions,
): Promise<import("./base.js").PasswordCheck<RarArchive>>;
/** Whether the input starts with a RAR signature; an unreadable path is not RAR. */
export function isRarFile(input: NodeRarInput): Promise<boolean>;
/** Whether a RAR archive starts in the input, at its start or behind a self-extractor stub. */
export function isRarFileSfx(input: NodeRarInput): Promise<boolean>;
export function repair(
  input: NodeRarInput,
  options?: OperationOptions & { output?: NodePath; overwrite?: boolean },
): Promise<import("./base.js").RepairResult>;
