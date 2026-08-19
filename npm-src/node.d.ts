export * from "./base.js";
import type {
  OperationOptions, RarData, RarEntryOptions, RarInput, RarName,
  RarWriterOptions,
} from "./base.js";

export type NodeRarInput = RarInput | string | URL;
export type NodePath = string | URL;

export class RarArchive {
  static open(input: NodeRarInput | readonly NodeRarInput[], options?: OperationOptions): Promise<RarArchive>;
  readonly entries: readonly import("./base.js").RarEntry[];
  readonly family: import("./base.js").RarFamily;
  readonly sfxOffset: number;
  readonly needsPassword: boolean;
  readonly comment?: Uint8Array;
  get(name: RarName): import("./base.js").RarEntry | undefined;
  getAll(name: RarName): readonly import("./base.js").RarEntry[];
  test(options?: OperationOptions): Promise<void>;
  close(): void;
}

export class RarWriter {
  constructor(options?: RarWriterOptions);
  readonly names: readonly RarName[];
  add(name: RarName, data: RarData, options?: RarEntryOptions): this;
  addFile(name: RarName, path: NodePath, options?: RarEntryOptions): this;
  remove(name: RarName): this;
  rename(from: RarName, to: RarName): this;
  bytes(options?: OperationOptions): Promise<Uint8Array>;
  volumes(size: number, options?: OperationOptions): Promise<readonly Uint8Array[]>;
  writeTo(path: NodePath, options?: OperationOptions): Promise<void>;
  writeVolumesTo(path: NodePath, size: number, options?: OperationOptions): Promise<readonly string[]>;
  close(): void;
}

export function repair(input: NodeRarInput, options?: OperationOptions): Promise<Uint8Array>;
export function repairDetailed(input: NodeRarInput, options?: OperationOptions): Promise<import("./base.js").RepairResult>;
