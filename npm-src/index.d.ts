export type RarFormat =
  | "rar13" | "rar14" | "rar15" | "rar20" | "rar29"
  | "rar30" | "rar40" | "rar50" | "rar70";
export type RarFamily = "rar13" | "rar15_40" | "rar50_plus";
export type RarInput = Blob | ArrayBuffer | ArrayBufferView;
export type RarData = string | RarInput;
export type RarName = string | Uint8Array;

export interface RarProgress {
  operation: "open" | "read" | "test" | "build" | "buildVolumes" | "writeTo" | "writeVolumesTo" | "repair" | "repairDetailed";
  phase: string;
  completed: number;
  total?: number;
}

export interface OperationOptions {
  password?: string | Uint8Array;
  signal?: AbortSignal;
  onProgress?: (progress: RarProgress) => void;
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
  data: Uint8Array;
  report: RepairReport;
}

export interface RarWriterOptions {
  format?: RarFormat;
  level?: 0 | 1 | 2 | 3 | 4 | 5;
  solid?: boolean;
  password?: string | Uint8Array;
  encryptHeaders?: boolean;
  comment?: string | Uint8Array;
  recoveryPercent?: number;
}

export interface RarEntryOptions {
  modifiedAt?: Date;
  mode?: number;
}

export type RarErrorCode =
  | "INVALID_ARCHIVE" | "INVALID_OPTION" | "UNSUPPORTED_FORMAT"
  | "UNSUPPORTED_FEATURE" | "PASSWORD_REQUIRED" | "BAD_PASSWORD"
  | "CHECKSUM_MISMATCH" | "ENTRY_NOT_FOUND" | "ENTRY_IS_DIRECTORY"
  | "DUPLICATE_ENTRY" | "UNSAFE_ENTRY_NAME" | "IO" | "CLOSED"
  | "WORKER_FAILED" | "INTERNAL";

export class RarError extends Error {
  readonly code: RarErrorCode;
  readonly details?: unknown;
}

export class RarEntry {
  private constructor();
  readonly index: number;
  readonly name: string;
  readonly nameBytes: Uint8Array;
  readonly size: number;
  readonly compressedSize: number;
  readonly modifiedAt?: Date;
  readonly crc32?: number;
  readonly isDirectory: boolean;
  readonly isEncrypted: boolean;
  readonly isStored: boolean;
  readonly isSolid: boolean;
  readonly isSplitBefore: boolean;
  readonly isSplitAfter: boolean;
  bytes(options?: OperationOptions): Promise<Uint8Array>;
}

export class RarArchive {
  static open(input: RarInput | readonly RarInput[], options?: OperationOptions): Promise<RarArchive>;
  readonly entries: readonly RarEntry[];
  readonly family: RarFamily;
  readonly sfxOffset: number;
  readonly needsPassword: boolean;
  readonly comment?: Uint8Array;
  get(name: RarName): RarEntry | undefined;
  getAll(name: RarName): readonly RarEntry[];
  test(options?: OperationOptions): Promise<void>;
  close(): void;
}

export class RarWriter {
  constructor(options?: RarWriterOptions);
  readonly names: readonly RarName[];
  add(name: RarName, data: RarData, options?: RarEntryOptions): this;
  remove(name: RarName): this;
  rename(from: RarName, to: RarName): this;
  bytes(options?: OperationOptions): Promise<Uint8Array>;
  volumes(size: number, options?: OperationOptions): Promise<readonly Uint8Array[]>;
  close(): void;
}

export function repair(input: RarInput, options?: OperationOptions): Promise<Uint8Array>;
export function repairDetailed(input: RarInput, options?: OperationOptions): Promise<RepairResult>;
export const version: string;
export const formats: readonly RarFormat[];
