import os
from collections.abc import Callable, Iterable, Iterator
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import IO, Final, Literal, Protocol, final

from typing_extensions import Buffer, Self, TypeAlias

__all__ = [
    "RarFile",
    "RarInfo",
    "RarBuilder",
    "ProgressEvent",
    "CancellationToken",
    "ReadOptions",
    "ArchiveVersion",
    "ArchiveFamily",
    "VolumeNaming",
    "AttributeKind",
    "ProgressPhase",
    "WriterResources",
    "RepairReport",
    "RepairResult",
    "PasswordCheck",
    "check_password",
    "is_rarfile",
    "is_rarfile_sfx",
    "repair",
    "Error",
    "BadRarFile",
    "BadPassword",
    "PasswordRequired",
    "MissingVolume",
    "ChecksumError",
    "UnsupportedRarFeature",
    "NotRarFile",
    "UnsafeArchivePath",
    "LimitExceeded",
    "UnsafeLinkWarning",
    "Cancelled",
    "RAR13",
    "RAR14",
    "RAR15",
    "RAR20",
    "RAR29",
    "RAR30",
    "RAR40",
    "RAR50",
    "RAR70",
]

class _BinaryReader(Protocol):
    def read(self, size: int = ..., /) -> bytes: ...

_StrPath: TypeAlias = str | os.PathLike[str]
_Source: TypeAlias = Buffer | _StrPath | _BinaryReader
_Password: TypeAlias = str | bytes
_Member: TypeAlias = RarInfo | str | bytes
_NewName: TypeAlias = str | bytes
_Overwrite: TypeAlias = bool | Literal["rename"]
_Progress: TypeAlias = Callable[[ProgressEvent], object]

class ArchiveVersion(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    RAR13 = "rar13"
    RAR14 = "rar14"
    RAR15 = "rar15"
    RAR20 = "rar20"
    RAR29 = "rar29"
    RAR30 = "rar30"
    RAR40 = "rar40"
    RAR50 = "rar50"
    RAR70 = "rar70"

class ArchiveFamily(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    RAR13 = "rar13"
    RAR15_40 = "rar15_40"
    RAR50_PLUS = "rar50_plus"
    UNKNOWN = "unknown"

class VolumeNaming(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    PART = "part"
    OLD = "old"

class AttributeKind(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    DOS = "dos"
    UNIX = "unix"
    UNKNOWN = "unknown"

class ProgressPhase(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    READING = "reading"
    EXTRACTING = "extracting"
    TESTING = "testing"
    STAGING = "staging"
    COMPRESSION = "compression"
    RECOVERY = "recovery"
    WRITING = "writing"

RAR13: Final = ArchiveVersion.RAR13
RAR14: Final = ArchiveVersion.RAR14
RAR15: Final = ArchiveVersion.RAR15
RAR20: Final = ArchiveVersion.RAR20
RAR29: Final = ArchiveVersion.RAR29
RAR30: Final = ArchiveVersion.RAR30
RAR40: Final = ArchiveVersion.RAR40
RAR50: Final = ArchiveVersion.RAR50
RAR70: Final = ArchiveVersion.RAR70

class Error(Exception): ...

class BadRarFile(Error):
    """The archive is damaged or malformed."""

class BadPassword(Error): ...
class PasswordRequired(Error): ...

class MissingVolume(Error):
    volume_number: int | None
    path: Path | None

class ChecksumError(BadRarFile):
    member: str | None
    volume_number: int | None

class UnsupportedRarFeature(Error): ...
class NotRarFile(Error): ...
class UnsafeArchivePath(Error): ...

class LimitExceeded(Error):
    """A configured limit refused the archive or the write."""
class UnsafeLinkWarning(UserWarning): ...

class Cancelled(Exception):
    """A CancellationToken or progress callback stopped the call. Not a rars.Error."""

@final
class ProgressEvent:
    @property
    def phase(self) -> ProgressPhase: ...
    @property
    def completed(self) -> int: ...
    @property
    def total(self) -> int: ...
    @property
    def pass_number(self) -> int: ...
    @property
    def entry_name(self) -> bytes | None: ...
    @property
    def entry_index(self) -> int | None: ...
    @property
    def total_entries(self) -> int | None: ...
    @property
    def volume_number(self) -> int | None: ...
    @property
    def percentage(self) -> float | None: ...

@final
class CancellationToken:
    def __new__(cls) -> Self: ...
    def cancel(self) -> None: ...
    def is_cancelled(self) -> bool: ...

@final
class ReadOptions:
    def __new__(
        cls,
        *,
        max_member_output_bytes: int | None = None,
        max_total_output_bytes: int | None = None,
        max_reader_workspace_bytes: int | None = None,
        rar50_dictionary_size_limit: int | None = None,
        rar50_buffered_decode_limit: int | None = None,
        max_header_count: int | None = None,
        max_header_bytes: int | None = None,
        legacy_name_encoding: str | None = None,
        allow_rar3_vm_programs: bool = False,
        threads: int | None = None,
    ) -> Self: ...
    @property
    def max_member_output_bytes(self) -> int | None: ...
    @property
    def max_total_output_bytes(self) -> int | None: ...
    @property
    def max_reader_workspace_bytes(self) -> int | None: ...
    @property
    def rar50_dictionary_size_limit(self) -> int | None: ...
    @property
    def rar50_buffered_decode_limit(self) -> int | None: ...
    @property
    def max_header_count(self) -> int | None: ...
    @property
    def max_header_bytes(self) -> int | None: ...
    @property
    def legacy_name_encoding(self) -> str | None: ...
    @property
    def allow_rar3_vm_programs(self) -> bool: ...
    @property
    def threads(self) -> int | None: ...

@final
class WriterResources:
    def __new__(
        cls,
        *,
        max_memory: int | None = None,
    ) -> Self: ...
    @property
    def max_memory(self) -> int | None: ...

@final
class RarInfo:
    @property
    def member_index(self) -> int: ...
    @property
    def filename(self) -> str: ...
    @property
    def orig_filename_bytes(self) -> bytes: ...
    @property
    def file_size(self) -> int: ...
    @property
    def compress_size(self) -> int: ...
    @property
    def date_time(self) -> tuple[int, int, int, int, int, int] | None: ...
    @property
    def CRC(self) -> int | None: ...
    @property
    def host_os(self) -> int | None:
        """The stored host number. RAR 5 numbers hosts differently from RAR 1.5 to 4.x; use file_attr_kind."""
    @property
    def file_attr_kind(self) -> AttributeKind: ...
    @property
    def is_encrypted(self) -> bool: ...
    @property
    def is_solid(self) -> bool: ...
    @property
    def is_split_before(self) -> bool: ...
    @property
    def is_split_after(self) -> bool: ...
    @property
    def family(self) -> ArchiveFamily: ...
    @property
    def file_attr(self) -> int: ...
    @property
    def volume_number(self) -> int: ...
    def is_dir(self) -> bool: ...

@final
class RarFile:
    def __new__(
        cls,
        source: _Source,
        mode: Literal["r"] = "r",
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
        first_volume_only: bool = False,
        volumes: list[_Source] | tuple[_Source, ...] | None = None,
    ) -> Self: ...
    def namelist(self) -> list[str]: ...
    def infolist(self) -> list[RarInfo]: ...
    def getinfo(self, name: _Member) -> RarInfo: ...
    def read(
        self,
        name: _Member,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
    ) -> bytes: ...
    def open(
        self,
        name: _Member,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
    ) -> IO[bytes]: ...
    def read_many(
        self,
        members: Iterable[_Member],
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
    ) -> list[bytes]: ...
    def extract(
        self,
        member: _Member,
        path: _StrPath | None = None,
        *,
        password: _Password | None = None,
        overwrite: _Overwrite = ...,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
        restore_times: bool = True,
        in_place: bool = False,
        flatten: bool = False,
    ) -> Path: ...
    def extractall(
        self,
        path: _StrPath | None = None,
        members: Iterable[_Member] | None = None,
        *,
        password: _Password | None = None,
        overwrite: _Overwrite = ...,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
        restore_times: bool = True,
        in_place: bool = False,
        flatten: bool = False,
    ) -> list[Path]: ...
    def testrar(
        self,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
    ) -> None: ...
    @property
    def comment(self) -> bytes | None: ...
    def read_comment(
        self,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
    ) -> bytes | None: ...
    @property
    def needs_password(self) -> bool: ...
    def getcomment(
        self,
        member: _Member,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
    ) -> bytes | None: ...
    def readlink(
        self,
        member: _Member,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
    ) -> bytes: ...
    def gettimes(
        self,
        member: _Member,
        *,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
    ) -> dict[Literal["modified", "created", "accessed"], int]: ...
    def rewrite_preservation_issues(self) -> list[str]: ...
    def volume_paths(self) -> list[Path]: ...
    @property
    def sfx_offset(self) -> int: ...
    @property
    def family(self) -> ArchiveFamily: ...
    @property
    def is_volume(self) -> bool: ...
    @property
    def volume_number(self) -> int | None: ...
    @property
    def is_first_volume(self) -> bool | None: ...
    @property
    def volume_naming(self) -> VolumeNaming: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]: ...
    def __iter__(self) -> Iterator[RarInfo]: ...

@final
class RarBuilder:
    def __new__(
        cls,
        format: ArchiveVersion | str = "rar50",
        *,
        level: int = 3,
        store: bool = False,
        solid: bool = False,
        password: _Password | None = None,
        encrypt_headers: bool = False,
        comment: str | bytes | None = None,
        recovery_percent: int | None = None,
        volume_size: int | None = None,
        resources: WriterResources | None = None,
    ) -> Self: ...
    @staticmethod
    def from_archive(
        source: RarFile | _Source,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        volumes: Iterable[_Source] | None = None,
        cancellation: CancellationToken | None = None,
        preserve: bool = True,
        staging_dir: _StrPath | None = None,
        max_staged_bytes: int | None = None,
    ) -> RarBuilder: ...
    def add(self, path: _StrPath, arcname: _NewName | None = None) -> None: ...
    def add_directory(
        self,
        arcname: _NewName,
        *,
        mtime: int | None = None,
        mode: int | None = None,
    ) -> None: ...
    def add_bytes(
        self,
        data: Buffer,
        arcname: _NewName,
        *,
        mtime: int | None = None,
        mode: int | None = None,
    ) -> None: ...
    def member_ids(self) -> list[int]: ...
    def remove(self, member: int | _Member) -> None: ...
    def rename(self, old: int | _Member, new: _NewName) -> None: ...
    def add_unix_symlink(
        self,
        arcname: _NewName,
        target: _NewName,
        *,
        target_is_directory: bool = False,
        mtime: int | None = None,
        mode: int | None = None,
    ) -> None: ...
    def set_times(
        self,
        member: int | _Member,
        *,
        modified_ns: int | None = None,
        created_ns: int | None = None,
        accessed_ns: int | None = None,
    ) -> None: ...
    def set_file_comment(
        self,
        member: int | _Member,
        comment: str | bytes | None = None,
    ) -> None: ...
    def to_bytes(
        self,
        *,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
    ) -> bytes: ...
    def write(
        self,
        path: _StrPath,
        *,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None: ...
    def write_volumes(
        self,
        first_path: _StrPath,
        *,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
    ) -> list[Path]: ...

@final
class RepairReport:
    @property
    def changed(self) -> bool: ...
    @property
    def data_repaired(self) -> bool: ...
    @property
    def recovery_record_rebuilt(self) -> bool: ...
    @property
    def end_record_rebuilt(self) -> bool: ...
    @property
    def available_recovery_shards(self) -> int | None: ...
    @property
    def expected_recovery_shards(self) -> int | None: ...

@final
class RepairResult:
    @property
    def data(self) -> bytes | None: ...
    @property
    def report(self) -> RepairReport: ...

@final
class PasswordCheck:
    @property
    def correct(self) -> _Password | None: ...
    @property
    def undetermined(self) -> list[_Password]: ...
    @property
    def archive(self) -> RarFile | None: ...
    @property
    def needs_password(self) -> bool: ...

def is_rarfile(source: _Source) -> bool: ...
def is_rarfile_sfx(source: _Source) -> bool: ...
def check_password(
    source: Buffer | _StrPath,
    candidates: Iterable[_Password],
    *,
    options: ReadOptions | None = None,
    cancellation: CancellationToken | None = None,
) -> PasswordCheck: ...
def repair(
    source: _Source,
    *,
    password: _Password | None = None,
    output: _StrPath | None = None,
    options: ReadOptions | None = None,
    cancellation: CancellationToken | None = None,
) -> RepairResult: ...
