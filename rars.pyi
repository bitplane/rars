import os
from collections.abc import Callable, Iterable, Iterator
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, Protocol, final

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
    "Truncation",
    "TruncatedBlock",
    "IncompleteMember",
    "MissingPart",
    "check_password",
    "is_rarfile",
    "is_rarfile_sfx",
    "repair",
    "Error",
    "BadRarFile",
    "BadPassword",
    "PasswordRequired",
    "MissingVolume",
    "VolumeOrderError",
    "ChecksumError",
    "UnsupportedRarFeature",
    "NotRarFile",
    "UnsafeArchivePath",
    "LimitExceeded",
    "UnsafeLinkWarning",
    "Cancelled",
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
_MemberErrorHandler: TypeAlias = Callable[[Exception], object]

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
    COMPRESSING = "compressing"
    PROTECTING = "protecting"
    """Adding a recovery record."""
    WRITING = "writing"

class TruncatedBlock(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    MEMBER = "member"
    RECOVERY_RECORD = "recovery_record"
    SERVICE = "service"
    COMMENT = "comment"
    END = "end"
    UNKNOWN = "unknown"

class MissingPart(str, Enum):
    def __new__(cls, value: str) -> Self: ...
    START = "start"
    END = "end"
    BOTH = "both"


class Error(Exception):
    member: str | None
    """The member the error is about, when known; set on every error `on_member_error` is given."""

class BadRarFile(Error):
    """The archive is damaged or malformed."""

class BadPassword(Error): ...
class PasswordRequired(Error): ...

class MissingVolume(Error):
    volume_index: int | None
    path: Path | None

class VolumeOrderError(Error):
    """`volumes` gave a volume out of order; `volume_index` is where the order broke."""
    volume_index: int | None

class ChecksumError(BadRarFile):
    member: str | None
    volume_index: int | None

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
    def total(self) -> int | None:
        """Bytes this phase will handle, or None while that isn't known yet."""
    @property
    def pass_number(self) -> int: ...
    @property
    def entry_name(self) -> bytes | None: ...
    @property
    def entry_index(self) -> int | None: ...
    @property
    def total_entries(self) -> int | None: ...
    @property
    def volume_index(self) -> int | None: ...
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
        max_rar50_dictionary_bytes: int | None = None,
        max_rar50_buffered_member_bytes: int | None = None,
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
    def max_rar50_dictionary_bytes(self) -> int | None: ...
    @property
    def max_rar50_buffered_member_bytes(self) -> int | None: ...
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
        max_memory_bytes: int | None = None,
        max_workspace_bytes: int | None = None,
    ) -> Self: ...
    @property
    def max_memory_bytes(self) -> int | None: ...
    @property
    def max_workspace_bytes(self) -> int | None: ...

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
    def date_time(self) -> tuple[int, int, int, int, int, int] | None:
        """Whole-second local wall-clock fields, as zipfile.ZipInfo.date_time."""
    @property
    def mtime(self) -> float | None: ...
    @property
    def mtime_ns(self) -> int | None: ...
    @property
    def atime_ns(self) -> int | None: ...
    @property
    def birthtime_ns(self) -> int | None: ...
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
    def volume_index(self) -> int: ...
    def is_dir(self) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class RarFile:
    def __new__(
        cls,
        source: _Source,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        cancellation: CancellationToken | None = None,
        first_volume_only: bool = False,
        volumes: list[_Source] | tuple[_Source, ...] | None = None,
        salvage: bool = False,
    ) -> Self:
        """`salvage=True` reads what survives: a file cut short inside a member up to that
        member (see `truncation`), and a volume set that begins late or ends early, leaving
        out the split members it holds only part of (see `incomplete_members`)."""
    def namelist(self) -> list[str]: ...
    def infolist(self) -> list[RarInfo]: ...
    def getinfo(self, member: _Member) -> RarInfo: ...
    def read(
        self,
        member: _Member,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
    ) -> bytes: ...
    def open(
        self,
        member: _Member,
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
        on_member_error: _MemberErrorHandler | None = None,
    ) -> list[Path]:
        """`on_member_error` works as in `testrar`, and no output of a failed member is kept."""
    def testrar(
        self,
        *,
        password: _Password | None = None,
        options: ReadOptions | None = None,
        progress: _Progress | None = None,
        cancellation: CancellationToken | None = None,
        volumes: Iterable[_Source] | None = None,
        on_member_error: _MemberErrorHandler | None = None,
    ) -> None:
        """`on_member_error` carries on past each member that fails, calling it with the
        error, whose `member` names it; raise from it to stop. A wrong password or an
        I/O error still raises."""
    @property
    def truncation(self) -> Truncation | None:
        """Where the file ends early, or None. With `salvage=True`, the first volume read that does."""
    @property
    def incomplete_members(self) -> list[IncompleteMember]:
        """The split members `salvage=True` left out of a volume set."""
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
    def member_comment(
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
    def volume_paths(self) -> list[Path]: ...
    @property
    def sfx_offset(self) -> int: ...
    @property
    def family(self) -> ArchiveFamily: ...
    @property
    def is_volume(self) -> bool: ...
    @property
    def volume_index(self) -> int | None: ...
    @property
    def is_first_volume(self) -> bool | None: ...
    @property
    def volume_naming(self) -> VolumeNaming: ...
    def close(self) -> None: ...
    @property
    def closed(self) -> bool: ...
    @property
    def first_volume_only(self) -> bool: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]: ...
    def __iter__(self) -> Iterator[RarInfo]: ...
    def __len__(self) -> int: ...
    def __contains__(self, member: object, /) -> bool: ...

@final
class RarBuilder:
    def __new__(
        cls,
        version: ArchiveVersion | str = "rar50",
        *,
        level: int = 3,
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
        mtime: float | None = None,
        mode: int | None = None,
    ) -> None: ...
    def add_bytes(
        self,
        data: Buffer,
        arcname: _NewName,
        *,
        mtime: float | None = None,
        mode: int | None = None,
    ) -> None: ...
    def member_ids(self) -> list[int]: ...
    def remove(self, member: int | _Member) -> None: ...
    def rename(self, member: int | _Member, new: _NewName) -> None: ...
    def add_unix_symlink(
        self,
        arcname: _NewName,
        target: _NewName,
        *,
        target_is_directory: bool = False,
        mtime: float | None = None,
        mode: int | None = None,
    ) -> None: ...
    def set_times(
        self,
        member: int | _Member,
        *,
        mtime_ns: int | None = None,
        atime_ns: int | None = None,
        birthtime_ns: int | None = None,
    ) -> None: ...
    def set_member_comment(
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
        overwrite: bool = False,
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

@final
class Truncation:
    """Where an archive's file ends early; every member listed before it is whole.
    `str()` describes it."""
    @property
    def block(self) -> TruncatedBlock: ...
    @property
    def name(self) -> bytes | None:
        """The stored name of a cut member or service block."""
    @property
    def offset(self) -> int: ...
    @property
    def started(self) -> bool:
        """Whether any of the block is in the file."""
    @property
    def volume_index(self) -> int: ...

@final
class IncompleteMember:
    """A split member left out because part of it is in a volume not given."""
    @property
    def filename(self) -> str: ...
    @property
    def orig_filename_bytes(self) -> bytes: ...
    @property
    def volume_index(self) -> int:
        """The first volume holding part of it, counting the one opened as 0."""
    @property
    def missing(self) -> MissingPart: ...

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
    overwrite: bool = False,
    options: ReadOptions | None = None,
    cancellation: CancellationToken | None = None,
) -> RepairResult: ...
