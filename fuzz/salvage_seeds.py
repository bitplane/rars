#!/usr/bin/env python3
"""Write seed corpora for the salvage_extract and salvage_volumes fuzz targets.

Every seed is a small archive that rars writes from synthetic members: text
from one vocabulary, so solid members refer back to earlier ones, a few
x86-looking bytes for the filters, and an empty file. Each format is written
solid and not, and RAR 2.9 with PPMd as well as LZ. A cut copy of each solid
archive seeds the parse-up-to-the-cut path.

salvage_volumes seeds are volume sets written with --volume-size, packed in
that target's layout: a count byte, a little-endian u16 length before each
volume but the last, then the volumes. Some leave out the first or last
volume, so drop_incomplete_members has split members to drop.

Usage: salvage_seeds.py <rars-binary> <corpus-dir>

Seeds go to <corpus-dir>/salvage_extract and <corpus-dir>/salvage_volumes.
"""

from __future__ import annotations

import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# (name, rars a arguments, also written solid). Stored archives can't be
# solid, and a RAR 5 solid archive picks its own filters.
FORMATS = [
    ("rar14", ["--format", "rar14"], True),
    ("rar15", ["--format", "rar15"], True),
    ("rar20", ["--format", "rar20"], True),
    ("rar29", ["--format", "rar29"], True),
    ("rar29_ppmd", ["--format", "rar29", "--ppmd"], True),
    ("rar29_e8e9", ["--format", "rar29", "--e8e9-filter"], True),
    ("rar29_delta", ["--format", "rar29", "--delta-filter", "3"], True),
    ("rar50", ["--format", "rar50"], True),
    ("rar50_e8e9", ["--format", "rar50", "--e8e9-filter"], False),
    ("rar50_delta", ["--format", "rar50", "--delta-filter", "3"], False),
    ("rar50_rr", ["--format", "rar50", "--recovery-percent", "5"], True),
    ("rar50_qo", ["--format", "rar50", "--quick-open"], True),
    ("rar20_store", ["--format", "rar20", "--store"], False),
    ("rar50_store", ["--format", "rar50", "--store"], False),
]

VOLUME_FORMATS = ["rar14", "rar15", "rar20", "rar29", "rar50"]


def members(directory: Path) -> list[str]:
    rng = random.Random(442)
    words = [
        bytes(rng.randrange(97, 123) for _ in range(rng.randrange(2, 10)))
        for _ in range(200)
    ]
    names = []
    for index in range(4):
        text = bytearray()
        while len(text) < 1500:
            text += rng.choice(words) + b" "
        names.append(f"m{index}.txt")
        (directory / names[-1]).write_bytes(bytes(text))
    code = bytearray()
    while len(code) < 1024:
        code += bytes([0xE8]) + struct.pack("<i", rng.randrange(-4096, 4096))
        code += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
    names.append("code.bin")
    (directory / names[-1]).write_bytes(bytes(code))
    names.append("empty.txt")
    (directory / names[-1]).write_bytes(b"")
    return names


def rars_add(rars: str, archive: Path, args: list[str], inputs: Path, names: list[str]):
    result = subprocess.run(
        [rars, "a", *args, str(archive), *names], cwd=inputs, capture_output=True
    )
    if result.returncode != 0:
        sys.stderr.buffer.write(result.stderr)
        result.check_returncode()


def pack_volumes(volumes: list[bytes]) -> bytes:
    packed = bytearray([len(volumes) - 1])
    for volume in volumes[:-1]:
        packed += struct.pack("<H", len(volume)) + volume
    return bytes(packed + volumes[-1])


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    rars = str(Path(sys.argv[1]).resolve())
    corpus = Path(sys.argv[2])
    single = corpus / "salvage_extract"
    split = corpus / "salvage_volumes"
    single.mkdir(parents=True, exist_ok=True)
    split.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=corpus) as work:
        work = Path(work)
        inputs = work / "in"
        inputs.mkdir()
        names = members(inputs)
        (inputs / "joined.txt").write_bytes(
            b"".join((inputs / name).read_bytes() for name in names)
        )
        for name, args, solid_too in FORMATS:
            for solid in (False, True) if solid_too else (False,):
                stem = f"{name}_solid" if solid else name
                archive = work / f"{stem}.rar"
                rars_add(rars, archive, args + (["--solid"] if solid else []), inputs, names)
                data = archive.read_bytes()
                (single / archive.name).write_bytes(data)
                if solid:
                    (single / f"{stem}_cut.rar").write_bytes(data[: len(data) * 2 // 3])
        for name in VOLUME_FORMATS:
            for solid in (False, True):
                stem = f"{name}_solid" if solid else name
                out = work / f"vol_{stem}"
                out.mkdir()
                args = ["--format", name, "--volume-size", "2k"]
                if solid:
                    args.append("--solid")
                # A RAR 1.3 volume set holds one file.
                files = ["joined.txt"] if name == "rar14" else names
                rars_add(rars, out / f"{stem}.rar", args, inputs, files)
                volumes = [path.read_bytes() for path in sorted(out.iterdir(), key=volume_order)]
                # The set from its start, without its first volume, and its
                # second volume alone.
                (split / f"{stem}_head").write_bytes(pack_volumes(volumes[:3]))
                if len(volumes) > 1:
                    (split / f"{stem}_tail").write_bytes(pack_volumes(volumes[1:3]))
                if len(volumes) > 2:
                    (split / f"{stem}_middle").write_bytes(pack_volumes(volumes[1:2]))
    return 0


def volume_order(path: Path) -> tuple[int, str]:
    """Volume order for both naming schemes: name.partN.rar, and name.rar then name.r00."""
    suffix = path.name.rsplit(".", 2)
    if len(suffix) == 3 and suffix[1].startswith("part"):
        return (int(suffix[1][4:]), path.name)
    if path.suffix == ".rar":
        return (-1, path.name)
    return (int(path.suffix[2:]), path.name)


if __name__ == "__main__":
    sys.exit(main())
