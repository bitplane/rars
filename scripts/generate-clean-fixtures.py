#!/usr/bin/env python3
"""Regenerate the test fixtures that replaced third-party content (issue #118).

Every payload here is synthesised by this script. The archives are written by
period RAR encoders, or by rars where no runnable period encoder exists, so
the fixtures carry no one else's files.

Encoders are found through environment variables:

  RAR393     native Linux RAR 3.93 (rar393-linux-x64)
  RAR290     WinRAR 2.90 console Rar.exe, run under wine
  RAR602     WinRAR 6.02 console Rar.exe, run under wine
  RAR1402    DOS RAR 1.402 RAR.EXE, run under dosbox-x
  RARS       a rars binary (defaults to target/release/rars)

Usage: generate-clean-fixtures.py <work-dir>

Archives are written into crates/rars/tests/fixtures. Encoders stamp the
current time into headers, so a rerun changes bytes but not the payloads,
names, sizes, CRCs or the stream properties the tests assert.
"""

from __future__ import annotations

import math
import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "crates" / "rars" / "tests" / "fixtures"


def tool(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"set {name} to the encoder's path")
    return value


def run(cmd: list[str], cwd: Path, **env: str) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, env={**os.environ, **env},
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wine(exe: str, args: list[str], cwd: Path) -> None:
    run(["wine", exe, *args], cwd, WINEDEBUG="-all")


def fresh(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def place(src: Path, dest: str) -> None:
    shutil.copyfile(src, FIXTURES / dest)
    print(f"wrote {dest}")


# ------------------------------------------------------------- payloads

def synthetic_executable(size: int = 204288) -> bytes:
    """A PE-shaped image: headers, x86-like code dense with E8/E9 rel32
    branches, then a data section of strings and pointers."""
    rng = random.Random(0xE8E9)
    img = bytearray(b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x80 - 64)
                    + b"PE\0\0" + bytes(0x400 - 0x84))
    ops = [b"\x55", b"\x89\xe5", b"\x83\xec\x10", b"\x8b\x45\x08", b"\x50", b"\x5d",
           b"\xc3", b"\x31\xc0", b"\x85\xc0", b"\x74\x05", b"\x48\x8b\x07", b"\x0f\xb6\x01"]
    code_end = 150000
    while len(img) < code_end:
        r = rng.random()
        if r < 0.12:
            target = rng.randrange(0x400, code_end)
            img += (b"\xe8" if r < 0.09 else b"\xe9") + struct.pack("<i", target - (len(img) + 5))
        else:
            img += rng.choice(ops)
    names = [b"archive_read", b"format_rar", b"filter_e8", b"window", b"symbol", b"read_data"]
    while len(img) < size:
        if rng.random() < 0.5:
            img += rng.choice(names) + b"_" + str(rng.randrange(1000)).encode() + b"\0"
        else:
            img += struct.pack("<I", rng.randrange(0x10000))
    return bytes(img[:size])


def synthetic_speech() -> bytes:
    """0.64 s of mono 16-bit 44.1 kHz PCM: a glottal pulse train with drifting
    pitch through two moving formant resonators, peaking at 12000."""
    rate, n = 44100, 28210

    def render(gain: float) -> tuple[list[int], float]:
        rng = random.Random(44100)
        out, peak = [], 0.0
        y1 = y2 = z1 = z2 = phase = 0.0
        for i in range(n):
            t = i / rate
            phase += (120 + 40 * math.sin(2 * math.pi * 1.7 * t)) / rate
            pulse = 1.0 if phase >= 1.0 else 0.0
            phase -= math.floor(phase)

            def resonator(f: float, bw: float = 90) -> tuple[float, float]:
                r = math.exp(-math.pi * bw / rate)
                return 2 * r * math.cos(2 * math.pi * f / rate), -r * r

            a1, a2 = resonator(500 + 250 * math.sin(2 * math.pi * 2.3 * t))
            b1, b2 = resonator(1500 + 600 * math.sin(2 * math.pi * 1.1 * t + 1))
            y = pulse * 3000 + rng.gauss(0, 2) + a1 * y1 + a2 * y2
            y2, y1 = y1, y
            z = y + b1 * z1 + b2 * z2
            z2, z1 = z1, z
            v = z * (0.5 - 0.5 * math.cos(2 * math.pi * min(t / 0.64, 1))) * gain
            peak = max(peak, abs(v))
            out.append(max(-32768, min(32767, int(v))))
        return out, peak

    _, peak = render(1.0)
    samples, _ = render(12000 / peak)
    data = struct.pack(f"<{n}h", *samples)
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
            + b"data" + struct.pack("<I", len(data)) + data)


SPEECH_NOTES = b"Synthetic speech-shaped PCM generated for rars.\r\nNo recorded audio.\r\n"

README_TEXT = """RARS TEST FIXTURE
=================

This file is a plain-text payload written for the rars test suite. It is
archived three times by the DOS RAR 1.402 command-line archiver: once stored,
once with normal compression and once with a password, so the reader can be
checked against the same bytes along three different paths.

Nothing here comes from any other product. The text only needs to be long
enough to give the RAR 1.3 compressor some repetition to work with, and
short enough to keep the fixtures small.

What the three archives cover
-----------------------------

1. The stored archive keeps these bytes unchanged after the file header, so
   a test can compare the packed data directly with this file.

2. The compressed archive runs the bytes through the adaptive Huffman and
   LZ coder that RAR 1.3 and RAR 1.4 share. Decoding it proves the coder,
   the sliding window and the rolling checksum together.

3. The password archive encrypts the same compressed stream, which checks
   the RAR 1.3 cipher on top of the decoder.

Some repetition for the matcher
-------------------------------

The quick brown fox jumps over the lazy dog. The quick brown fox jumps over
the lazy dog again. Pack my box with five dozen liquor jugs. Pack my box
with five dozen liquor jugs once more. Sphinx of black quartz, judge my vow.

0123456789 0123456789 0123456789 0123456789 0123456789 0123456789
ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ ABCDEFGHIJ

End of file.
"""


# ------------------------------------------------------------- archives

def rar13_readme(work: Path) -> None:
    """RAR 1.402 stored, compressed and encrypted copies of one text file."""
    work = fresh(work / "rar13")
    shutil.copyfile(tool("RAR1402"), work / "RAR.EXE")
    (work / "README").write_bytes(README_TEXT.replace("\n", "\r\n").encode("ascii"))
    (work / "GO.BAT").write_bytes(
        b"@echo off\r\n"
        b"rar a -m0 RSTORE.RAR README\r\n"
        b"rar a RNORM.RAR README\r\n"
        b"rar a -ppassword RPASS.RAR README\r\n"
        b"exit\r\n")
    run(["dosbox-x", "-silent", "-exit", "-nogui", "-nomenu", "-time-limit", "30",
         "-c", f"mount c {work}", "-c", "c:", "-c", "go.bat", "-c", "exit"],
        work, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
    place(work / "README", "rar13/README")
    place(work / "RSTORE.RAR", "rar13/README_store.rar")
    place(work / "RNORM.RAR", "rar13/README.RAR")
    place(work / "RPASS.RAR", "rar13/README_password=password.rar")


def ppmd_restarts(work: Path) -> None:
    """Solid PPMd with a 1 MB model at order 61: the suballocator runs out and
    the model restarts several times across the eight members."""
    work = fresh(work / "ppmd")
    rng = random.Random(170)
    syllables = ["ka", "lo", "mi", "ne", "ru", "ta", "vi", "so", "pe", "du",
                 "fa", "gi", "ho", "ju", "ze", "xa", "qu", "bry", "str", "ell"]
    vocab = ["".join(rng.choice(syllables) for _ in range(rng.randint(1, 4)))
             for _ in range(6000)]
    names = []
    for n in range(8):
        lines, size = [], 0
        while size < 48 * 1024:
            line = " ".join(rng.choice(vocab) for _ in range(rng.randint(4, 14)))
            line = f"{rng.randint(0, 99999):05d} {line}.\r\n"
            lines.append(line)
            size += len(line)
        name = f"part{n}.txt"
        (work / name).write_bytes("".join(lines)[:48 * 1024].encode("ascii"))
        names.append(name)
    run([tool("RAR393"), "a", "-idq", "-ep", "-s", "-m5", "-mc63:1t+", "-md1024",
         "out.rar", *names], work)
    place(work / "out.rar", "rar15_40/ppmd/ppmd_solid_restarts_rar393.rar")


def unpack20_keep_tables(work: Path) -> None:
    """A member whose content shifts from text to code to noise and back, so
    WinRAR 2.90 emits new Unpack20 tables mid-stream that keep the previous
    lengths, then a second compressed member that starts fresh tables."""
    work = fresh(work / "keep_tables")
    rng = random.Random(250)
    words = [b"table", b"block", b"symbol", b"length", b"window", b"match", b"literal", b"huffman"]
    text = bytearray()
    while len(text) < 20000:
        text += rng.choice(words) + (b"\r\n" if rng.random() < 0.1 else b" ")
    code = bytearray()
    for i in range(6000):
        code += struct.pack("<IHBB", 0x08048000 + i * 16, rng.randrange(4096), 0x8B,
                            rng.choice([0xE8, 0xE9, 0x55, 0xC3]))
    noise = bytes(rng.randrange(256) for _ in range(8000))
    (work / "SHIFT.BIN").write_bytes(bytes(text[:20000]) + bytes(code) + noise + bytes(text[:12000]))
    (work / "NOTES.TXT").write_bytes(
        b"Synthetic keep-tables fixture for rars.\r\n"
        + b"".join(b"Line %02d: the second member starts a fresh Unpack20 table.\r\n" % i
                   for i in range(6)))
    wine(tool("RAR290"), ["a", "-idq", "-m3", "out.rar", "SHIFT.BIN", "NOTES.TXT"], work)
    place(work / "out.rar", "rar15_40/rar250/unpack20_keep_tables.rar")


def unpack20_audio(work: Path) -> None:
    """WinRAR 2.90 with default switches: LZ, not the audio predictor."""
    work = fresh(work / "audio20")
    (work / "SyntheticSpeech.wav").write_bytes(synthetic_speech())
    (work / "NOTES.txt").write_bytes(SPEECH_NOTES)
    wine(tool("RAR290"), ["a", "-idq", "-m3", "out.rar", "SyntheticSpeech.wav", "NOTES.txt"], work)
    place(work / "out.rar", "rar15_40/rar250/unpack20_audio_text.rar")


def unpack15_audio(work: Path) -> None:
    """RAR 1.5 (UnpVer 15) archives. WinRAR 1.54 is a Win16 program that wine
    cannot run, so rars writes these and unrar validates them."""
    rars = tool("RARS", str(ROOT / "target" / "release" / "rars"))
    for variant, wav, notes in [("win", "SyntheticSpeech.wav", "NOTES.txt"),
                                ("dos", "SYNTHE~1.WAV", "NOTES.TXT")]:
        dir = fresh(work / f"audio15_{variant}")
        (dir / wav).write_bytes(synthetic_speech())
        (dir / notes).write_bytes(SPEECH_NOTES)
        run([rars, "--progress", "never", "add", "--format", "rar15", "--level", "5",
             "out.rar", wav, notes], dir)
        place(dir / "out.rar", f"rar15_40/rar154/audio_{variant}_names_unpack15.rar")


def wide_e8e9_blocks(work: Path) -> None:
    """WinRAR 6.02 in RAR 4 format with the x86 filter forced cuts 64 KiB
    E8E9 blocks; a size of 0x10000 only fits the 32-bit integer encoding."""
    work = fresh(work / "e8e9")
    (work / "synthetic.exe").write_bytes(synthetic_executable())
    wine(tool("RAR602"), ["a", "-idq", "-ep", "-ma4", "-m5", "-mcE+", "out.rar", "synthetic.exe"], work)
    place(work / "out.rar", "rar15_40/rarvm/x86_e8e9_64k_blocks_rar602.rar")


def rar4_encrypted(work: Path) -> None:
    """RAR 3.93 per-file, header and Unicode-name encryption."""
    work = fresh(work / "enc")
    rar = tool("RAR393")
    utf8 = {"LANG": "C.UTF-8"}

    tree = work / "tree"
    for sub in ("exe", "jpg", "Empty"):
        (tree / sub).mkdir(parents=True)
    (tree / "exe" / "test.exe").write_bytes(synthetic_executable()[:45056])
    rng = random.Random(4)
    scan = bytearray()
    while len(scan) < 40000:
        b = rng.randrange(256)
        scan += bytes([b, 0]) if b == 0xFF else bytes([b])
    (tree / "jpg" / "test.jpg").write_bytes(
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + bytes(scan) + b"\xff\xd9")
    (tree / "тест.txt").write_bytes("".join(
        f"Строка {i}: синтетический текст для проверки имён в Юникоде.\r\n"
        for i in range(160)).encode("utf-8"))
    run([rar, "a", "-idq", "-r", "-ptest", "-m3", "../files_and_dirs.rar",
         "Empty", "exe", "jpg", "тест.txt"], tree, **utf8)
    place(work / "files_and_dirs.rar", "rar15_40/encrypted/rar4_encrypted_files_and_dirs.rar")

    (work / "file1.txt").write_bytes(b"file1\n")
    (work / "新建文本文档.txt").write_bytes(b"aaaaaaaaaa")
    run([rar, "a", "-idq", "-m3", "-ppassword", "pw.rar", "file1.txt"], work)
    run([rar, "a", "-idq", "-m3", "-hppassword", "hp.rar", "file1.txt"], work)
    run([rar, "a", "-idq", "-m3", "-ptest", "uni.rar", "新建文本文档.txt"], work, **utf8)
    place(work / "pw.rar", "rar15_40/encrypted/rar4_password.rar")
    place(work / "hp.rar", "rar15_40/encrypted/rar4_header_encrypted.rar")
    place(work / "uni.rar", "rar15_40/encrypted/rar4_unicode_name_encrypted.rar")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    work = Path(sys.argv[1]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    rar13_readme(work)
    ppmd_restarts(work)
    unpack20_keep_tables(work)
    unpack20_audio(work)
    unpack15_audio(work)
    wide_e8e9_blocks(work)
    rar4_encrypted(work)


if __name__ == "__main__":
    main()
