#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_command cargo
require_command dosbox-x
require_command python3

rar1402_exe="${RARS_RAR1402_EXE:-/home/gaz/src/tmp/rar/fixtures/1.402/.rar1402-bin/RAR.EXE}"
if [[ ! -f "$rar1402_exe" ]]; then
  cat >&2 <<EOF
missing DOS RAR 1.402 executable: $rar1402_exe

Set RARS_RAR1402_EXE to the local DOS RAR 1.402 RAR.EXE.
EOF
  exit 1
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar14-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

cp "$rar1402_exe" "$tmpdir/RAR.EXE"

python3 - "$tmpdir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "TEXT.TXT").write_bytes(
    b"RAR14 oracle text alpha beta gamma repeated line.\r\n" * 512
)
(root / "REPEAT.BIN").write_bytes(b"abcdefghijklmnop" * 1024)
(root / "NEAR1.BIN").write_bytes(b"A" * 16 * 1024)
(root / "NEAR256.BIN").write_bytes(bytes(range(256)) * 64)
(root / "OLDDIST.BIN").write_bytes(b"abcdabcdXYZXYZwxyzwxyz" * 128)

state = 0x13579BDF
binary = bytearray()
for _ in range(32 * 1024):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    binary.append(state & 0xFF)
(root / "BINARY.BIN").write_bytes(binary)
PY

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

run_rars_add --format rar14 --level 5 "$tmpdir/T.RAR" "$tmpdir/TEXT.TXT"
run_rars_add --format rar14 --level 5 "$tmpdir/R.RAR" "$tmpdir/REPEAT.BIN"
run_rars_add --format rar14 --level 5 "$tmpdir/N1.RAR" "$tmpdir/NEAR1.BIN"
run_rars_add --format rar14 --level 5 "$tmpdir/N256.RAR" "$tmpdir/NEAR256.BIN"
run_rars_add --format rar14 --level 5 "$tmpdir/O.RAR" "$tmpdir/OLDDIST.BIN"
run_rars_add --format rar14 --level 5 "$tmpdir/B.RAR" "$tmpdir/BINARY.BIN"

extract_with_dos_rar() {
  local archive_name=$1
  local output_dir=$2
  mkdir -p "$tmpdir/$output_dir"
  dosbox-x -silent -exit -time-limit 20 \
    -c "mount c $tmpdir" \
    -c 'c:' \
    -c "cd $output_dir" \
    -c "c:\\RAR e -y c:\\$archive_name > c:\\$output_dir.OUT" \
    -c 'exit' >/dev/null 2>&1
}

extract_with_dos_rar T.RAR OT
extract_with_dos_rar R.RAR OR
extract_with_dos_rar N1.RAR ON1
extract_with_dos_rar N256.RAR ON256
extract_with_dos_rar O.RAR OO
extract_with_dos_rar B.RAR OB

python3 - "$tmpdir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
checks = [
    ("TEXT.TXT", "OT/TEXT.TXT"),
    ("REPEAT.BIN", "OR/REPEAT.BIN"),
    ("NEAR1.BIN", "ON1/NEAR1.BIN"),
    ("NEAR256.BIN", "ON256/NEAR256.BIN"),
    ("OLDDIST.BIN", "OO/OLDDIST.BIN"),
    ("BINARY.BIN", "OB/BINARY.BIN"),
]
for original, extracted in checks:
    original_bytes = (root / original).read_bytes()
    extracted_path = root / extracted
    if not extracted_path.exists():
        raise SystemExit(f"DOS RAR 1.402 did not extract {extracted}")
    extracted_bytes = extracted_path.read_bytes()
    if original_bytes != extracted_bytes:
        raise SystemExit(f"DOS RAR 1.402 extracted different bytes for {original}")
PY

echo
echo "RAR14 generated writer reference checks passed."
