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
require_command python3
require_command wine

if [[ -z "${RARS_WINRAR300_PREFIX:-}" || -z "${RARS_WINRAR420_PREFIX:-}" ]]; then
  cat >&2 <<'EOF'
missing reference Wine prefix

Set RARS_WINRAR300_PREFIX and RARS_WINRAR420_PREFIX before running this
script. Set RARS_UNRAR300 or RARS_UNRAR420 as well if UnRAR.exe is not in
the standard Wine install path.
EOF
  exit 1
fi

winrar300_prefix="$RARS_WINRAR300_PREFIX"
winrar420_prefix="$RARS_WINRAR420_PREFIX"
unrar300="${RARS_UNRAR300:-$winrar300_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"
unrar420="${RARS_UNRAR420:-$winrar420_prefix/drive_c/Program Files (x86)/WinRAR/UnRAR.exe}"

for tool in "$unrar300" "$unrar420"; do
  if [[ ! -f "$tool" ]]; then
    cat >&2 <<EOF
missing reference tool: $tool

Set the matching RARS_UNRAR300 or RARS_UNRAR420 variable if UnRAR.exe is
not in the standard Wine install path.
EOF
    exit 1
  fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar29-rarvm-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$tmpdir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "e8.bin").write_bytes(b"\xe8\x00\x00\x00\x00RAR29 E8 filter reference\n" * 4)
(root / "e8e9.bin").write_bytes(b"\xe9\x00\x00\x00\x00RAR29 E8E9 filter reference\n" * 4)
(root / "auto.bin").write_bytes(
    b"\xe8\x00\x00\x00\x00RAR29 auto filter reference\n" * 16
    + b"plain trailing data for the size chooser\n"
)
(root / "auto-delta.bin").write_bytes(bytes((i // 3) & 0xff for i in range(768)))
(root / "delta.bin").write_bytes(bytes((i * 7 + 3) & 0xff for i in range(192)))

itanium = bytearray(512)
for i in range(len(itanium)):
    itanium[i] = (i * 11 + 5) & 0xff
for start in range(0, len(itanium), 32):
    if start + 21 < len(itanium):
        itanium[start + 16] = 22
        itanium[start + 21] = 20
(root / "itanium.bin").write_bytes(itanium)
(root / "auto-itanium.bin").write_bytes(itanium)

rgb = bytearray()
for y in range(32):
    for x in range(8):
        rgb.extend(((x * 23 + y * 3) & 0xff, (x * 5 + y * 17) & 0xff, (x * 13 + y * 19) & 0xff))
(root / "rgb.bin").write_bytes(rgb)
(root / "auto-rgb.bin").write_bytes(rgb)

audio = bytes((128 + ((i * 9) % 73) - ((i * 5) % 41)) & 0xff for i in range(256))
(root / "audio.bin").write_bytes(audio)
(root / "auto-audio.bin").write_bytes(bytes((128 + ((i * 9) % 73) - ((i * 5) % 41)) & 0xff for i in range(512)))
PY

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

run_rars_add --format rar29 --e8-filter "$tmpdir/e8.rar" "$tmpdir/e8.bin"
run_rars_add --format rar29 --e8e9-filter "$tmpdir/e8e9.rar" "$tmpdir/e8e9.bin"
run_rars_add --format rar29 --auto-filter "$tmpdir/auto.rar" "$tmpdir/auto.bin"
run_rars_add --format rar29 --auto-filter "$tmpdir/auto-delta.rar" "$tmpdir/auto-delta.bin"
run_rars_add --format rar29 --auto-filter "$tmpdir/auto-itanium.rar" "$tmpdir/auto-itanium.bin"
run_rars_add --format rar29 --auto-filter "$tmpdir/auto-rgb.rar" "$tmpdir/auto-rgb.bin"
run_rars_add --format rar29 --auto-filter "$tmpdir/auto-audio.rar" "$tmpdir/auto-audio.bin"
run_rars_add --format rar29 --delta-filter 3 "$tmpdir/delta.rar" "$tmpdir/delta.bin"
run_rars_add --format rar29 --itanium-filter "$tmpdir/itanium.rar" "$tmpdir/itanium.bin"
run_rars_add --format rar29 --rgb-filter 24 "$tmpdir/rgb.rar" "$tmpdir/rgb.bin"
run_rars_add --format rar29 --audio-filter 2 "$tmpdir/audio.rar" "$tmpdir/audio.bin"

run_unrar() {
  local prefix=$1
  local unrar=$2
  local archive=$3
  env WINEPREFIX="$prefix" wine "$unrar" t "$(wine_z_path "$archive")"
}

wine_z_path() {
  local path=$1
  printf 'Z:%s' "${path//\//\\}"
}

for archive in \
  "$tmpdir/e8.rar" \
  "$tmpdir/e8e9.rar" \
  "$tmpdir/auto.rar" \
  "$tmpdir/auto-delta.rar" \
  "$tmpdir/auto-itanium.rar" \
  "$tmpdir/auto-rgb.rar" \
  "$tmpdir/auto-audio.rar" \
  "$tmpdir/delta.rar" \
  "$tmpdir/itanium.rar" \
  "$tmpdir/rgb.rar" \
  "$tmpdir/audio.rar"
do
  run_unrar "$winrar300_prefix" "$unrar300" "$archive"
  run_unrar "$winrar420_prefix" "$unrar420" "$archive"
done

cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_e8_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_e8e9_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_delta_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_itanium_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_rgb_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_segmented_audio_filter_record \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar300_accepts_rar29_segmented_filter_records \
  -- --ignored --exact
cargo test -p rars --test rar15_40_fixtures \
  reference_unrar_accepts_rar29_solid_e8_filter_record \
  -- --ignored --exact

echo
echo "RAR29 standard RARVM generated writer reference checks passed."
