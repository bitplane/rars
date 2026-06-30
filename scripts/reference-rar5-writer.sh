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
require_command rar

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/rars-rar5-ref.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

payload="$tmpdir/payload.txt"
printf 'RAR5 generated writer reference payload\n' >"$payload"
delta_payload="$tmpdir/delta.bin"
printf '\001\003\006\012\017\025\034\044\055\067\102\116\133\151\170\210' >"$delta_payload"
e8_payload="$tmpdir/e8.bin"
printf '\350\000\000\000\000RAR5 e8 filtered reference payload\n' >"$e8_payload"
e8e9_payload="$tmpdir/e8e9.bin"
printf '\351\000\000\000\000RAR5 e8e9 filtered reference payload\n' >"$e8e9_payload"
arm_payload="$tmpdir/arm.bin"
printf '\004\000\000\353ARM!' >"$arm_payload"
auto_payload="$tmpdir/auto.bin"
printf '\350\000\000\000\000RAR5 auto filtered reference payload\n%.0s' {1..16} >"$auto_payload"
solid_one="$tmpdir/solid-one.txt"
solid_two="$tmpdir/solid-two.txt"
printf 'RAR5 solid generated writer shared phrase alpha beta gamma\n%.0s' {1..12} >"$solid_one"
printf 'RAR5 solid generated writer shared phrase alpha beta gamma\nsecond\n%.0s' {1..4} >"$solid_two"

run_rars_add() {
  cargo run -p rars-cli --quiet -- a "$@"
}

run_rars_add --format rar50 --store "$tmpdir/stored.rar" "$payload"
run_rars_add --format rar50 --store --file-comment "RAR5 generated file comment" \
  "$tmpdir/file-comment.rar" "$payload"
run_rars_add --format rar50 "$tmpdir/compressed.rar" "$payload"
run_rars_add --format rar50 --comment "RAR5 generated compressed comment" \
  "$tmpdir/compressed-comment.rar" "$payload"
run_rars_add --format rar50 --delta-filter 3 "$tmpdir/delta-filtered.rar" "$delta_payload"
run_rars_add --format rar50 --e8-filter "$tmpdir/e8-filtered.rar" "$e8_payload"
run_rars_add --format rar50 --e8e9-filter "$tmpdir/e8e9-filtered.rar" "$e8e9_payload"
run_rars_add --format rar50 --arm-filter "$tmpdir/arm-filtered.rar" "$arm_payload"
run_rars_add --format rar50 --auto-filter "$tmpdir/auto-filtered.rar" "$auto_payload"
run_rars_add --format rar50 --solid "$tmpdir/solid-compressed.rar" "$solid_one" "$solid_two"
run_rars_add --format rar50 --volume-size 20 "$tmpdir/compressed-volume.rar" "$payload"
run_rars_add --format rar50 --solid --volume-size 20 \
  "$tmpdir/solid-compressed-volume.rar" "$payload"
run_rars_add --format rar50 --solid --volume-size 96 \
  "$tmpdir/multi-solid-compressed-volume.rar" "$solid_one" "$solid_two"
run_rars_add --format rar50 --store --quick-open "$tmpdir/quick-open.rar" "$payload"
run_rars_add --password pass --format rar50 "$tmpdir/encrypted-compressed.rar" "$payload"
run_rars_add --password pass --format rar50 --comment "RAR5 generated encrypted compressed comment" \
  "$tmpdir/encrypted-compressed-comment.rar" "$payload"
run_rars_add --password pass --format rar50 --solid \
  "$tmpdir/encrypted-solid-compressed.rar" "$solid_one" "$solid_two"
run_rars_add --password pass --format rar50 --volume-size 32 \
  "$tmpdir/encrypted-compressed-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --solid --volume-size 32 \
  "$tmpdir/encrypted-solid-compressed-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --solid --volume-size 96 \
  "$tmpdir/encrypted-multi-solid-compressed-volume.rar" "$solid_one" "$solid_two"
run_rars_add --password pass --format rar50 --encrypt-headers \
  "$tmpdir/header-encrypted-compressed.rar" "$payload"
run_rars_add --password pass --format rar50 --encrypt-headers \
  --comment "RAR5 generated header-encrypted compressed comment" \
  "$tmpdir/header-encrypted-compressed-comment.rar" "$payload"
run_rars_add --password pass --format rar50 --encrypt-headers --solid \
  "$tmpdir/header-encrypted-solid-compressed.rar" "$solid_one" "$solid_two"
run_rars_add --password pass --format rar50 --encrypt-headers --volume-size 32 \
  "$tmpdir/header-encrypted-compressed-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --encrypt-headers --solid --volume-size 32 \
  "$tmpdir/header-encrypted-solid-compressed-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --encrypt-headers --solid --volume-size 96 \
  "$tmpdir/header-encrypted-multi-solid-compressed-volume.rar" "$solid_one" "$solid_two"
run_rars_add --password pass --format rar50 --store "$tmpdir/encrypted.rar" "$payload"
run_rars_add --password pass --format rar50 --store \
  --file-comment "RAR5 generated encrypted file comment" \
  "$tmpdir/encrypted-file-comment.rar" "$payload"
run_rars_add --password pass --format rar70 --store --archive-name encrypted-metadata.rar \
  "$tmpdir/encrypted-metadata.rar" "$payload"
run_rars_add --format rar70 --archive-name compressed-metadata.rar \
  "$tmpdir/compressed-metadata.rar" "$payload"
run_rars_add --format rar70 --dict-size 192k \
  "$tmpdir/rar70-v1-dictionary.rar" "$payload"
run_rars_add --password pass --format rar70 --archive-name encrypted-compressed-metadata.rar \
  "$tmpdir/encrypted-compressed-metadata.rar" "$payload"
run_rars_add --password pass --format rar50 --store --encrypt-headers \
  "$tmpdir/header-encrypted.rar" "$payload"
run_rars_add --password pass --format rar50 --store --encrypt-headers \
  --file-comment "RAR5 generated header-encrypted file comment" \
  "$tmpdir/header-encrypted-file-comment.rar" "$payload"
run_rars_add --password pass --format rar70 --store --encrypt-headers \
  --archive-name header-encrypted-metadata.rar \
  "$tmpdir/header-encrypted-metadata.rar" "$payload"
run_rars_add --password pass --format rar70 --encrypt-headers \
  --archive-name header-encrypted-compressed-metadata.rar \
  "$tmpdir/header-encrypted-compressed-metadata.rar" "$payload"
run_rars_add --format rar50 --store --recovery-percent 4 "$tmpdir/recovery.rar" "$payload"
run_rars_add --format rar50 --recovery-percent 4 "$tmpdir/compressed-recovery.rar" "$payload"
run_rars_add --format rar50 --store --recovery-percent 4 --volume-size 20 \
  "$tmpdir/recovery-volume.rar" "$payload"
run_rars_add --format rar50 --recovery-percent 4 --volume-size 20 \
  "$tmpdir/compressed-recovery-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --recovery-percent 4 \
  "$tmpdir/encrypted-compressed-recovery.rar" "$payload"
run_rars_add --password pass --format rar50 --recovery-percent 4 --volume-size 32 \
  "$tmpdir/encrypted-compressed-recovery-volume.rar" "$payload"
run_rars_add --password pass --format rar50 --store --encrypt-headers --recovery-percent 4 \
  "$tmpdir/header-encrypted-recovery.rar" "$payload"
run_rars_add --password pass --format rar50 --encrypt-headers --recovery-percent 4 \
  "$tmpdir/header-encrypted-compressed-recovery.rar" "$payload"

rar t "$tmpdir/stored.rar"
rar t "$tmpdir/file-comment.rar"
rar t "$tmpdir/compressed.rar"
rar t "$tmpdir/compressed-comment.rar"
rar t "$tmpdir/delta-filtered.rar"
rar t "$tmpdir/e8-filtered.rar"
rar t "$tmpdir/e8e9-filtered.rar"
rar t "$tmpdir/arm-filtered.rar"
rar t "$tmpdir/auto-filtered.rar"
rar t "$tmpdir/solid-compressed.rar"
rar t "$tmpdir/compressed-volume.part1.rar"
rar t "$tmpdir/solid-compressed-volume.part1.rar"
rar t "$tmpdir/multi-solid-compressed-volume.part1.rar"
rar t "$tmpdir/quick-open.rar"
rar t -ppass "$tmpdir/encrypted-compressed.rar"
rar t -ppass "$tmpdir/encrypted-compressed-comment.rar"
rar t -ppass "$tmpdir/encrypted-solid-compressed.rar"
rar t -ppass "$tmpdir/encrypted-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/encrypted-solid-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/encrypted-multi-solid-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/header-encrypted-compressed.rar"
rar t -ppass "$tmpdir/header-encrypted-compressed-comment.rar"
rar t -ppass "$tmpdir/header-encrypted-solid-compressed.rar"
rar t -ppass "$tmpdir/header-encrypted-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/header-encrypted-solid-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/header-encrypted-multi-solid-compressed-volume.part1.rar"
rar t -ppass "$tmpdir/encrypted.rar"
rar t -ppass "$tmpdir/encrypted-file-comment.rar"
rar t -ppass "$tmpdir/encrypted-metadata.rar"
rar t "$tmpdir/compressed-metadata.rar"
rar t "$tmpdir/rar70-v1-dictionary.rar"
rar t -ppass "$tmpdir/encrypted-compressed-metadata.rar"
rar t -ppass "$tmpdir/header-encrypted.rar"
rar t -ppass "$tmpdir/header-encrypted-file-comment.rar"
rar t -ppass "$tmpdir/header-encrypted-metadata.rar"
rar t -ppass "$tmpdir/header-encrypted-compressed-metadata.rar"

rar t "$tmpdir/recovery.rar"
rar t "$tmpdir/compressed-recovery.rar"
rar t "$tmpdir/recovery-volume.part1.rar"
rar t "$tmpdir/compressed-recovery-volume.part1.rar"
rar t -ppass "$tmpdir/encrypted-compressed-recovery.rar"
rar t -ppass "$tmpdir/encrypted-compressed-recovery-volume.part1.rar"
rar t -ppass "$tmpdir/header-encrypted-recovery.rar"
rar t -ppass "$tmpdir/header-encrypted-compressed-recovery.rar"

cargo test -p rars --test rar50_fixtures \
  reference_rar_accepts_rar50_acl_and_stream_file_service_records \
  -- --ignored --exact

echo
echo "RAR5 generated writer reference checks passed."
