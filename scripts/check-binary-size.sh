#!/usr/bin/env bash
# Enforce a binary size budget on the release `ua` binary built with
# `--features embeddings` (docs/memory.md §2, acceptance item 7).
set -euo pipefail

BIN="${1:-target/release/ua}"
# Recorded release budget in bytes: calibrated from the measured x86_64 Linux
# `cargo build -p ua-cli --release --features embeddings` binary
# (90,568,680 bytes / 86.37 MiB, statically linked with ONNX Runtime) plus
# ~25% headroom. Update with a fresh measurement when changed.
MAX_BYTES="${UA_RELEASE_MAX_BYTES:-115000000}"

if [[ ! -f "$BIN" ]]; then
  echo "check-binary-size: binary not found: $BIN" >&2
  exit 2
fi

SIZE=$(stat -c '%s' "$BIN" 2>/dev/null || stat -f '%z' "$BIN")
SIZE_MB=$(awk -v b="$SIZE" 'BEGIN { printf "%.2f", b / 1048576 }')
MAX_MB=$(awk -v b="$MAX_BYTES" 'BEGIN { printf "%.2f", b / 1048576 }')

echo "check-binary-size: $BIN is ${SIZE} bytes (${SIZE_MB} MiB); budget is ${MAX_BYTES} bytes (${MAX_MB} MiB)"
if (( SIZE > MAX_BYTES )); then
  echo "check-binary-size: FAIL — exceeds budget by $((SIZE - MAX_BYTES)) bytes" >&2
  exit 1
fi
echo "check-binary-size: PASS"
