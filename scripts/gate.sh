#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build and run the complete pure seeded OM-2 omega-ledger gate suite on DGX Spark CPU 7.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OMC_BIN="${OMC_BIN:-$HOME/canon/omega-mv/seed/out/omc}"
PINNED_OMC_SHA="28fca13d44054e26f78c33d1753fd5c005d08e9144d95985c90bd75b60885072"
SHA256_REF="${SHA256_REF:-$HOME/canon/omega-mv/seed/ng/sha256.om}"
CPU_PIN="${CPU_PIN:-7}"

ACTUAL_SHA="$(sha256sum "$OMC_BIN" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$PINNED_OMC_SHA" ]; then
  echo "GATE_FAIL omc_sha256=$ACTUAL_SHA expected=$PINNED_OMC_SHA" >&2
  exit 2
fi
echo "OMC_PIN_OK sha256=$ACTUAL_SHA"

mkdir -p bin

compile_om() {
  local out_bin="$1"
  shift
  cat "$@" | "$OMC_BIN" > "${out_bin}.tmp"
  chmod +x "${out_bin}.tmp"
  mv -f "${out_bin}.tmp" "$out_bin"
}

compile_om bin/omega-ledger-gate om/ledger_core.om om/ledger_gate.om
compile_om bin/omega-ledger-bench om/ledger_core.om om/ledger_bench.om
compile_om bin/test-overflow-trap om/ledger_core.om om/test_overflow_trap.om
compile_om bin/test-sha256-parity om/ledger_core.om "$SHA256_REF" om/test_sha256_parity.om

BENCH_BYTES="$(stat -c %s bin/omega-ledger-bench)"
GATE_BYTES="$(stat -c %s bin/omega-ledger-gate)"
echo "ELF_SIZES omega-ledger-bench=${BENCH_BYTES}B omega-ledger-gate=${GATE_BYTES}B"

echo "=== [1/3] FIPS 180-4 SHA-256 Parity vs seed/ng/sha256.om (CPU ${CPU_PIN}) ==="
taskset -c "$CPU_PIN" ./bin/test-sha256-parity

echo "=== [2/3] Hardware Signed-64 Overflow Trap Negative Control (CPU ${CPU_PIN}, expect exit 101) ==="
set +e
taskset -c "$CPU_PIN" ./bin/test-overflow-trap
OV_RC=$?
set -e
echo "OVERFLOW_TRAP_EXIT=$OV_RC"
if [ "$OV_RC" -ne 101 ]; then
  echo "GATE_FAIL expected overflow trap exit 101, got $OV_RC" >&2
  exit 1
fi

echo "=== [3/3] Full Ledger Refusal, Single-Bit Tamper & 100k Delta vs Full-Scan Gate (CPU ${CPU_PIN}) ==="
taskset -c "$CPU_PIN" ./bin/omega-ledger-gate

echo "ALL_OM2_GATES_PASS"
