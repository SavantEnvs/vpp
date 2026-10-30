#!/usr/bin/env bash
#
# mayhem/test.sh — RUN vppinfra's tests and a known-answer probe (all built by mayhem/build.sh, normal flags).
# exit 0 = pass. The oracle is value-based: vppinfra_kat prints computed results (parse/format/JSON/serialize/
# macro/ELF/pcap) that are compared with fixed expectations, and test_infra must print its named PASS lines.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TEST_BUILD="$SRC/build-root/build-mayhem-test"
BIN="$TEST_BUILD/bin"
passed=0
failed=0
fail() { echo "FAIL: $*" >&2; failed=$((failed + 1)); }
ok() { passed=$((passed + 1)); }

# 1) Known-answer probe: exact expected lines (any missing line is a failure).
EXPECT='kat unformat -17 255 15 5 2.5 hello
kat format    42|42   |ff|str|deadbe
kat cjson 3 c 3.5 {"a":[1,2,{"b":"c"}],"n":3.5}
kat serialize len=7 bytes=deadbeef616263
kat unserialize deadbeef abc err=0
kat macro returns '"'"'this is foo which contains bar'"'"'
kat elf class=2 machine=62 type=3
kat pcap packets=1 first=01020304 ts=100000200'
[ -x "$SRC/vppinfra_kat" ] || { echo "missing $SRC/vppinfra_kat (build.sh bug)" >&2; emit_ctrf "vppinfra" 0 1 0; exit 1; }
kat_out="$("$SRC/vppinfra_kat" 2>&1)" || fail "vppinfra_kat exited non-zero"
while IFS= read -r line; do
  if printf '%s\n' "$kat_out" | grep -qxF -- "$line"; then ok; else fail "known answer missing: $line"; fi
done <<< "$EXPECT"

# 2) vppinfra's own assertion suite (test_infra): every check prints "<name> PASS" or "<name> FAIL", once per CPU
#    multiarch variant the host supports. Require each named check to PASS at least once (the default variant
#    runs on every CPU) and no FAIL anywhere, so the result does not depend on the host's vector extensions.
[ -x "$BIN/test_infra" ] || { echo "missing $BIN/test_infra (build.sh bug)" >&2; emit_ctrf "vppinfra" 0 1 0; exit 1; }
infra_out="$(timeout 600 "$BIN/test_infra" 2>&1)" || fail "test_infra exited non-zero"
n_fail=$(printf '%s\n' "$infra_out" | grep -cE ' FAIL' || true)
[ "$n_fail" -eq 0 ] || fail "test_infra reported $n_fail FAIL lines"
for name in clib_toeplitz_hash_x4 clib_toeplitz_hash clib_hmac_sha512 clib_hmac_sha384 clib_hmac_sha256 \
            clib_hmac_sha224 clib_memcpy_x86_64 clib_mask_compare_u64 clib_mask_compare_u32 clib_mask_compare_u16 \
            clib_ip_csum clib_index_to_ptr_u32 clib_dynamic_shuffle clib_crc32c clib_count_equal_u64 \
            clib_count_equal_u32 clib_count_equal_u16 clib_count_equal_u8 clib_compress_u8 clib_compress_u16 \
            clib_compress_u32 clib_compress_u64 clib_array_mask_u32 clib_poly1305; do
  if printf '%s\n' "$infra_out" | grep -qE "^$name +PASS$"; then ok; else fail "test_infra: $name did not PASS"; fi
done

# 3) Remaining vppinfra unit binaries: they assert internally (ASSERT/clib_error -> non-zero exit).
for t in test_format test_serialize test_vec test_hash test_mhash test_elog test_dlist test_pool_iterate test_ptclosure; do
  [ -x "$BIN/$t" ] || { fail "missing $BIN/$t"; continue; }
  if timeout 600 "$BIN/$t" >/dev/null 2>&1; then ok; else fail "$t exited non-zero"; fi
done

# test_macros prints the evaluated macro; check the value.
macro_out="$(timeout 60 "$BIN/test_macros" 2>&1)" || fail "test_macros exited non-zero"
if printf '%s\n' "$macro_out" | grep -qxF "evaluate: returns 'this is foo which contains bar'"; then ok; else fail "test_macros: wrong macro expansion"; fi

emit_ctrf "vppinfra" "$passed" "$failed" 0
