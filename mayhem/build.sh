#!/usr/bin/env bash
#
# mayhem/build.sh — build the vppinfra fuzz harnesses (sanitized), their standalone reproducers, and
# the normal-flags test suite + known-answer probe that mayhem/test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FUZZ_BUILD="$SRC/build-root/build-mayhem-fuzz"
TEST_BUILD="$SRC/build-root/build-mayhem-test"
# A re-run may resolve the compiler differently (ccache prefill wrapper vs /usr/bin/clang); CMake then discards its
# cache and silently drops the -D options of that run (tests OFF), so always configure from empty trees.
rm -rf "$FUZZ_BUILD" "$TEST_BUILD"
ARCH_FLAGS="-march=x86-64-v2"

# VPP's CMake derives its version from `git describe --match 'v*'`; give it a fallback when the clone has no tags.
if [ ! -f src/scripts/.version ] && ! git describe --long --match 'v*' >/dev/null 2>&1; then
  echo "v27.02-rc0-0-g0000000" > src/scripts/.version
fi

# 1) vppinfra with sanitizers + SanCov + DWARF<=3 (the fuzzed code itself is instrumented).
#    VPP's CMake only builds vppinfra here; vlib/vnet need ~35 min under ASan and are out of scope.
#    UBSan `pointer-overflow` and `null` are relaxed for the library: vppinfra's hash lookup (hash.h hash_forward,
#    hash.c lookup's `return &p->direct` with p == NULL) forms zero-offset/NULL-member addresses on every key miss,
#    which would flag every input as the same benign-pattern defect. Real NULL dereferences still SEGV under ASan.
#    `alignment` (unaligned u32/u64 wire-format loads in byte_order.h) and `shift-base` (1 << 31 in heap.h) are also
#    relaxed: both are deliberate, harmless on x86 and would flag every serialized input. `builtin` (min_log2 (0)
#    -> clz (0)) and `nonnull-attribute` (memcpy/memcmp (NULL, 0) in hash.c) fire on trivial empty-input paths.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow,null,alignment,shift-base,builtin,nonnull-attribute -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S src -B "$FUZZ_BUILD" -G Ninja -DCMAKE_BUILD_TYPE=release \
  -DCMAKE_C_COMPILER="$CC" -DVPP_USE_LTO=OFF \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
ninja -C "$FUZZ_BUILD" -j"$MAYHEM_JOBS" vppinfra
FUZZ_LIB="$(dirname "$(find "$FUZZ_BUILD" -name libvppinfra.so -print -quit)")"
[ -f "$FUZZ_LIB/libvppinfra.so" ] || { echo "libvppinfra.so missing under $FUZZ_BUILD" >&2; exit 1; }
RPATH_FUZZ="-Wl,-rpath,\$ORIGIN/${FUZZ_LIB#"$SRC"/}"

# 2) Harnesses: fuzzer binary + standalone reproducer each, with LSan switched off at build time.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ_BUILD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

HARNESSES="fuzz_unformat fuzz_cjson fuzz_serialize fuzz_elf fuzz_pcap fuzz_macros"
HFLAGS="-I$SRC/src -I$FUZZ_BUILD/CMakeFiles $ARCH_FLAGS -fno-common -Wno-address-of-packed-member"
for h in $HARNESSES; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $HFLAGS $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$h.c" "$FUZZ_BUILD/lsan_off.o" \
      -L"$FUZZ_LIB" -lvppinfra $RPATH_FUZZ -o "/mayhem/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $HFLAGS \
      "$SRC/mayhem/$h.c" "$FUZZ_BUILD/standalone_main.o" "$FUZZ_BUILD/lsan_off.o" \
      -L"$FUZZ_LIB" -lvppinfra $RPATH_FUZZ -o "/mayhem/$h-standalone"
done

# 3) Test suite + KAT probe with the project's NORMAL flags (no sanitizers, no DWARF pin), in a separate tree.
cmake -S src -B "$TEST_BUILD" -G Ninja -DCMAKE_BUILD_TYPE=release \
  -DCMAKE_C_COMPILER="$CC" -DVPP_USE_LTO=OFF -DVPP_BUILD_VPPINFRA_TESTS=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$COVERAGE_FLAGS"
ninja -C "$TEST_BUILD" -j"$MAYHEM_JOBS" vppinfra test_infra test_macros test_format test_serialize \
  test_vec test_hash test_mhash test_elog test_heap test_dlist test_fifo test_pool_iterate test_ptclosure
TEST_LIB="$(dirname "$(find "$TEST_BUILD" -name libvppinfra.so -print -quit)")"
$CC -O2 $COVERAGE_FLAGS -I"$SRC/src" -I"$TEST_BUILD/CMakeFiles" $ARCH_FLAGS \
    "$SRC/mayhem/kat/vppinfra_kat.c" -L"$TEST_LIB" -lvppinfra \
    "-Wl,-rpath,\$ORIGIN/${TEST_LIB#"$SRC"/}" -o /mayhem/vppinfra_kat
file /mayhem/vppinfra_kat | grep -q 'dynamically linked'
