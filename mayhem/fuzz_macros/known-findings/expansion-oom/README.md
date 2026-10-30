# clib_macro_eval: unbounded recursive/multiplicative expansion -> OOM abort; trailing backslash over-read

Cause: `clib_macro_eval()` (src/vppinfra/macros.c) appends the expansion of `$name` recursively with no growth limit, so a macro that references itself repeatedly (or a short chain of doubling macros) grows the output vector until `os_panic()`; independently, the `case '\\'` branch does `s++; vec_add1 (rv, *s)` and so skips the terminating NUL when the string ends in a backslash (ASan use-after-poison at macros.c:97).

Impact: a template/macro definition supplied by a user can abort the process or read past the end of the string.

Fix: stop at the NUL after an escape, and cap the expanded length (or reject recursive definitions).

Reproduce: `/mayhem/fuzz_macros-standalone mayhem/fuzz_macros/known-findings/expansion-oom/repro.bin`.
