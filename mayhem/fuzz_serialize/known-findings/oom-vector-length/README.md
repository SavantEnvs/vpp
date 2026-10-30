# unserialize_vector: unchecked u32 element count -> allocation abort

Cause: `unserialize_vector_ha()` (src/vppinfra/serialize.c:283-288) reads a 32-bit length from the stream and passes it straight to `_vec_alloc_internal()`; `max_length` is `~0` for both `unserialize_vector` and `unserialize_aligned_vector`, so a 5-byte input asks for gigabytes and `clib_mem_heap_alloc` calls `os_panic()`.

Impact: any process that unserializes untrusted data (saved elogs, API state) can be aborted with a few bytes (denial of service). The same pattern is in the pool/heap/elog unserializers.

Fix: bound the length against the bytes remaining in the stream (each element needs at least one byte), e.g. `serialize_error` when `l > max_length` with a sane `max_length`, or when `l` exceeds the remaining input.

Reproduce: `/mayhem/fuzz_serialize-standalone mayhem/fuzz_serialize/known-findings/oom-vector-length/repro.bin` (abort, "Out-of-memory, calling os_panic()").
