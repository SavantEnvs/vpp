# elf_parse_sections: unchecked section count/offset from the ELF header

Cause: `elf_parse_sections()` (src/vppinfra/elf.c:724) does `vec_add (em->sections, file_data + section_header_file_offset, n_sections * entry_size)` using the header's `e_shnum`/`e_shoff` without checking them against the file size; a 64-byte file asks for a multi-gigabyte vector (`os_panic()`), and with a plausible count but an offset near the end of the file the `memcpy` reads past the mapped file (ASan SEGV in `clib_memcpy_fast`).

Impact: parsing a crafted ELF file aborts or crashes the reader (e.g. vppinfra-based tools, elf-section loaders).

Fix: validate `e_shoff + e_shnum * e_shentsize <= file size` (with overflow-safe arithmetic) before copying.

Reproduce: `/mayhem/fuzz_elf-standalone mayhem/fuzz_elf/known-findings/oom-section-count/repro.bin`.
