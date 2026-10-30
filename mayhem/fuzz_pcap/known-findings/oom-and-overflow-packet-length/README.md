# pcap_read: attacker-controlled packet sizes -> OOM abort / heap overflow

Cause: `pcap_read()` (src/vppinfra/pcap.c:196-197) allocates `vec_new (u8, ph.n_bytes_in_packet)` from the record header and then `read()`s `ph.n_packet_bytes_stored_in_file` bytes into it. Neither field is validated: a large `n_bytes_in_packet` aborts in `os_panic()`, and `stored > n_bytes_in_packet` writes past the vector (ASan: use-after-poison / heap-buffer-overflow inside `read`).

Impact: opening a crafted .pcap file aborts the process or corrupts the heap.

Fix: reject records with `n_packet_bytes_stored_in_file > n_bytes_in_packet` (and cap `n_bytes_in_packet`, e.g. at the file header's snaplen), allocate `stored` bytes.

Reproduce: `/mayhem/fuzz_pcap-standalone mayhem/fuzz_pcap/known-findings/oom-and-overflow-packet-length/repro.bin`.
