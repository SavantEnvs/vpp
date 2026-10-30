/* Fuzz vppinfra's pcap file reader (pcap.c). pcap_read() takes a path, so each input goes through a temp file. */
#include "fuzz_common.h"
#include <vppinfra/pcap.h>
#include <vppinfra/pcap_funcs.h>
#include <stdlib.h>
#include <unistd.h>

static int
run (const uint8_t *data, size_t size)
{
  char path[] = "/tmp/fuzz_pcap_XXXXXX";
  pcap_main_t pm = { 0 };
  clib_error_t *err;
  int fd = mkstemp (path);

  if (fd < 0)
    return -1;
  if (write (fd, data, size) != (ssize_t) size)
    {
      close (fd);
      unlink (path);
      return -1;
    }
  close (fd);

  pm.file_name = path;
  err = pcap_read (&pm);
  unlink (path);
  if (err)
    {
      clib_error_free (err);
      return -1;
    }
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  fuzz_heap_t h;
  int rv;

  if (size > 1 << 16)
    return -1;
  fuzz_heap_enter (&h, 16ULL << 20);
  rv = run (data, size);
  fuzz_heap_leave (&h);
  return rv;
}
