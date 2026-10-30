/* Fuzz vppinfra's ELF reader (elf.c): elf_read_file() maps a path, so each input goes through a temp file. */
#include "fuzz_common.h"
#include <vppinfra/elf.h>
#include <stdlib.h>
#include <unistd.h>

static int
run (const uint8_t *data, size_t size)
{
  char path[] = "/tmp/fuzz_elf_XXXXXX";
  elf_main_t em;
  clib_error_t *err;
  u8 *s;
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

  err = elf_read_file (&em, path);
  unlink (path);
  if (err)
    {
      clib_error_free (err);
      return -1;
    }

  s = format (0, "%U", format_elf_main, &em, 2);
  vec_free (s);
  elf_main_free (&em);
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  fuzz_heap_t h;
  int rv;

  if (size < 64 || size > 1 << 16)
    return -1;
  fuzz_heap_enter (&h, 16ULL << 20);
  rv = run (data, size);
  fuzz_heap_leave (&h);
  return rv;
}
