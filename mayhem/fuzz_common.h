#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>

/* vppinfra needs its heap before any vec_/format use. */
static inline void
fuzz_init (void)
{
  static int done;
  if (!done)
    {
      clib_mem_init (0, 256ULL << 20);
      done = 1;
    }
}


/* Run each iteration on a throw-away heap so allocations left behind when a
 * parser bails out mid-way (longjmp, early return) cannot accumulate. */
typedef struct
{
  clib_mem_heap_t *old, *heap;
} fuzz_heap_t;

static inline void
fuzz_heap_enter (fuzz_heap_t *f, uword size)
{
  fuzz_init ();
  f->old = clib_mem_get_heap ();
  f->heap = clib_mem_create_heap (0, size, 0 /* is_locked */, "fuzz");
  if (!f->heap)
    abort ();
  clib_mem_set_heap (f->heap);
}

static inline void
fuzz_heap_leave (fuzz_heap_t *f)
{
  clib_mem_set_heap (f->old);
  clib_mem_destroy_heap (f->heap);
}

#endif
