/* Fuzz vppinfra's unserialize() paths (serialize.c, elog.c): the wire format
 * used for saved event logs and for state handed between processes. */
#include "fuzz_common.h"
#include <vppinfra/serialize.h>
#include <vppinfra/elog.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/pool.h>
#include <vppinfra/heap.h>

typedef struct
{
  u32 a;
  u16 b;
  u8 c;
} rec_t;

static void
unserialize_rec (serialize_main_t *m, va_list *va)
{
  rec_t *r = va_arg (*va, rec_t *);
  u32 n = va_arg (*va, u32);
  u32 i, t;
  for (i = 0; i < n; i++)
    {
      unserialize_integer (m, &r[i].a, sizeof (r[i].a));
      unserialize_integer (m, &t, sizeof (r[i].b));
      r[i].b = t;
      unserialize_integer (m, &t, sizeof (r[i].c));
      r[i].c = t;
    }
}

static void
w_cstring (serialize_main_t *m, va_list *va)
{
  char **s = va_arg (*va, char **);
  unserialize_cstring (m, s);
}

static void
w_rec_multi (serialize_main_t *m, va_list *va)
{
  rec_t **vp = va_arg (*va, rec_t **);
  u32 n;
  unserialize_integer (m, &n, sizeof (n));
  n &= 0xff;
  vec_validate (*vp, n);
  unserialize_multiple (m, &(*vp)[0].a, sizeof ((*vp)[0].a), sizeof ((*vp)[0]), n);
  unserialize_multiple (m, &(*vp)[0].b, sizeof ((*vp)[0].b), sizeof ((*vp)[0]), n);
}

static void
w_ints (serialize_main_t *m, va_list *va)
{
  u32 mode = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < 8; i++)
    {
      u64 v = 0;
      switch (mode)
	{
	case 0:
	  v = unserialize_likely_small_unsigned_integer (m);
	  break;
	case 1:
	  v = unserialize_likely_small_signed_integer (m);
	  break;
	case 2:
	  unserialize_integer (m, &v, 1);
	  break;
	default:
	  unserialize_integer (m, &v, 8);
	  break;
	}
      (void) v;
    }
}

/* Past the end of the input, serialize_read_not_inline() promises zero padding but hands back unzeroed vec_resize()
 * memory (ASan: use-after-poison); report end-of-input as an error instead so truncated inputs don't mask real bugs. */
static void
input_exhausted (serialize_main_header_t *h, serialize_stream_t *s)
{
  serialize_error (h, clib_error_return (0, "end of input"));
}

static int
run (const uint8_t *data, size_t size)
{
  serialize_main_t m;
  clib_error_t *err = 0;
  u8 mode = data[0] & 15;

  unserialize_open_data (&m, (u8 *) data + 1, size - 1);
  m.header.data_function = input_exhausted;

  switch (mode)
    {
    case 0:
      {
	u8 *v = 0;
	err = unserialize (&m, unserialize_vector, (void *) &v, sizeof (v[0]), unserialize_vec_8);
	vec_free (v);
      }
      break;
    case 1:
      {
	u32 *v = 0;
	err = unserialize (&m, unserialize_vector, (void *) &v, sizeof (v[0]), unserialize_vec_32);
	vec_free (v);
      }
      break;
    case 2:
      {
	rec_t *v = 0;
	err = unserialize (&m, unserialize_vector, (void *) &v, sizeof (v[0]), unserialize_rec);
	vec_free (v);
      }
      break;
    case 3:
      {
	rec_t *v = 0;
	err = unserialize (&m, unserialize_aligned_vector, (void *) &v, sizeof (v[0]), unserialize_rec, 64);
	vec_free (v);
      }
      break;
    case 4:
      {
	char *s = 0;
	err = unserialize (&m, w_cstring, &s);
	vec_free (s);
      }
      break;
    case 5:
      {
	elog_main_t em = { 0 };
	err = unserialize (&m, unserialize_elog_main, &em);
	if (!err)
	  {
	    elog_event_t *e;
	    vec_foreach (e, em.events)
	      {
		u8 *s = format (0, "%U", format_elog_event, &em, e);
		vec_free (s);
	      }
	  }
      }
      break;
    case 6:
      {
	rec_t *v = 0;
	err = unserialize (&m, w_rec_multi, &v);
	vec_free (v);
      }
      break;
    case 7:
      {
	f64 f;
	f32 g;
	err = unserialize (&m, unserialize_f64, &f);
	if (!err)
	  err = unserialize (&m, unserialize_f32, &g);
      }
      break;
    case 8:
      {
	rec_t *p = 0;
	err = unserialize (&m, unserialize_pool, (void *) &p, sizeof (p[0]), unserialize_rec);
	pool_free (p);
      }
      break;
    case 9:
      {
	rec_t *h = 0;
	err = unserialize (&m, unserialize_heap, (void *) &h, unserialize_rec);
	heap_free (h);
      }
      break;
    default:
      err = unserialize (&m, w_ints, (u32) ((data[0] >> 4) & 3));
      break;
    }

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

  if (size < 2 || size > 4096)
    return -1;
  fuzz_heap_enter (&h, 16ULL << 20);
  rv = run (data, size);
  fuzz_heap_leave (&h);
  return rv;
}
