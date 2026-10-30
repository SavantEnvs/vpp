/* Fuzz vppinfra's unformat() parsers: the engine behind every VPP CLI command. */
#include "fuzz_common.h"
#include <vppinfra/time_range.h>
#include <vppinfra/bitmap.h>

static void
parse_cli_style (unformat_input_t *in)
{
  u32 a = 0, b = 0;
  u64 big = 0;
  f64 f = 0;
  u8 *s = 0, *hex = 0;
  uword sz = 0;
  uword *bm = 0;
  int guard = 0;

  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT && guard++ < 64)
    {
      if (unformat (in, "set %d %u", &a, &b))
	;
      else if (unformat (in, "size %U", unformat_memory_size, &sz))
	;
      else if (unformat (in, "hex %U", unformat_hex_string, &hex))
	{
	  vec_free (hex);
	  hex = 0;
	}
      else if (unformat (in, "cpus %U", unformat_bitmap_list, &bm))
	{
	  clib_bitmap_free (bm);
	  bm = 0;
	}
      else if (unformat (in, "mask %U", unformat_bitmap_mask, &bm))
	{
	  clib_bitmap_free (bm);
	  bm = 0;
	}
      else if (unformat (in, "f %f", &f))
	;
      else if (unformat (in, "big %llx", &big) || unformat (in, "big %lld", &big))
	;
      else if (unformat (in, "q %U", unformat_double_quoted_string, &s) ||
	       unformat (in, "q %U", unformat_single_quoted_string, &s) ||
	       unformat (in, "name %s", &s) || unformat (in, "tok %v", &s))
	{
	  vec_free (s);
	  s = 0;
	}
      else if (unformat (in, "d %U", unformat_data_size, &sz))
	;
      else if (unformat (in, "pg %U", unformat_log2_page_size, &a))
	;
      else if (unformat (in, "o %o %b", &a, &b))
	;
      else if (unformat (in, "%U", unformat_line, &s))
	{
	  vec_free (s);
	  s = 0;
	}
      else
	break;
    }
  vec_free (s);
  vec_free (hex);
}

static void
parse_bare_formats (unformat_input_t *in, u8 sel)
{
  u64 v = 0;
  u32 w = 0;
  f64 f = 0;
  u8 *s = 0;
  u8 u8v = 0;
  u16 u16v = 0;

  switch (sel & 7)
    {
    case 0:
      unformat (in, "%d", &w);
      break;
    case 1:
      unformat (in, "%llx", &v);
      break;
    case 2:
      unformat (in, "%f", &f);
      break;
    case 3:
      unformat (in, "%s", &s);
      break;
    case 4:
      unformat (in, "%U", unformat_u8, &u8v);
      break;
    case 5:
      unformat (in, "%U", unformat_u16, &u16v);
      break;
    case 6:
      {
	char arr[32];
	unformat (in, "%U", unformat_c_string_array, arr, (u32) sizeof (arr));
      }
      break;
    default:
      unformat (in, "%U", unformat_base10, &v);
      break;
    }
  vec_free (s);
}

static void
parse_time_ranges (unformat_input_t *in)
{
  clib_timebase_range_t *r = 0;
  /* "now" arithmetic in the range parser needs a clib_time. */
  static clib_time_t ct;
  static int ct_init;

  if (!ct_init)
    {
      clib_time_init (&ct);
      ct_init = 1;
    }
  unformat (in, "%U", unformat_clib_timebase_range_vector, &r);
  vec_free (r);
}

static int
fuzz_one (const uint8_t *data, size_t size)
{
  unformat_input_t in;

  if (size < 2 || size > 2048)
    return -1;

  unformat_init_string (&in, (char *) data + 1, size - 1);
  switch (data[0] & 3)
    {
    case 0:
      parse_cli_style (&in);
      break;
    case 1:
      parse_bare_formats (&in, data[0] >> 2);
      break;
    case 2:
      parse_time_ranges (&in);
      break;
    default:
      {
	u8 *fmt = 0;
	size_t i;
	u64 a = 0, b = 0;
	/* Format built from fuzz-chosen integer conversions; input is the remainder. */
	for (i = 0; i < size - 1 && i < 6; i++)
	  {
	    static const char *tab[] = { "%d ", "%x ", "%u ", "%o ", "%b ", "x" };
	    const char *t = tab[data[1 + i] % 6];
	    vec_add (fmt, t, strlen (t));
	  }
	vec_add1 (fmt, 0);
	unformat (&in, (char *) fmt, &a, &b, &a, &b, &a, &b);
	vec_free (fmt);
      }
      break;
    }
  unformat_free (&in);
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  fuzz_heap_t h;
  int rv;
  fuzz_heap_enter (&h, 2ULL << 20);
  rv = fuzz_one (data, size);
  fuzz_heap_leave (&h);
  return rv;
}
