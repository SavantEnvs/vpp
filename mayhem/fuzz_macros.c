/* Fuzz vppinfra's $(var) macro expander: the input is split at the first NUL
 * into a variable definition list ("name=value" lines) and a template. */
#include "fuzz_common.h"
#include <vppinfra/macros.h>

static int
fuzz_one (const uint8_t *data, size_t size)
{
  clib_macro_main_t mm = { 0 };
  u8 *defs, *tmpl;
  size_t split, i;
  i8 *rv;

  if (size > 1024)
    return -1;
  for (split = 0; split < size && data[split]; split++)
    ;

  defs = 0;
  vec_add (defs, data, split);
  vec_add1 (defs, 0);
  tmpl = 0;
  if (split < size)
    vec_add (tmpl, data + split + 1, size - split - 1);
  vec_add1 (tmpl, 0);

  clib_macro_init (&mm);

  /* Each line "name=value" defines a macro. */
  for (i = 0; i < vec_len (defs) - 1;)
    {
      u8 *line = defs + i, *eol = line, *eq;
      while (*eol && *eol != '\n')
	eol++;
      eq = line;
      while (eq < eol && *eq != '=')
	eq++;
      if (eq < eol)
	{
	  u8 *name = 0, *value = 0;
	  vec_add (name, line, eq - line);
	  vec_add1 (name, 0);
	  vec_add (value, eq + 1, eol - eq - 1);
	  vec_add1 (value, 0);
	  clib_macro_set_value (&mm, (char *) name, (char *) value);
	  vec_free (name);
	  vec_free (value);
	}
      i = (eol - defs) + (*eol ? 1 : 0);
      if (!*eol)
	break;
    }

  rv = clib_macro_eval (&mm, (i8 *) tmpl, 0 /* complain */, 0, 8);
  vec_free (rv);
  rv = clib_macro_eval_dollar (&mm, (i8 *) tmpl, 0);
  vec_free (rv);

  clib_macro_free (&mm);
  vec_free (defs);
  vec_free (tmpl);
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
