/* Fuzz the cJSON parser/printer bundled in vppinfra. */
#include "fuzz_common.h"
#include <vppinfra/cJSON.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  cJSON *j, *dup;
  char *out;

  fuzz_init ();
  if (size > 65536)
    return -1;

  j = cJSON_ParseWithLength ((const char *) data, size);
  if (!j)
    return -1;

  out = cJSON_PrintUnformatted (j);
  if (out)
    {
      cJSON *again = cJSON_Parse (out);
      if (again)
	cJSON_Delete (again);
      cJSON_free (out);
    }
  out = cJSON_Print (j);
  if (out)
    cJSON_free (out);

  dup = cJSON_Duplicate (j, 1);
  if (dup)
    {
      cJSON_Compare (j, dup, 1);
      cJSON_Delete (dup);
    }
  cJSON_Delete (j);
  return 0;
}
