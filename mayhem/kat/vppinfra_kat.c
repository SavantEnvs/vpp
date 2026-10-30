/* Known-answer probe for vppinfra, linked dynamically against the normally-built libvppinfra.so.
 * Every line is "kat <name> <value>"; mayhem/test.sh compares the output against fixed expectations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/serialize.h>
#include <vppinfra/macros.h>
#include <vppinfra/cJSON.h>
#include <vppinfra/elf.h>
#include <vppinfra/pcap.h>
#include <vppinfra/pcap_funcs.h>

static void
kat_unformat (void)
{
  unformat_input_t in;
  int d = 0;
  u32 x = 0, o = 0, b = 0;
  f64 f = 0;
  u8 *name = 0;

  unformat_init_string (&in, "-17 ff 17 101 2.5 hello", 23);
  if (!unformat (&in, "%d %x %o %b %f %s", &d, &x, &o, &b, &f, &name))
    printf ("kat unformat FAILED\n");
  else
    printf ("kat unformat %d %u %u %u %.1f %s\n", d, x, o, b, f, name);
  vec_free (name);
  unformat_free (&in);
}

static void
kat_format (void)
{
  u8 *s = format (0, "%5d|%-5d|%x|%s|%U", 42, 42, 255, "str", format_hex_bytes,
		  "\xde\xad\xbe", 3);
  vec_add1 (s, 0);
  printf ("kat format %s\n", s);
  vec_free (s);
}

static void
kat_cjson (void)
{
  cJSON *j = cJSON_Parse ("{\"a\":[1,2,{\"b\":\"c\"}],\"n\":3.5}");
  cJSON *a, *third, *b;
  char *out;

  if (!j)
    {
      printf ("kat cjson FAILED\n");
      return;
    }
  a = cJSON_GetObjectItem (j, "a");
  third = cJSON_GetArrayItem (a, 2);
  b = cJSON_GetObjectItem (third, "b");
  out = cJSON_PrintUnformatted (j);
  printf ("kat cjson %d %s %.1f %s\n", cJSON_GetArraySize (a), b->valuestring,
	  cJSON_GetObjectItem (j, "n")->valuedouble, out);
  cJSON_free (out);
  cJSON_Delete (j);
}

static void
kat_serialize (void)
{
  serialize_main_t sm, um;
  u8 *buf = 0;
  u32 v32 = 0;
  u8 *vec8 = 0, *back = 0, *p;
  clib_error_t *err;
  int i;

  vec_add (vec8, "abc", 3);

  serialize_open_vector (&sm, 0);
  serialize_integer (&sm, 0xdeadbeef, 4);
  serialize (&sm, serialize_vec_8, vec8, 3);
  buf = serialize_close_vector (&sm);

  printf ("kat serialize len=%u bytes=", (u32) vec_len (buf));
  for (p = buf; p < buf + vec_len (buf); p++)
    printf ("%02x", *p);
  printf ("\n");

  unserialize_open_data (&um, buf, vec_len (buf));
  unserialize_integer (&um, &v32, 4);
  vec_validate (back, 2);
  err = unserialize (&um, unserialize_vec_8, back, 3);
  printf ("kat unserialize %x %.3s err=%d\n", v32, back, err != 0);
  (void) i;
  vec_free (back);
  vec_free (vec8);
  vec_free (buf);
}

static void
kat_macro (void)
{
  clib_macro_main_t mm = { 0 };
  i8 *r;

  clib_macro_init (&mm);
  clib_macro_set_value (&mm, "foo", "this is foo which contains $(bar)");
  clib_macro_set_value (&mm, "bar", "bar");
  r = clib_macro_eval (&mm, (i8 *) "returns '$(foo)'", 0, 0, 8);
  printf ("kat macro %s\n", r);
  vec_free (r);
  clib_macro_free (&mm);
}

static void
kat_elf (void)
{
  elf_main_t em;
  clib_error_t *err = elf_read_file (&em, "/proc/self/exe");

  if (err)
    {
      printf ("kat elf FAILED\n");
      return;
    }
  printf ("kat elf class=%d machine=%d type=%d\n", em.first_header.file_class,
	  em.first_header.architecture, em.first_header.file_type);
  elf_main_free (&em);
}

static void
kat_pcap (void)
{
  char path[] = "/tmp/kat_pcap_XXXXXX";
  int fd = mkstemp (path);
  u32 fh[6] = { 0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1 };
  u32 ph[4] = { 100, 200, 4, 4 };
  u8 pkt[4] = { 1, 2, 3, 4 };
  pcap_main_t pm = { 0 };
  clib_error_t *err;

  if (fd < 0 || write (fd, fh, 24) != 24 || write (fd, ph, 16) != 16 ||
      write (fd, pkt, 4) != 4)
    {
      printf ("kat pcap FAILED setup\n");
      return;
    }
  close (fd);
  pm.file_name = path;
  err = pcap_read (&pm);
  unlink (path);
  if (err)
    {
      printf ("kat pcap FAILED\n");
      return;
    }
  printf ("kat pcap packets=%u first=%02x%02x%02x%02x ts=%llu\n",
	  (u32) vec_len (pm.packets_read), pm.packets_read[0][0],
	  pm.packets_read[0][1], pm.packets_read[0][2], pm.packets_read[0][3],
	  (unsigned long long) pm.timestamps[0]);
}

int
main (void)
{
  clib_mem_init (0, 64ULL << 20);
  kat_unformat ();
  kat_format ();
  kat_cjson ();
  kat_serialize ();
  kat_macro ();
  kat_elf ();
  kat_pcap ();
  return 0;
}
