/* t_json_writer.c - gw_core/gw_json_writer.c: modes, grammar, numbers, escaping, sticky errors. */
#include <stdint.h>

#include "bt.h"
#include "gw_core/gw_json_writer.h"

static char g_sink[4096];
static size_t g_sink_len;
static int g_sink_calls, g_sink_zero_calls, g_sink_fail_after = -1;

static int sink(void *arg, const char *data, size_t len) {
    (void)arg;
    if (len == 0)
        g_sink_zero_calls++;
    if (g_sink_fail_after >= 0 && g_sink_calls >= g_sink_fail_after)
        return -1;
    g_sink_calls++;
    if (g_sink_len + len < sizeof(g_sink)) {
        memcpy(g_sink + g_sink_len, data, len);
        g_sink_len += len;
        g_sink[g_sink_len] = '\0';
    }
    return 0;
}

static const char *one_str(const char *s, size_t n, char *buf, size_t cap) {
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, cap);
    gw_jw_strn(&w, s, n);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    return buf;
}

static void test_basic(void) {
    char b[256];
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_obj_open(&w);
    gw_jw_kint(&w, "a", 1);
    gw_jw_karr(&w, "b");
    gw_jw_bool(&w, true);
    gw_jw_bool(&w, false);
    gw_jw_null(&w);
    gw_jw_arr_close(&w);
    gw_jw_kstr(&w, "c", "x");
    gw_jw_kobj(&w, "d");
    gw_jw_obj_close(&w);
    gw_jw_karr(&w, "e");
    gw_jw_arr_close(&w);
    gw_jw_kuint(&w, "f", UINT64_MAX);
    gw_jw_kint(&w, "g", INT64_MIN);
    gw_jw_knull(&w, "h");
    gw_jw_kbool(&w, "i", true);
    gw_jw_key(&w, "j");
    gw_jw_raw(&w, "{\"x\":[1,2]}", 11);
    gw_jw_kstr(&w, "k", NULL);
    gw_jw_obj_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(gw_jw_data(&w), "{\"a\":1,\"b\":[true,false,null],\"c\":\"x\",\"d\":{},\"e\":[],"
                              "\"f\":18446744073709551615,\"g\":-9223372036854775808,\"h\":null,\"i\":true,"
                              "\"j\":{\"x\":[1,2]},\"k\":null}");
    CHECK_EQ(gw_jw_length(&w), strlen(b));

    /* top-level scalar and array */
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_int(&w, -42);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(b, "-42");
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_arr_open(&w);
    gw_jw_int(&w, 1);
    gw_jw_arr_open(&w);
    gw_jw_arr_close(&w);
    gw_jw_obj_open(&w);
    gw_jw_obj_close(&w);
    gw_jw_str(&w, "");
    gw_jw_arr_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(b, "[1,[],{},\"\"]");
    /* empty writer finishes OK with empty output */
    gw_jw_init_fixed(&w, b, sizeof(b));
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(b, "");
}

static void test_fixed_numbers(void) {
    static const struct {
        int64_t v;
        uint16_t div;
        const char *want;
    } cases[] = {
        {235, 10, "23.5"},   {-5, 10, "-0.5"},       {7, 1, "7"},          {0, 10, "0.0"},
        {-1234, 100, "-12.34"}, {5, 1000, "0.005"},  {-250, 10, "-25.0"},  {850, 10, "85.0"},
        {1, 100, "0.01"},    {-1, 1000, "-0.001"},   {100000, 1000, "100.000"},
        {INT64_MIN, 10, "-922337203685477580.8"},    {INT64_MAX, 1000, "9223372036854775.807"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char b[64];
        gw_jw_t w;
        gw_jw_init_fixed(&w, b, sizeof(b));
        gw_jw_fixed(&w, cases[i].v, cases[i].div);
        CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
        CHECK_STR(b, cases[i].want);
    }
    char b[64];
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_arr_open(&w);
    gw_jw_fixed(&w, 1, 3); /* invalid divisor */
    gw_jw_int(&w, 1);      /* sticky: no-op */
    gw_jw_arr_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_STATE);
    CHECK_EQ(gw_jw_error(&w), GW_JW_E_STATE);
}

static int grammar_case(int which) {
    char b[128];
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    switch (which) {
    case 0: /* value without key */
        gw_jw_obj_open(&w);
        gw_jw_int(&w, 1);
        gw_jw_obj_close(&w);
        break;
    case 1: /* key inside array */
        gw_jw_arr_open(&w);
        gw_jw_key(&w, "a");
        break;
    case 2: /* mismatched close */
        gw_jw_obj_open(&w);
        gw_jw_arr_close(&w);
        break;
    case 3: /* close without open */
        gw_jw_obj_close(&w);
        break;
    case 4: /* unclosed container */
        gw_jw_obj_open(&w);
        break;
    case 5: /* dangling key */
        gw_jw_obj_open(&w);
        gw_jw_key(&w, "a");
        gw_jw_obj_close(&w);
        break;
    case 6: /* two keys in a row */
        gw_jw_obj_open(&w);
        gw_jw_key(&w, "a");
        gw_jw_key(&w, "b");
        break;
    case 7: /* second top-level value */
        gw_jw_int(&w, 1);
        gw_jw_int(&w, 2);
        break;
    case 8: /* depth limit */
        for (int i = 0; i <= GW_JW_MAX_DEPTH; i++)
            gw_jw_arr_open(&w);
        break;
    case 9: /* NULL key */
        gw_jw_obj_open(&w);
        gw_jw_key(&w, NULL);
        break;
    case 10: /* empty raw */
        gw_jw_raw(&w, "", 0);
        break;
    default:
        break;
    }
    return gw_jw_finish(&w);
}

static void test_grammar(void) {
    for (int i = 0; i <= 10; i++)
        CHECK_EQ(grammar_case(i), GW_JW_E_STATE);
    /* exactly the maximum depth is fine */
    char b[128];
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    for (int i = 0; i < GW_JW_MAX_DEPTH; i++)
        gw_jw_arr_open(&w);
    for (int i = 0; i < GW_JW_MAX_DEPTH; i++)
        gw_jw_arr_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_EQ(strlen(b), 2 * GW_JW_MAX_DEPTH);
}

static void test_fixed_overflow(void) {
    char b[8];
    memset(b, 'Z', sizeof(b));
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_arr_open(&w);
    gw_jw_str(&w, "abcdef"); /* "[\"abcdef\"" = 9 > 7 */
    gw_jw_arr_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_OVERFLOW);
    CHECK(memchr(b, '\0', sizeof(b)) != NULL);
    /* exact fit: cap - 1 bytes of output */
    char c[4];
    gw_jw_init_fixed(&w, c, sizeof(c));
    gw_jw_int(&w, 123);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(c, "123");
    gw_jw_init_fixed(&w, c, sizeof(c));
    gw_jw_int(&w, 1234);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_OVERFLOW);
}

static void test_dynamic(void) {
    gw_jw_t w;
    CHECK_EQ(gw_jw_init_dynamic(&w, 16, 1 << 20), GW_JW_OK);
    gw_jw_arr_open(&w);
    for (int i = 0; i < 1000; i++)
        gw_jw_int(&w, i);
    gw_jw_arr_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    size_t len = 0;
    char *s = gw_jw_detach(&w, &len);
    CHECK(s != NULL);
    CHECK_EQ(len, strlen(s));
    CHECK(s && strncmp(s, "[0,1,2,", 7) == 0 && s[len - 1] == ']');
    CHECK_EQ(len, gw_jw_length(&w));
    free(s);
    CHECK(gw_jw_detach(&w, &len) == NULL);
    gw_jw_free(&w);
    gw_jw_free(&w); /* twice is safe */

    CHECK_EQ(gw_jw_init_dynamic(&w, 16, 32), GW_JW_OK);
    gw_jw_str(&w, "0123456789012345678901234567890123456789");
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_OVERFLOW);
    gw_jw_free(&w);
}

static void test_stream(void) {
    char scratch[16];
    gw_jw_t w;
    g_sink_len = 0;
    g_sink_calls = g_sink_zero_calls = 0;
    g_sink_fail_after = -1;
    gw_jw_init_stream(&w, scratch, sizeof(scratch), sink, NULL);
    gw_jw_obj_open(&w);
    for (int i = 0; i < 20; i++) {
        char k[8];
        snprintf(k, sizeof(k), "k%d", i);
        gw_jw_kfixed(&w, k, i * 7 - 50, 10);
    }
    gw_jw_kstr(&w, "s", "a very long string value that spans several sink chunks \"quoted\"");
    gw_jw_obj_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK(g_sink_calls > 3);
    CHECK_EQ(g_sink_zero_calls, 0);
    CHECK_EQ(gw_jw_length(&w), g_sink_len);
    CHECK(strncmp(g_sink, "{\"k0\":-5.0,\"k1\":-4.3,", 21) == 0);
    CHECK(strstr(g_sink, "\\\"quoted\\\"\"}") != NULL);

    /* finish of an exactly-flushed buffer does not call the sink with len 0 */
    g_sink_len = 0;
    g_sink_calls = g_sink_zero_calls = 0;
    gw_jw_init_stream(&w, scratch, 4, sink, NULL);
    gw_jw_int(&w, 1234);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(g_sink, "1234");
    CHECK_EQ(g_sink_zero_calls, 0);

    /* sink failure is sticky */
    g_sink_len = 0;
    g_sink_calls = 0;
    g_sink_fail_after = 1;
    gw_jw_init_stream(&w, scratch, 4, sink, NULL);
    gw_jw_str(&w, "0123456789abcdef");
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_SINK);
    g_sink_fail_after = -1;

    /* bad stream setup */
    gw_jw_init_stream(&w, NULL, 0, sink, NULL);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_STATE);
}

static void test_escaping(void) {
    char b[256];
    CHECK_STR(one_str("a\"b\\c", 5, b, sizeof(b)), "\"a\\\"b\\\\c\"");
    CHECK_STR(one_str("\n\r\t\b\f", 5, b, sizeof(b)), "\"\\n\\r\\t\\b\\f\"");
    CHECK_STR(one_str("\x01\x1f", 2, b, sizeof(b)), "\"\\u0001\\u001f\"");
    CHECK_STR(one_str("a\0b", 3, b, sizeof(b)), "\"a\\u0000b\"");
    CHECK_STR(one_str("</script>", 9, b, sizeof(b)), "\"<\\/script>\"");
    CHECK_STR(one_str("a/b", 3, b, sizeof(b)), "\"a/b\"");
    CHECK_STR(one_str("\x7f", 1, b, sizeof(b)), "\"\x7f\"");
    /* UTF-8 passthrough: Hangul, 4-byte emoji-plane code point, U+FFFF */
    CHECK_STR(one_str("현재온도", strlen("현재온도"), b, sizeof(b)), "\"현재온도\"");
    CHECK_STR(one_str("\xF0\x9F\x98\x80", 4, b, sizeof(b)), "\"\xF0\x9F\x98\x80\"");
    CHECK_STR(one_str("\xEF\xBF\xBF", 3, b, sizeof(b)), "\"\xEF\xBF\xBF\"");
    /* invalid sequences -> U+FFFD per bad byte */
    CHECK_STR(one_str("a\xff" "b", 3, b, sizeof(b)), "\"a\xEF\xBF\xBD" "b\"");
    CHECK_STR(one_str("\xC0\xAF", 2, b, sizeof(b)), "\"\xEF\xBF\xBD\xEF\xBF\xBD\""); /* overlong '/' */
    CHECK_STR(one_str("\xED\xA0\x80", 3, b, sizeof(b)),
              "\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\""); /* surrogate */
    CHECK_STR(one_str("\xE2\x82", 2, b, sizeof(b)), "\"\xEF\xBF\xBD\xEF\xBF\xBD\""); /* truncated */
    CHECK_STR(one_str("\xF4\x90\x80\x80", 4, b, sizeof(b)),
              "\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\""); /* > U+10FFFF */
    /* keys are escaped too */
    gw_jw_t w;
    gw_jw_init_fixed(&w, b, sizeof(b));
    gw_jw_obj_open(&w);
    gw_jw_kint(&w, "k\"\n", 1);
    gw_jw_obj_close(&w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK_STR(b, "{\"k\\\"\\n\":1}");
}

int main(void) {
    test_basic();
    test_fixed_numbers();
    test_grammar();
    test_fixed_overflow();
    test_dynamic();
    test_stream();
    test_escaping();
    return BT_DONE();
}
