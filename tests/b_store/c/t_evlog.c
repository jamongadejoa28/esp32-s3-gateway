/* t_evlog.c - store/evlog_core.c: two-file rings, rotation, seq recovery, torn tails, RAM-tail
 * merge, newest-first paging with filters, type names. */
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <unistd.h>

#include "bt.h"
#include "evlog_core.h"

static char g_dir[512];

static evlog_rec_t rec(uint32_t seq) {
    evlog_rec_t r;
    memset(&r, 0, sizeof(r));
    r.seq = seq;
    r.ts = 1792371600u + seq;
    r.dev = (uint16_t)(seq % 3 == 0 ? EVLOG_DEV_NONE : seq % 3);
    r.code = (uint16_t)(seq % 1000);
    r.type = (uint8_t)(seq % 2 ? EVT_ALARM_RAISE : EVT_COMM_LOST);
    r.sev = (uint8_t)(seq % 4);
    r.value = (int16_t)-(int32_t)(seq % 500);
    snprintf(r.user, sizeof(r.user), "u%u", (unsigned)(seq % 10));
    r.extra = seq * 7;
    return r;
}

static void append_range(evlog_files_t *f, uint32_t from, uint32_t to) {
    static evlog_rec_t buf[512];
    while (from <= to) {
        uint32_t n = 0;
        while (from <= to && n < 512)
            buf[n++] = rec(from++);
        CHECK_EQ(evlog_files_append(f, buf, n), ESP_OK);
    }
}

static long fsize(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

static evlog_rec_t g_out[EVLOG_QUERY_MAX + 10];

/* all matching seqs newest first, by paging with `page` */
static uint32_t page_all(evlog_files_t *f, const evlog_rec_t *ram, size_t n_ram, size_t page, const evlog_filter_t *flt,
                         uint32_t *first, uint32_t *last, bool *strictly_desc) {
    uint32_t before = 0, total = 0, prev = UINT32_MAX;
    *strictly_desc = true;
    for (int guard = 0; guard < 100000; guard++) {
        uint32_t next = 77;
        size_t n = evlog_core_query(f, ram, n_ram, before, page, flt, g_out, &next);
        for (size_t i = 0; i < n; i++) {
            if (g_out[i].seq >= prev)
                *strictly_desc = false;
            prev = g_out[i].seq;
            if (total == 0)
                *first = g_out[i].seq;
            *last = g_out[i].seq;
            total++;
            CHECK(evlog_filter_match(flt, &g_out[i]));
        }
        if (n == page && next == 0) {
            /* exhausted exactly at a page boundary: the following query must be empty */
            CHECK_EQ(evlog_core_query(f, ram, n_ram, g_out[n - 1].seq, page, flt, g_out, &next), 0);
        }
        if (next == 0)
            break;
        CHECK_EQ(next, g_out[n - 1].seq);
        before = next;
    }
    return total;
}

static void test_names(void) {
    CHECK_STR(evlog_type_name(EVT_ALARM_RAISE), "alarm_raise");
    CHECK_STR(evlog_type_name(EVT_HEALTH), "health");
    CHECK_STR(evlog_type_name(AUD_REG_WRITE), "reg_write");
    CHECK_STR(evlog_type_name(AUD_REBOOT), "reboot_req");
    CHECK_STR(evlog_type_name(AUD_TIME_SET), "time_sync");
    CHECK_STR(evlog_type_name(AUD_ALARM_ACK), "alarm_ack_req");
    CHECK_STR(evlog_type_name(0), "unknown");
    CHECK_STR(evlog_type_name(200), "unknown");
    /* print every name for the Python side (API.md list) */
    for (int t = 0; t < 256; t++)
        if (strcmp(evlog_type_name((uint8_t)t), "unknown") != 0)
            printf("type %d %s\n", t, evlog_type_name((uint8_t)t));
    /* reason byte macros */
    CHECK_EQ(EVLOG_REASON_BYTE(3), 3);
    CHECK_EQ(EVLOG_REASON_BYTE(0x100 + 2), 0x82);
    CHECK_EQ(EVLOG_REASON_FROM_BYTE(0x82), 0x102);
    CHECK_EQ(EVLOG_REASON_FROM_BYTE(9), 9);
    uint32_t x = EVLOG_REG_WRITE_EXTRA(-15, 2, 0x104);
    CHECK_EQ(x & 0xFFFF, 0xFFF1);
    CHECK_EQ((x >> 16) & 0xFF, 2);
    CHECK_EQ(x >> 24, 0x84);
}

static void test_basic_and_paging(void) {
    evlog_files_t f;
    CHECK_EQ(evlog_files_open(&f, g_dir, "events"), ESP_OK);
    CHECK_EQ(f.last_seq, 0);
    CHECK_EQ(f.count[0] + f.count[1], 0);
    uint32_t next = 5;
    CHECK_EQ(evlog_core_query(&f, NULL, 0, 0, 50, NULL, g_out, &next), 0);
    CHECK_EQ(next, 0);
    append_range(&f, 1, 300);
    CHECK_EQ(f.last_seq, 300);
    CHECK_EQ(f.count[f.active], 300);
    size_t n = evlog_core_query(&f, NULL, 0, 0, 50, NULL, g_out, &next);
    CHECK_EQ(n, 50);
    CHECK_EQ(g_out[0].seq, 300);
    CHECK_EQ(g_out[49].seq, 251);
    CHECK_EQ(next, 251);
    evlog_rec_t want = rec(300);
    CHECK(memcmp(&g_out[0], &want, sizeof(want)) == 0);
    n = evlog_core_query(&f, NULL, 0, 251, 50, NULL, g_out, &next);
    CHECK_EQ(g_out[0].seq, 250);
    n = evlog_core_query(&f, NULL, 0, 3, 50, NULL, g_out, &next);
    CHECK_EQ(n, 2);
    CHECK_EQ(next, 0);
    /* limit capping and zero */
    n = evlog_core_query(&f, NULL, 0, 0, 1000, NULL, g_out, &next);
    CHECK_EQ(n, EVLOG_QUERY_MAX);
    CHECK_EQ(evlog_core_query(&f, NULL, 0, 0, 0, NULL, g_out, &next), 0);
    /* filters */
    evlog_filter_t flt = EVLOG_FILTER_ANY;
    flt.dev = 1;
    uint32_t first = 0, last = 0;
    bool desc;
    CHECK_EQ(page_all(&f, NULL, 0, 7, &flt, &first, &last, &desc), 100);
    CHECK(desc);
    CHECK_EQ(first, 298);
    flt = EVLOG_FILTER_ANY;
    flt.min_sev = 3;
    CHECK_EQ(page_all(&f, NULL, 0, 13, &flt, &first, &last, &desc), 75);
    flt = EVLOG_FILTER_ANY;
    flt.type_min = flt.type_max = EVT_COMM_LOST;
    CHECK_EQ(page_all(&f, NULL, 0, 200, &flt, &first, &last, &desc), 150);
    CHECK_EQ(first, 300);
    CHECK_EQ(last, 2);
    flt = EVLOG_FILTER_ANY;
    flt.dev = (int16_t)EVLOG_DEV_NONE;
    flt.type_min = 32;
    flt.type_max = 63; /* no audit records here */
    CHECK_EQ(page_all(&f, NULL, 0, 10, &flt, &first, &last, &desc), 0);
    /* exact-page exhaustion */
    flt = EVLOG_FILTER_ANY;
    CHECK_EQ(page_all(&f, NULL, 0, 100, &flt, &first, &last, &desc), 300);
    CHECK_EQ(page_all(&f, NULL, 0, 150, NULL, &first, &last, &desc), 300);
}

static void test_ram_merge(void) {
    evlog_files_t f;
    CHECK_EQ(evlog_files_open(&f, g_dir, "audit"), ESP_OK);
    append_range(&f, 1, 100);
    /* RAM tail: 64 newest, of which 90..100 are already on flash and 101..153 are not */
    static evlog_rec_t ram[EVLOG_RAM_TAIL];
    for (uint32_t i = 0; i < EVLOG_RAM_TAIL; i++)
        ram[i] = rec(90 + i);
    uint32_t first = 0, last = 0;
    bool desc;
    CHECK_EQ(page_all(&f, ram, EVLOG_RAM_TAIL, 33, NULL, &first, &last, &desc), 153);
    CHECK(desc);
    CHECK_EQ(first, 153);
    CHECK_EQ(last, 1);
    uint32_t next;
    size_t n = evlog_core_query(&f, ram, EVLOG_RAM_TAIL, 95, 3, NULL, g_out, &next);
    CHECK_EQ(n, 3);
    CHECK_EQ(g_out[0].seq, 94);
    CHECK_EQ(next, 92);
    /* RAM only */
    CHECK_EQ(page_all(NULL, ram, EVLOG_RAM_TAIL, 10, NULL, &first, &last, &desc), EVLOG_RAM_TAIL);
    /* garbage records (seq 0, type 0) are skipped */
    ram[5].seq = 0;
    ram[6].type = 0;
    CHECK_EQ(page_all(NULL, ram, EVLOG_RAM_TAIL, 10, NULL, &first, &last, &desc), EVLOG_RAM_TAIL - 2);
}

static void test_rotation_recovery(void) {
    evlog_files_t f;
    CHECK_EQ(evlog_files_open(&f, g_dir, "rot"), ESP_OK);
    append_range(&f, 1, 2 * EVLOG_RECS_PER_FILE + 100);
    CHECK_EQ(f.count[f.active], 100);
    CHECK_EQ(f.count[1 - f.active], EVLOG_RECS_PER_FILE);
    CHECK_EQ(fsize(f.path[f.active]), 100 * 32);
    CHECK_EQ(fsize(f.path[1 - f.active]), (long)EVLOG_FILE_BYTES);
    uint32_t first = 0, last = 0;
    bool desc;
    CHECK_EQ(page_all(&f, NULL, 0, EVLOG_QUERY_MAX, NULL, &first, &last, &desc), EVLOG_RECS_PER_FILE + 100);
    CHECK(desc);
    CHECK_EQ(first, 2 * EVLOG_RECS_PER_FILE + 100);
    CHECK_EQ(last, EVLOG_RECS_PER_FILE + 1);
    /* reopen: seq and active file recovered */
    evlog_files_t g;
    CHECK_EQ(evlog_files_open(&g, g_dir, "rot"), ESP_OK);
    CHECK_EQ(g.last_seq, 2 * EVLOG_RECS_PER_FILE + 100);
    CHECK_EQ(g.active, f.active);
    CHECK_EQ(g.count[g.active], 100);
    /* torn tail (power loss mid-append) is cut at open */
    FILE *fp = fopen(g.path[g.active], "ab");
    fwrite("partial", 1, 7, fp);
    fclose(fp);
    CHECK_EQ(evlog_files_open(&g, g_dir, "rot"), ESP_OK);
    CHECK_EQ(g.count[g.active], 100);
    CHECK_EQ(fsize(g.path[g.active]), 100 * 32);
    append_range(&g, g.last_seq + 1, g.last_seq + 5);
    CHECK_EQ(g.last_seq, 2 * EVLOG_RECS_PER_FILE + 105);
    /* the full file becomes active when it holds the newest records, then rotates on append */
    evlog_files_t h;
    CHECK_EQ(evlog_files_open(&h, g_dir, "full"), ESP_OK);
    append_range(&h, 1, EVLOG_RECS_PER_FILE);
    CHECK_EQ(evlog_files_open(&h, g_dir, "full"), ESP_OK);
    CHECK_EQ(h.active, 0);
    CHECK_EQ(h.count[0], EVLOG_RECS_PER_FILE);
    append_range(&h, EVLOG_RECS_PER_FILE + 1, EVLOG_RECS_PER_FILE + 1);
    CHECK_EQ(h.active, 1);
    CHECK_EQ(h.count[1], 1);
    /* clear */
    CHECK_EQ(evlog_files_clear(&h), ESP_OK);
    CHECK_EQ(fsize(h.path[0]), -1);
    CHECK_EQ(fsize(h.path[1]), -1);
    CHECK_EQ(h.count[0] + h.count[1], 0);
    uint32_t next;
    CHECK_EQ(evlog_core_query(&h, NULL, 0, 0, 10, NULL, g_out, &next), 0);
    /* path too long */
    char longdir[400];
    memset(longdir, 'a', sizeof(longdir) - 1);
    longdir[sizeof(longdir) - 1] = 0;
    CHECK_EQ(evlog_files_open(&h, longdir, "x"), ESP_ERR_INVALID_ARG);
    /* appending into a missing directory fails and keeps counts consistent */
    CHECK_EQ(evlog_files_open(&h, "/nonexistent-dir-gw", "x"), ESP_OK);
    evlog_rec_t r = rec(1);
    CHECK_EQ(evlog_files_append(&h, &r, 1), ESP_FAIL);
    CHECK_EQ(h.count[0] + h.count[1], 0);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    snprintf(g_dir, sizeof(g_dir), "%s", argv[1]);
    test_names();
    test_basic_and_paging();
    test_ram_merge();
    test_rotation_recovery();
    return BT_DONE();
}
