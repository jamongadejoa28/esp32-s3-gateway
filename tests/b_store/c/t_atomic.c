/* t_atomic.c - store/atomic_file.c on a temp directory: write protocol, fallback order, crash states. */
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <unistd.h>

#include "bt.h"
#include "store/atomic_file.h"
#include "store_priv.h"

static char g_dir[512];

static void path_of(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "%s/%s", g_dir, name);
}

static void put_file(const char *name, const char *data) {
    char p[600];
    path_of(p, sizeof(p), name);
    FILE *f = fopen(p, "wb");
    if (f) {
        fwrite(data, 1, strlen(data), f);
        fclose(f);
    }
}

static int exists(const char *name) {
    char p[600];
    path_of(p, sizeof(p), name);
    struct stat st;
    return stat(p, &st) == 0;
}

static char *slurp(const char *name) {
    char p[600];
    path_of(p, sizeof(p), name);
    FILE *f = fopen(p, "rb");
    if (!f)
        return NULL;
    static char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}

/* accept only documents that start with '{' and end with '}' (stand-in for "parses + validates") */
static bool accept_json(const char *data, size_t len, void *arg) {
    int *calls = arg;
    if (calls)
        (*calls)++;
    return len >= 2 && data[0] == '{' && data[len - 1] == '}';
}

static void reset(void) {
    char p[600];
    path_of(p, sizeof(p), "cfg.json");
    atomic_remove(p);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    snprintf(g_dir, sizeof(g_dir), "%s", argv[1]);
    char X[600];
    path_of(X, sizeof(X), "cfg.json");
    char *buf = NULL;
    size_t len = 0;
    atomic_src_t src;

    /* first write: X only */
    CHECK_EQ(atomic_write(X, "{\"v\":1}", 7), ESP_OK);
    CHECK_STR(slurp("cfg.json"), "{\"v\":1}");
    CHECK(!exists("cfg.json.tmp"));
    CHECK(!exists("cfg.json.bak"));
    /* second write keeps the previous version as .bak */
    CHECK_EQ(atomic_write(X, "{\"v\":2}", 7), ESP_OK);
    CHECK_STR(slurp("cfg.json"), "{\"v\":2}");
    CHECK_STR(slurp("cfg.json.bak"), "{\"v\":1}");
    CHECK(!exists("cfg.json.tmp"));
    CHECK_EQ(atomic_write(X, "{\"v\":3}", 7), ESP_OK);
    CHECK_STR(slurp("cfg.json.bak"), "{\"v\":2}");

    /* read: main wins */
    int calls = 0;
    CHECK_EQ(atomic_read(X, 1024, accept_json, &calls, &buf, &len, &src), ESP_OK);
    CHECK_STR(buf, "{\"v\":3}");
    CHECK_EQ(len, 7);
    CHECK_EQ(src, ATOMIC_SRC_MAIN);
    CHECK_EQ(calls, 1);
    free(buf);

    /* corrupt main -> .tmp absent -> .bak */
    put_file("cfg.json", "{\"v\":3");
    calls = 0;
    CHECK_EQ(atomic_read(X, 1024, accept_json, &calls, &buf, &len, &src), ESP_OK);
    CHECK_STR(buf, "{\"v\":2}");
    CHECK_EQ(src, ATOMIC_SRC_BAK);
    CHECK_EQ(calls, 2);
    free(buf);

    /* crash after the tmp was completed and X renamed to bak: X missing, tmp + bak complete */
    reset();
    put_file("cfg.json.tmp", "{\"v\":5}");
    put_file("cfg.json.bak", "{\"v\":4}");
    CHECK_EQ(atomic_read(X, 1024, accept_json, NULL, &buf, &len, &src), ESP_OK);
    CHECK_STR(buf, "{\"v\":5}");
    CHECK_EQ(src, ATOMIC_SRC_TMP);
    free(buf);
    /* the next write recovers a clean state */
    CHECK_EQ(atomic_write(X, "{\"v\":6}", 7), ESP_OK);
    CHECK_STR(slurp("cfg.json"), "{\"v\":6}");
    CHECK(!exists("cfg.json.tmp"));

    /* crash during the tmp write: torn tmp, intact X */
    reset();
    put_file("cfg.json", "{\"v\":7}");
    put_file("cfg.json.tmp", "{\"v\":8");
    CHECK_EQ(atomic_read(X, 1024, accept_json, NULL, &buf, &len, &src), ESP_OK);
    CHECK_EQ(src, ATOMIC_SRC_MAIN);
    free(buf);
    /* only a torn tmp and a torn bak: nothing acceptable */
    reset();
    put_file("cfg.json.tmp", "{");
    put_file("cfg.json.bak", "}");
    CHECK_EQ(atomic_read(X, 1024, accept_json, NULL, &buf, &len, &src), ESP_ERR_NOT_FOUND);
    CHECK(buf == NULL);
    CHECK_EQ(src, ATOMIC_SRC_NONE);
    /* accept NULL takes the first readable candidate */
    CHECK_EQ(atomic_read(X, 1024, NULL, NULL, &buf, &len, &src), ESP_OK);
    CHECK_EQ(src, ATOMIC_SRC_TMP);
    CHECK_STR(buf, "{");
    free(buf);

    /* oversize candidates are skipped */
    reset();
    put_file("cfg.json", "{\"long\":\"0123456789\"}");
    put_file("cfg.json.bak", "{}");
    CHECK_EQ(atomic_read(X, 8, accept_json, NULL, &buf, &len, &src), ESP_OK);
    CHECK_EQ(src, ATOMIC_SRC_BAK);
    CHECK_STR(buf, "{}");
    free(buf);

    /* empty file write/read */
    reset();
    CHECK_EQ(atomic_write(X, NULL, 0), ESP_OK);
    CHECK_EQ(atomic_read(X, 8, NULL, NULL, &buf, &len, &src), ESP_OK);
    CHECK_EQ(len, 0);
    CHECK_STR(buf, "");
    free(buf);

    /* remove: all variants, missing ones are fine */
    put_file("cfg.json.tmp", "x");
    put_file("cfg.json.bak", "x");
    CHECK_EQ(atomic_remove(X), ESP_OK);
    CHECK(!exists("cfg.json") && !exists("cfg.json.tmp") && !exists("cfg.json.bak"));
    CHECK_EQ(atomic_remove(X), ESP_OK);
    CHECK_EQ(atomic_read(X, 8, NULL, NULL, &buf, &len, &src), ESP_ERR_NOT_FOUND);

    /* factory reset: a rewrite keeps the old version as .bak; drop_backups removes it (and .tmp) */
    reset();
    CHECK_EQ(atomic_write(X, "old-secret", 10), ESP_OK);
    CHECK_EQ(atomic_write(X, "new", 3), ESP_OK);
    CHECK(exists("cfg.json.bak"));
    put_file("cfg.json.tmp", "stale");
    CHECK_EQ(atomic_drop_backups(X), ESP_OK);
    CHECK(exists("cfg.json") && !exists("cfg.json.bak") && !exists("cfg.json.tmp"));
    CHECK_EQ(atomic_drop_backups(X), ESP_OK); /* nothing left: fine */
    CHECK_EQ(atomic_read(X, 8, NULL, NULL, &buf, &len, &src), ESP_OK);
    CHECK_STR(buf, "new");
    free(buf);
    CHECK_EQ(atomic_drop_backups(NULL), ESP_ERR_INVALID_ARG);
    atomic_remove(X);

    /* argument errors */
    char longp[ATOMIC_PATH_MAX + 8];
    memset(longp, 'a', sizeof(longp));
    longp[sizeof(longp) - 1] = 0;
    CHECK_EQ(atomic_write(longp, "x", 1), ESP_ERR_INVALID_ARG);
    longp[ATOMIC_PATH_MAX - 4] = 0; /* + ".tmp" needs one more byte than fits */
    CHECK_EQ(atomic_write(longp, "x", 1), ESP_ERR_INVALID_ARG);
    CHECK_EQ(atomic_read(longp, 8, NULL, NULL, &buf, &len, &src), ESP_ERR_INVALID_ARG);
    CHECK_EQ(atomic_write(NULL, "x", 1), ESP_ERR_INVALID_ARG);
    CHECK_EQ(atomic_write(X, NULL, 3), ESP_ERR_INVALID_ARG);
    CHECK_EQ(atomic_read(X, 8, NULL, NULL, NULL, &len, &src), ESP_ERR_INVALID_ARG);

    /* missing parent directory: I/O error, nothing created */
    char nodir[600];
    snprintf(nodir, sizeof(nodir), "%s/none/f.json", g_dir);
    if (strlen(nodir) + 4 < ATOMIC_PATH_MAX)
        CHECK_EQ(atomic_write(nodir, "{}", 2), ESP_FAIL);
    return BT_DONE();
}
