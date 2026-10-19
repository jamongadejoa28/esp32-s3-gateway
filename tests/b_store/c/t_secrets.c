/* t_secrets.c - store/secrets.c pure part: defaults, validation, file JSON, flags, lookup, trap remap. */
#include <stdlib.h>

#include "bt.h"
#include "store/config_json.h"
#include "store/secrets.h"

#define PSK "mfrg-gzdf-mztw-q2lk"
#define HASH "pbkdf2-sha256$10000$c2FsdHNhbHRzYWx0c2FsdA$ZGVyaXZlZGtleWRlcml2ZWRrZXlkZXJpdmVka2V5MDE"

static gw_secrets_t g_s, g_t;

static void add_user(gw_secrets_t *s, const char *name, gw_role_t role) {
    sec_user_t *u = &s->users[s->n_users++];
    memset(u, 0, sizeof(*u));
    strcpy(u->name, name);
    u->role = (uint8_t)role;
    strcpy(u->hash, HASH);
}

static void test_defaults_validate(void) {
    sec_defaults(&g_s, PSK);
    CHECK_EQ(g_s.schema, SEC_SCHEMA_VERSION);
    CHECK_EQ(g_s.n_users, 0);
    CHECK_STR(g_s.snmp_ro, "");
    CHECK_STR(g_s.snmp_rw, "");
    for (int i = 0; i < GW_MAX_TRAP_TARGETS; i++)
        CHECK_STR(g_s.trap_comm[i], SEC_DEFAULT_TRAP);
    CHECK_STR(g_s.ap_psk, PSK);
    CHECK(!g_s.v3[0].set && !g_s.v3[1].set);
    CHECK(sec_validate(&g_s));

    add_user(&g_s, "admin", GW_ROLE_ADMIN);
    add_user(&g_s, "op.1", GW_ROLE_OPERATOR);
    CHECK(sec_validate(&g_s));
    g_t = g_s;
    g_t.users[0].role = GW_ROLE_VIEWER; /* no admin left */
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    strcpy(g_t.users[1].name, "admin"); /* duplicate */
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    strcpy(g_t.users[1].name, "Op"); /* upper case */
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    strcpy(g_t.users[1].name, "1op");
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    memset(g_t.users[1].name, 'a', sizeof(g_t.users[1].name)); /* 12 chars, unterminated */
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.users[1].role = 0;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.users[1].role = 4;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.users[1].hash[0] = 0;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.users[1].changed_ms = -1;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.n_users = 5;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    strcpy(g_t.snmp_ro, "with space");
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.trap_comm[2][0] = 0;
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    strcpy(g_t.ap_psk, "short");
    CHECK(!sec_validate(&g_t));
    g_t = g_s;
    g_t.schema = 2;
    CHECK(!sec_validate(&g_t));
    CHECK(!sec_validate(NULL));
    sec_defaults(&g_t, NULL); /* no factory PSK: invalid until one is set */
    CHECK(!sec_validate(&g_t));
}

static char g_buf[8192];

static void test_json(void) {
    sec_defaults(&g_s, PSK);
    add_user(&g_s, "admin", GW_ROLE_ADMIN);
    g_s.users[0].must_change = true;
    add_user(&g_s, "viewer_2", GW_ROLE_VIEWER);
    g_s.users[1].changed_ms = 1792285200000LL;
    strcpy(g_s.snmp_ro, "ro-comm!");
    strcpy(g_s.snmp_rw, "rw\"comm\\");
    g_s.v3[1].set = true;
    for (int i = 0; i < SEC_V3_KEY_LEN; i++) {
        g_s.v3[1].auth_key[i] = (uint8_t)(i * 7);
        g_s.v3[1].priv_key[i] = (uint8_t)(0xFF - i);
    }
    memset(g_s.trap_comm[1], 0, sizeof(g_s.trap_comm[1]));
    strcpy(g_s.trap_comm[1], "nms-trap");
    strcpy(g_s.ap_psk, "my new psk with spaces");
    CHECK(sec_validate(&g_s));
    gw_jw_t w;
    gw_jw_init_fixed(&w, g_buf, sizeof(g_buf));
    CHECK_EQ(sec_to_json(&g_s, &w), CFG_JSON_OK);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_OK);
    CHECK(strstr(g_buf, "\"slot\":1,\"auth_key\":\"00070e15") != NULL);
    CHECK(strstr(g_buf, "\"changed\":null") != NULL);
    CHECK(strstr(g_buf, "\"changed\":1792285200000") != NULL);
    CHECK(strstr(g_buf, "\"role\":\"viewer\"") != NULL);
    CHECK_EQ(sec_from_json(g_buf, strlen(g_buf), "other-factory-psk", &g_t), CFG_JSON_OK);
    CHECK(memcmp(&g_s, &g_t, sizeof(g_s)) == 0);

    /* missing members from defaults; "name" in v3 entries ignored, position = slot */
    const char *min = "{\"users\":[{\"name\":\"admin\",\"role\":\"admin\",\"hash\":\"x$y\"}],"
                      "\"snmp\":{\"v3\":[{\"name\":\"gwmonitor\",\"auth_key\":\"0000000000000000000000000000000000000001\","
                      "\"priv_key\":\"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\"}]},\"zzz\":1}";
    CHECK_EQ(sec_from_json(min, strlen(min), PSK, &g_t), CFG_JSON_OK);
    CHECK_EQ(g_t.n_users, 1);
    CHECK(g_t.v3[0].set && !g_t.v3[1].set);
    CHECK_EQ(g_t.v3[0].auth_key[19], 1);
    CHECK_EQ(g_t.v3[0].priv_key[0], 0xFF);
    CHECK_STR(g_t.ap_psk, PSK);
    CHECK_STR(g_t.trap_comm[3], SEC_DEFAULT_TRAP);

    static const char *const bad[] = {
        "[]",
        "{\"schema\":\"1\"}",
        "{\"users\":[{\"name\":\"admin\",\"role\":\"root\",\"hash\":\"x\"}]}",
        "{\"users\":[{\"name\":\"admin\",\"role\":\"admin\"}]}",
        "{\"users\":[{\"name\":\"viewer\",\"role\":\"viewer\",\"hash\":\"x\"}]}", /* no admin */
        "{\"users\":[1,2,3,4,5]}",
        "{\"users\":[{\"name\":\"admin\",\"role\":\"admin\",\"hash\":\"x\",\"changed\":-5}]}",
        "{\"users\":[{\"name\":\"admin\",\"role\":\"admin\",\"hash\":\"x\",\"must_change\":1}]}",
        "{\"snmp\":{\"v3\":[{\"auth_key\":\"00\",\"priv_key\":\"00\"}]}}",
        "{\"snmp\":{\"v3\":[{\"slot\":2,\"auth_key\":\"0000000000000000000000000000000000000000\","
        "\"priv_key\":\"0000000000000000000000000000000000000000\"}]}}",
        "{\"snmp\":{\"v3\":[{\"auth_key\":\"zz00000000000000000000000000000000000000\","
        "\"priv_key\":\"0000000000000000000000000000000000000000\"}]}}",
        "{\"snmp\":{\"trap_comm\":[\"a\",\"b\",\"c\",\"d\",\"e\"]}}",
        "{\"snmp\":{\"ro\":\"0123456789012345678901234567890123\"}}",
        "{\"ap_psk\":\"short\"}",
        "{\"ap_psk\":5}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = sec_from_json(bad[i], strlen(bad[i]), PSK, &g_t);
        if (rc == CFG_JSON_OK)
            fprintf(stderr, "bad[%zu] accepted\n", i);
        CHECK(rc != CFG_JSON_OK);
        CHECK_EQ(g_t.n_users, 0); /* defaults on failure */
        CHECK_STR(g_t.ap_psk, PSK);
    }
    CHECK_EQ(sec_from_json("{\"schema\":2}", 12, PSK, &g_t), CFG_JSON_E_SCHEMA);
    CHECK_EQ(sec_from_json("{", 1, PSK, &g_t), CFG_JSON_E_PARSE);
    CHECK_EQ(sec_from_json(NULL, 0, PSK, &g_t), CFG_JSON_E_PARSE);
    /* writer overflow */
    char small[32];
    gw_jw_init_fixed(&w, small, sizeof(small));
    sec_to_json(&g_s, &w);
    CHECK_EQ(gw_jw_finish(&w), GW_JW_E_OVERFLOW);
}

static void test_flags_lookup_remap(void) {
    sec_defaults(&g_s, PSK);
    cfg_secret_flags_t f;
    sec_flags(&g_s, &f);
    CHECK(f.ap_psk_set && !f.snmp_ro_set && !f.snmp_rw_set && !f.v3_keys_set[0] && !f.trap_comm_set[0]);
    strcpy(g_s.snmp_ro, "r");
    g_s.v3[0].set = true;
    strcpy(g_s.trap_comm[2], "x");
    sec_flags(&g_s, &f);
    CHECK(f.snmp_ro_set && f.v3_keys_set[0] && !f.v3_keys_set[1] && f.trap_comm_set[2] && !f.trap_comm_set[1]);

    add_user(&g_s, "admin", GW_ROLE_ADMIN);
    add_user(&g_s, "bob", GW_ROLE_VIEWER);
    CHECK_EQ(sec_find_user(&g_s, "bob"), 1);
    CHECK_EQ(sec_find_user(&g_s, "admin"), 0);
    CHECK_EQ(sec_find_user(&g_s, "alice"), -1);
    CHECK_EQ(sec_find_user(&g_s, NULL), -1);

    /* remap: old [A, B, C]; new slot0 = old 2, slot1 = explicit, slot2 = new target */
    strcpy(g_s.trap_comm[0], "A");
    strcpy(g_s.trap_comm[1], "B");
    strcpy(g_s.trap_comm[2], "C");
    strcpy(g_s.trap_comm[3], "D");
    cfg_secret_input_t in;
    memset(&in, 0, sizeof(in));
    in.has_traps = true;
    in.trap_from[0] = 2;
    in.trap_from[1] = 0;
    in.trap[1].has = true;
    strcpy(in.trap[1].community, "EXPL");
    in.trap_from[2] = -1;
    in.trap_from[3] = 1;
    sec_trap_remap(&g_s, &in, 3);
    CHECK_STR(g_s.trap_comm[0], "C");
    CHECK_STR(g_s.trap_comm[1], "EXPL");
    CHECK_STR(g_s.trap_comm[2], SEC_DEFAULT_TRAP);
    CHECK_STR(g_s.trap_comm[3], SEC_DEFAULT_TRAP); /* beyond n_traps */
    /* no-op without has_traps */
    in.has_traps = false;
    strcpy(g_s.trap_comm[0], "keep");
    sec_trap_remap(&g_s, &in, 0);
    CHECK_STR(g_s.trap_comm[0], "keep");
}

int main(void) {
    test_defaults_validate();
    test_json();
    test_flags_lookup_remap();
    return BT_DONE();
}
