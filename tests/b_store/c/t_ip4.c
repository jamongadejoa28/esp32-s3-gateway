/* t_ip4.c - gw_core/gw_ip4.c: strict parsing, formatting, masks, CIDR, overlap, host validity. */
#include "bt.h"
#include "gw_core/gw_ip4.h"

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static void test_parse(void) {
    static const struct {
        const char *s;
        uint32_t v;
    } ok[] = {
        {"0.0.0.0", 0},
        {"255.255.255.255", 0xFFFFFFFFu},
        {"192.168.10.150", IP(192, 168, 10, 150)},
        {"10.0.0.1", IP(10, 0, 0, 1)},
        {"1.2.3.4", IP(1, 2, 3, 4)},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        uint32_t v = 0x12345678;
        CHECK(gw_ip4_parse(ok[i].s, &v));
        CHECK_EQ(v, ok[i].v);
        char b[GW_IP4_STR_SZ];
        gw_ip4_format(ok[i].v, b);
        CHECK_STR(b, ok[i].s);
    }
    static const char *const bad[] = {"",        "1.2.3",       "1.2.3.4.5",  "256.1.1.1", "01.2.3.4",
                                      "1.2.3.04", " 1.2.3.4",   "1.2.3.4 ",   "1..3.4",    "1.2.3.",
                                      "a.b.c.d", "1.2.3.4/24", "1234.1.1.1", "-1.2.3.4",  "1.2.3.4\n",
                                      "999.999.999.999"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint32_t v = 77;
        CHECK(!gw_ip4_parse(bad[i], &v));
        CHECK_EQ(v, 77);
    }
    CHECK(!gw_ip4_parse(NULL, NULL));
}

static void test_masks(void) {
    for (unsigned p = 0; p <= 32; p++) {
        uint32_t m = gw_ip4_mask_from_prefix(p);
        CHECK(gw_ip4_mask_valid(m));
        CHECK_EQ(gw_ip4_prefix_len(m), (int)p);
    }
    CHECK_EQ(gw_ip4_mask_from_prefix(33), 0xFFFFFFFFu);
    CHECK(!gw_ip4_mask_valid(IP(255, 0, 255, 0)));
    CHECK(!gw_ip4_mask_valid(IP(0, 255, 255, 255)));
    CHECK(!gw_ip4_mask_valid(IP(255, 255, 255, 253)));
    CHECK_EQ(gw_ip4_prefix_len(IP(255, 0, 255, 0)), -1);
}

static void test_cidr(void) {
    uint32_t n, m;
    CHECK(gw_cidr_parse("10.0.0.0/8", &n, &m));
    CHECK_EQ(n, IP(10, 0, 0, 0));
    CHECK_EQ(m, IP(255, 0, 0, 0));
    CHECK(gw_cidr_parse("192.168.10.7", &n, &m)); /* bare = /32 */
    CHECK_EQ(m, 0xFFFFFFFFu);
    CHECK(gw_cidr_parse("0.0.0.0/0", &n, &m));
    CHECK_EQ(n, 0);
    CHECK_EQ(m, 0);
    CHECK(gw_cidr_parse("192.168.10.0/24", &n, &m));
    char b[GW_CIDR_STR_SZ];
    gw_cidr_format(n, m, b);
    CHECK_STR(b, "192.168.10.0/24");
    gw_cidr_format(IP(255, 255, 255, 255), 0xFFFFFFFFu, b);
    CHECK_STR(b, "255.255.255.255/32");
    static const char *const bad[] = {"10.0.0.1/8", "10.0.0.0/33", "10.0.0.0/", "10.0.0.0/08", "10.0.0.0/8x",
                                      "10.0.0/8",   "/8",          "10.0.0.0//8", "10.0.0.0/-1", "1.2.3.4/100"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(!gw_cidr_parse(bad[i], &n, &m));
}

static void test_nets(void) {
    CHECK(gw_ip4_in_net(IP(192, 168, 10, 5), IP(192, 168, 10, 0), IP(255, 255, 255, 0)));
    CHECK(!gw_ip4_in_net(IP(192, 168, 11, 5), IP(192, 168, 10, 0), IP(255, 255, 255, 0)));
    CHECK(gw_ip4_in_net(IP(8, 8, 8, 8), 0, 0));
    /* overlap: AP 192.168.150.0/24 vs candidates */
    uint32_t ap = IP(192, 168, 150, 0), apm = IP(255, 255, 255, 0);
    CHECK(gw_ip4_nets_overlap(IP(192, 168, 0, 0), IP(255, 255, 0, 0), ap, apm));
    CHECK(gw_ip4_nets_overlap(ap, apm, IP(192, 168, 0, 0), IP(255, 255, 0, 0)));
    CHECK(gw_ip4_nets_overlap(IP(192, 168, 150, 128), IP(255, 255, 255, 128), ap, apm));
    CHECK(!gw_ip4_nets_overlap(IP(192, 168, 151, 0), apm, ap, apm));
    CHECK(!gw_ip4_nets_overlap(IP(10, 0, 0, 0), IP(255, 0, 0, 0), ap, apm));
    CHECK(gw_ip4_nets_overlap(0, 0, ap, apm));
    /* host validity */
    uint32_t m24 = IP(255, 255, 255, 0);
    CHECK(gw_ip4_host_valid(IP(192, 168, 10, 150), m24));
    CHECK(!gw_ip4_host_valid(IP(192, 168, 10, 0), m24));
    CHECK(!gw_ip4_host_valid(IP(192, 168, 10, 255), m24));
    CHECK(!gw_ip4_host_valid(IP(0, 1, 2, 3), m24));
    CHECK(!gw_ip4_host_valid(IP(127, 0, 0, 1), m24));
    CHECK(!gw_ip4_host_valid(IP(224, 0, 0, 1), m24));
    CHECK(!gw_ip4_host_valid(IP(255, 255, 255, 255), m24));
    CHECK(gw_ip4_host_valid(IP(10, 0, 0, 0), IP(255, 255, 255, 254))); /* /31: both usable */
    CHECK(gw_ip4_host_valid(IP(10, 0, 0, 1), 0xFFFFFFFFu));
    CHECK(!gw_ip4_host_valid(IP(10, 0, 0, 1), IP(255, 0, 255, 0)));
}

int main(void) {
    test_parse();
    test_masks();
    test_cidr();
    test_nets();
    return BT_DONE();
}
