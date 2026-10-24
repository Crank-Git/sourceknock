/* config_test.c - unit tests for the config parser. */
#include <string.h>

#include "test.h"
#include "config.h"

static const char *good_cfg =
    "# a knockd-ish config\n"
    "[global]\n"
    "  interface = eth0\n"
    "\n"
    "[trigger:ssh]\n"
    "  service = ssh\n"
    "  port = 22\n"
    "  protocol = tcp\n"
    "  sequence = 7000, 8000, 9000\n"
    "  window = 5\n"
    "  mode = fixed_ttl\n"
    "  duration = 30\n";

static void test_good(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(good_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(strcmp(g_cfg.interface, "eth0"), 0);
    CHECK_EQ_INT(strcmp(g_cfg.trigger.service, "ssh"), 0);
    CHECK_EQ_INT(g_cfg.trigger.port, 22);
    CHECK_EQ_INT(g_cfg.trigger.protocol, PROTO_TCP);
    CHECK_EQ_INT(g_cfg.trigger.seq_len, 3);
    CHECK_EQ_INT(g_cfg.trigger.sequence[0], 7000);
    CHECK_EQ_INT(g_cfg.trigger.sequence[2], 9000);
    CHECK_EQ_INT(g_cfg.trigger.window, 5);
    CHECK_EQ_INT(g_cfg.trigger.mode, MODE_FIXED_TTL);
    CHECK_EQ_INT(g_cfg.trigger.duration, 30);
}

static const char *udp_cfg =
    "[global]\ninterface = lo\n"
    "[trigger:t]\nport = 2222\nprotocol = udp\n"
    "sequence = 1,2,3,4,5\nmode = close_on_connect\nwindow = 10\nduration = 30\n";

static void test_udp_close(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(udp_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.trigger.protocol, PROTO_UDP);
    CHECK_EQ_INT(g_cfg.trigger.seq_len, 5);
    CHECK_EQ_INT(g_cfg.trigger.mode, MODE_CLOSE_ON_CONNECT);
}

static const char *bad_seq =
    "[global]\ninterface = lo\n"
    "[trigger:t]\nport = 22\nprotocol = tcp\nsequence = 7000,abc,9000\n";

static void test_bad_sequence(void)
{
    char err[256];
    CHECK(config_parse_string(bad_seq, err, sizeof(err)) == -1);
}

static const char *no_seq =
    "[global]\ninterface = lo\n[trigger:t]\nport = 22\nprotocol = tcp\n";

static void test_missing_sequence(void)
{
    char err[256];
    CHECK(config_parse_string(no_seq, err, sizeof(err)) == -1);
}

static void test_bad_protocol(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n"
        "[trigger:t]\nport = 22\nprotocol = sctp\nsequence = 1,2\n";
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
}

static void test_bad_port(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n"
        "[trigger:t]\nport = 0\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
    const char *c2 =
        "[global]\ninterface = lo\n"
        "[trigger:t]\nport = 70000\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c2, err, sizeof(err)) == -1);
}

int main(void)
{
    printf("== config parser tests ==\n");
    TEST_RUN(test_good);
    TEST_RUN(test_udp_close);
    TEST_RUN(test_bad_sequence);
    TEST_RUN(test_missing_sequence);
    TEST_RUN(test_bad_protocol);
    TEST_RUN(test_bad_port);
    TEST_SUMMARY();
}
