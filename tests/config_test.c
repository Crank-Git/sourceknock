/* config_test.c - unit tests for the config parser. */
#include <string.h>

#include "config.h"
#include "test.h"

static const char *good_cfg = "# a knockd-ish config\n"
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
    CHECK_EQ_INT(g_cfg.n_triggers, 1);
    CHECK_EQ_INT(strcmp(g_cfg.triggers[0].service, "ssh"), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].n_ports, 1);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[0], 22);
    CHECK_EQ_INT(g_cfg.triggers[0].protocol, PROTO_TCP);
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 3);
    CHECK_EQ_INT(g_cfg.triggers[0].sequence[0], 7000);
    CHECK_EQ_INT(g_cfg.triggers[0].sequence[2], 9000);
    CHECK_EQ_INT(g_cfg.triggers[0].window, 5);
    CHECK_EQ_INT(g_cfg.triggers[0].mode, MODE_FIXED_TTL);
    CHECK_EQ_INT(g_cfg.triggers[0].duration, 30);
}

static const char *udp_cfg = "[global]\ninterface = lo\n"
                             "[trigger:t]\nport = 2222\nprotocol = udp\n"
                             "sequence = 1,2,3,4,5\nmode = "
                             "close_on_connect\nwindow = 10\nduration = 30\n";

static void test_udp_close(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(udp_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].protocol, PROTO_UDP);
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 5);
    CHECK_EQ_INT(g_cfg.triggers[0].mode, MODE_CLOSE_ON_CONNECT);
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
    const char *c = "[global]\ninterface = lo\n"
                    "[trigger:t]\nport = 22\nprotocol = sctp\nsequence = 1,2\n";
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
}

static void test_bad_port(void)
{
    char err[256];
    const char *c = "[global]\ninterface = lo\n"
                    "[trigger:t]\nport = 0\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
    const char *c2 =
        "[global]\ninterface = lo\n"
        "[trigger:t]\nport = 70000\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c2, err, sizeof(err)) == -1);
}

/* Acceptance: two [trigger:] sections parse into two distinct triggers. */
static const char *multi_cfg =
    "[global]\ninterface = eth0\n"
    "[trigger:ssh]\nport = 22\nprotocol = tcp\n"
    "  sequence = 7000,8000\nmode = fixed_ttl\nduration = 30\n"
    "[trigger:web]\nport = 8080\nprotocol = udp\n"
    "  sequence = 1,2,3\nmode = close_on_connect\nwindow = 10\n";

static void test_multi_trigger(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(multi_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.n_triggers, 2);
    /* trigger 0: ssh / tcp / 22 / 2 ports */
    CHECK_EQ_INT(strcmp(g_cfg.triggers[0].service, "ssh"), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].n_ports, 1);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[0], 22);
    CHECK_EQ_INT(g_cfg.triggers[0].protocol, PROTO_TCP);
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 2);
    CHECK_EQ_INT(g_cfg.triggers[0].mode, MODE_FIXED_TTL);
    /* trigger 1: web / udp / 8080 / 3 ports */
    CHECK_EQ_INT(strcmp(g_cfg.triggers[1].service, "web"), 0);
    CHECK_EQ_INT(g_cfg.triggers[1].n_ports, 1);
    CHECK_EQ_INT(g_cfg.triggers[1].ports[0], 8080);
    CHECK_EQ_INT(g_cfg.triggers[1].protocol, PROTO_UDP);
    CHECK_EQ_INT(g_cfg.triggers[1].seq_len, 3);
    CHECK_EQ_INT(g_cfg.triggers[1].mode, MODE_CLOSE_ON_CONNECT);
}

/* Acceptance: a trigger without a sequence is a config error. */
static void test_multi_trigger_missing_seq(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n"
        "[trigger:a]\nport = 22\nprotocol = tcp\nsequence = 1,2\n"
        "[trigger:b]\nport = 80\nprotocol = tcp\n"; /* no sequence */
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
    CHECK_EQ_INT(g_cfg.n_triggers, 0); /* nothing left valid on error */
}

/* A single port still parses (backwards compatible). */
static void test_single_port(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n"
        "[trigger:t]\nport = 2222\nprotocol = tcp\nsequence = 1,2\n";
    CHECK_EQ_INT(config_parse_string(c, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].n_ports, 1);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[0], 2222);
}

/* Acceptance: `port` accepts a comma-separated list and inclusive ranges, all
 * expanded and validated. */
static const char *multi_port_cfg =
    "[global]\ninterface = lo\n"
    "[trigger:multi]\nport = 22, 80, 443, 8000-8002\n"
    "protocol = tcp\nsequence = 1,2,3\n";

static void test_multi_port(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(multi_port_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].n_ports, 6);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[0], 22);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[1], 80);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[2], 443);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[3], 8000);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[4], 8001);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[5], 8002);
}

/* Invalid port specs are rejected: out of range, malformed, reversed range,
 * multi-dash, and empty. */
static void test_bad_ports(void)
{
    char err[256];
    const char *c0 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "0\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c0, err, sizeof(err)) == -1);
    const char *c1 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "70000\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c1, err, sizeof(err)) == -1);
    const char *c2 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "abc\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c2, err, sizeof(err)) == -1);
    const char *c3 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "80-\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c3, err, sizeof(err)) == -1);
    const char *c4 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "80-70\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c4, err, sizeof(err)) == -1);
    const char *c5 = "[global]\ninterface = lo\n[trigger:t]\nport = "
                     "80-90-100\nprotocol = tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c5, err, sizeof(err)) == -1);
    const char *c6 = "[global]\ninterface = lo\n[trigger:t]\nport =\nprotocol "
                     "= tcp\nsequence = 1,2\n";
    CHECK(config_parse_string(c6, err, sizeof(err)) == -1);
}

/* Acceptance: `mode = permanent` parses, and an optional `admin_sequence`
 * configures a revoke knock. */
static const char *permanent_cfg =
    "[global]\ninterface = lo\n"
    "[trigger:whitelist]\nport = 22\nprotocol = tcp\n"
    "sequence = 7000,8000,9000\nmode = permanent\n"
    "admin_sequence = 9000,8000,7000\n";

static void test_permanent_mode(void)
{
    char err[256];
    CHECK_EQ_INT(config_parse_string(permanent_cfg, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.n_triggers, 1);
    CHECK_EQ_INT(g_cfg.triggers[0].mode, MODE_PERMANENT);
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 3);
    /* admin revoke sequence */
    CHECK_EQ_INT(g_cfg.triggers[0].admin_seq_len, 3);
    CHECK_EQ_INT(g_cfg.triggers[0].admin_sequence[0], 9000);
    CHECK_EQ_INT(g_cfg.triggers[0].admin_sequence[2], 7000);
}

/* Permanent mode without an admin_sequence is valid: no revoke configured. */
static void test_permanent_no_admin(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n[trigger:t]\nport = 22\nprotocol = tcp\n"
        "sequence = 1,2,3\nmode = permanent\n";
    CHECK_EQ_INT(config_parse_string(c, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].mode, MODE_PERMANENT);
    CHECK_EQ_INT(g_cfg.triggers[0].admin_seq_len, 0);
}

/* Invalid mode values are rejected. */
static void test_bad_mode(void)
{
    char err[256];
    const char *c =
        "[global]\ninterface = lo\n[trigger:t]\nport = 22\nprotocol = tcp\n"
        "sequence = 1,2\nmode = never\n";
    CHECK(config_parse_string(c, err, sizeof(err)) == -1);
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
    TEST_RUN(test_multi_trigger);
    TEST_RUN(test_multi_trigger_missing_seq);
    TEST_RUN(test_single_port);
    TEST_RUN(test_multi_port);
    TEST_RUN(test_bad_ports);
    TEST_RUN(test_permanent_mode);
    TEST_RUN(test_permanent_no_admin);
    TEST_RUN(test_bad_mode);
    TEST_SUMMARY();
}
