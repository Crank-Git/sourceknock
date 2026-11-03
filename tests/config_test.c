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

/* ---- issue #34: invalid configs are rejected, never crash ---- */

static int parse(const char *c, char *err, size_t n)
{
    err[0] = '\0';
    return config_parse_string(c, err, n);
}

/* A key before any [section] used to dereference a NULL section (segfault). */
static void test_key_before_section(void)
{
    char err[256];
    CHECK(parse("interface = eth0\n", err, sizeof(err)) == -1);
    CHECK(strstr(err, "outside of any section") != NULL);
    CHECK(parse("# comment first\n\nport = 22\n[global]\n", err, sizeof(err)) ==
          -1);
    CHECK_EQ_INT(g_cfg.n_triggers, 0);
}

/* A trigger without `port` would start and "open" nothing. */
static void test_missing_port(void)
{
    char err[256];
    const char *c = "[global]\ninterface = lo\n"
                    "[trigger:noport]\nsequence = 7000,8000,9000\n";
    CHECK(parse(c, err, sizeof(err)) == -1);
    CHECK(strstr(err, "noport") != NULL);
    CHECK(strstr(err, "port is required") != NULL);
    CHECK_EQ_INT(g_cfg.n_triggers, 0);
}

/* web-1 and web_1 both sanitize to sourceknock_web_1: the second trigger's
 * reward_init would flush the first one's rules. */
static void test_table_name_collision(void)
{
    char err[256];
    const char *c = "[global]\ninterface = lo\n"
                    "[trigger:web-1]\nport = 80\nsequence = 1,2,3\n"
                    "[trigger:web_1]\nport = 443\nsequence = 4,5,6\n";
    CHECK(parse(c, err, sizeof(err)) == -1);
    CHECK(strstr(err, "web-1") != NULL);
    CHECK(strstr(err, "web_1") != NULL);

    /* `service =` renames a trigger; a rename into a collision counts too. */
    const char *c2 =
        "[global]\ninterface = lo\n"
        "[trigger:a]\nservice = ssh\nport = 22\nsequence = 1,2,3\n"
        "[trigger:b]\nservice = ssh\nport = 23\nsequence = 4,5,6\n";
    CHECK(parse(c2, err, sizeof(err)) == -1);

    /* distinct names are fine */
    const char *ok = "[global]\ninterface = lo\n"
                     "[trigger:web1]\nport = 80\nsequence = 1,2,3\n"
                     "[trigger:web2]\nport = 443\nsequence = 4,5,6\n";
    CHECK_EQ_INT(parse(ok, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.n_triggers, 2);
}

/* Names that don't fit the 64-byte table name used to be truncated, so two
 * long names with a common prefix collided silently. */
static void test_service_name_too_long(void)
{
    char err[256];
    char c[512];
    char longname[80];
    memset(longname, 'x', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(c, sizeof(c), "[trigger:%s]\nport = 22\nsequence = 1,2,3\n",
             longname);
    CHECK(parse(c, err, sizeof(err)) == -1);
    CHECK(strstr(err, "too long") != NULL);
}

static void test_empty_service_name(void)
{
    char err[256];
    CHECK(parse("[trigger:]\nport = 22\nsequence = 1,2,3\n", err,
                sizeof(err)) == -1);
    CHECK(parse("[trigger:  ]\nport = 22\nsequence = 1,2,3\n", err,
                sizeof(err)) == -1);
    CHECK(parse("[trigger:t]\nservice =\nport = 22\nsequence = 1,2,3\n", err,
                sizeof(err)) == -1);
}

/* Source port 0 can't be bound by a client, so it can't be knocked. */
static void test_sequence_port_zero(void)
{
    char err[256];
    CHECK(parse("[trigger:t]\nport = 22\nsequence = 7000,0,9000\n", err,
                sizeof(err)) == -1);
    CHECK(parse("[trigger:t]\nport = 22\nsequence = 1,2,3\n"
                "admin_sequence = 0\n",
                err, sizeof(err)) == -1);
    CHECK(parse("[trigger:t]\nport = 22\nsequence = 1,,3\n", err,
                sizeof(err)) == 0); /* empty items are skipped, as before */
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 2);
}

/* Repeated keys replace the earlier value (and must not leak it: LSan). */
static void test_repeated_keys(void)
{
    char err[256];
    const char *c = "[trigger:t]\nport = 22\nport = 2222, 2223\n"
                    "sequence = 1,2,3\nsequence = 7,8,9,10\n"
                    "admin_sequence = 1,2,3\nadmin_sequence = 4,5,6\n";
    CHECK_EQ_INT(parse(c, err, sizeof(err)), 0);
    CHECK_EQ_INT(g_cfg.triggers[0].n_ports, 2);
    CHECK_EQ_INT(g_cfg.triggers[0].ports[0], 2222);
    CHECK_EQ_INT(g_cfg.triggers[0].seq_len, 4);
    CHECK_EQ_INT(g_cfg.triggers[0].sequence[0], 7);
    CHECK_EQ_INT(g_cfg.triggers[0].admin_sequence[0], 4);
}

/* Every kind of error after triggers were parsed leaves g_cfg empty and frees
 * what was parsed so far (LSan checks the freeing). */
static void test_error_paths_leave_nothing(void)
{
    char err[256];
    const char *bad[] = {
        "[trigger:a]\nport = 22\nsequence = 1,2,3\n[bogus]\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\n[global]\nnope = 1\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\n[trigger:b]\nport = x\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nprotocol = sctp\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nsequence = 1,x\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nadmin_sequence = x\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nwindow = -1\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nmode = never\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nduration = 0\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nfallback_ttl = abc\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\nunknown = 1\n",
        "[trigger:a]\nport = 22\nsequence = 1,2,3\n[trigger:b\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        CHECK_EQ_INT(parse(good_cfg, err, sizeof(err)), 0);
        CHECK(parse(bad[i], err, sizeof(err)) == -1);
        CHECK(err[0] != '\0');
        CHECK_EQ_INT(g_cfg.n_triggers, 0);
        CHECK(g_cfg.triggers == NULL);
    }
}

static void test_config_table_name(void)
{
    char out[CONFIG_TABLE_NAME_MAX];
    CHECK_EQ_INT(config_table_name("ssh", out, sizeof(out)), 0);
    CHECK_EQ_INT(strcmp(out, "inet sourceknock_ssh"), 0);
    CHECK_EQ_INT(config_table_name("web-1.x", out, sizeof(out)), 0);
    CHECK_EQ_INT(strcmp(out, "inet sourceknock_web_1_x"), 0);

    /* "inet sourceknock_" is 17 chars, so 46 more fill 63 + NUL exactly. */
    char fits[47];
    memset(fits, 'a', 46);
    fits[46] = '\0';
    CHECK_EQ_INT(config_table_name(fits, out, sizeof(out)), 0);
    CHECK_EQ_INT(strlen(out), 63);
    char over[48];
    memset(over, 'a', 47);
    over[47] = '\0';
    CHECK_EQ_INT(config_table_name(over, out, sizeof(out)), -1);
}

static void test_weak_sequence(void)
{
    char msg[160];
    uint16_t two[] = {7000, 8000};
    uint16_t three[] = {7000, 8000, 9000};
    uint16_t eph[] = {7000, 40000, 9000};
    uint16_t edge_lo[] = {7000, 32767, 9000};
    uint16_t edge_hi[] = {7000, 61000, 9000};
    uint16_t in_lo[] = {32768, 8000, 9000};
    uint16_t in_hi[] = {7000, 8000, 60999};
    trigger_t t;
    memset(&t, 0, sizeof(t));

    t.sequence = two;
    t.seq_len = 2;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 1);
    CHECK(strstr(msg, "at least 3") != NULL);
    t.sequence = three;
    t.seq_len = 3;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 0);
    t.sequence = eph;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 1);
    CHECK(strstr(msg, "40000") != NULL);
    t.sequence = edge_lo;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 0);
    t.sequence = edge_hi;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 0);
    t.sequence = in_lo;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 1);
    t.sequence = in_hi;
    CHECK_EQ_INT(config_weak_sequence(&t, msg, sizeof(msg)), 1);
}

/* Read a whole file (tests run from the repo root). */
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n)
    {
        free(buf);
        buf = NULL;
    }
    if (buf)
        buf[n] = '\0';
    fclose(f);
    return buf;
}

/* The README's Configuration example must parse as-is (it used inline
 * comments, which the parser does not strip). */
static void test_readme_example_parses(void)
{
    char err[256];
    char *md = slurp("README.md");
    CHECK(md != NULL);
    if (!md)
        return;
    char *start = strstr(md, "```ini\n");
    CHECK(start != NULL);
    if (start)
    {
        start += strlen("```ini\n");
        char *end = strstr(start, "```");
        CHECK(end != NULL);
        if (end)
        {
            *end = '\0';
            int rc = parse(start, err, sizeof(err));
            if (rc != 0)
                fprintf(stderr, "  README example: %s\n", err);
            CHECK_EQ_INT(rc, 0);
            CHECK_EQ_INT(g_cfg.n_triggers, 1);
        }
    }
    free(md);
}

/* Every shipped example must parse. */
static void test_examples_parse(void)
{
    const char *files[] = {
        "examples/sourceknock.conf", "examples/ssh.conf",
        "examples/web.conf",         "examples/udp/wireguard.conf",
        "tests/e2e_fixed.conf",      "tests/e2e_close.conf",
    };
    char err[256];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
    {
        int rc = config_parse_file(files[i], err, sizeof(err));
        if (rc != 0)
            fprintf(stderr, "  %s: %s\n", files[i], err);
        CHECK_EQ_INT(rc, 0);
        CHECK(g_cfg.n_triggers >= 1);
    }
}

/* ---- issue #40: knock_port ---- */
static void test_knock_port(void)
{
    char err[256];
    CHECK_EQ_INT(
        parse("[trigger:t]\nport = 22\nsequence = 1,2,3\n", err, sizeof(err)),
        0);
    CHECK_EQ_INT(g_cfg.triggers[0].knock_port, 0); /* default: any port */
    CHECK_EQ_INT(parse("[trigger:t]\nport = 22\nsequence = 1,2,3\n"
                       "knock_port = 4444\n",
                       err, sizeof(err)),
                 0);
    CHECK_EQ_INT(g_cfg.triggers[0].knock_port, 4444);
    CHECK_EQ_INT(parse("[trigger:t]\nport = 22\nsequence = 1,2,3\n"
                       "knock_port = 65535\n",
                       err, sizeof(err)),
                 0);
    const char *bad[] = {"0", "65536", "-1", "abc", "44x", "", "1,2"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        char c[128];
        snprintf(c, sizeof(c),
                 "[trigger:t]\nport = 22\nsequence = 1,2,3\nknock_port = %s\n",
                 bad[i]);
        CHECK(parse(c, err, sizeof(err)) == -1);
        CHECK(strstr(err, "knock_port") != NULL);
    }
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
    TEST_RUN(test_key_before_section);
    TEST_RUN(test_missing_port);
    TEST_RUN(test_table_name_collision);
    TEST_RUN(test_service_name_too_long);
    TEST_RUN(test_empty_service_name);
    TEST_RUN(test_sequence_port_zero);
    TEST_RUN(test_repeated_keys);
    TEST_RUN(test_error_paths_leave_nothing);
    TEST_RUN(test_config_table_name);
    TEST_RUN(test_weak_sequence);
    TEST_RUN(test_readme_example_parses);
    TEST_RUN(test_examples_parse);
    TEST_RUN(test_knock_port);
    config_free();
    TEST_SUMMARY();
}
