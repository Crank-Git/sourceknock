/* reward_test.c - unit tests for the nft script builder. */
#include <string.h>

#include "reward.h"
#include "test.h"

#define OWNER "/etc/sourceknock/a.conf"
static const char SETS_FMT_HEAD[] =
    "add table inet sourceknock_t { comment \"sourceknock:" OWNER "\"; }\n";

/* TCP with two ports: every rule, in order, per port. */
static void test_script_tcp_two_ports(void)
{
    uint16_t ports[] = {22, 2222};
    char buf[4096];
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", OWNER,
                           "eth0", ports, 2, PROTO_TCP, 256);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_STR(
        buf,
        "add table inet sourceknock_t { comment "
        "\"sourceknock:/etc/sourceknock/a.conf\"; }\n"
        "add set inet sourceknock_t allowed_v4 { type ipv4_addr; flags "
        "timeout; size 256; }\n"
        "add set inet sourceknock_t allowed_v6 { type ipv6_addr; flags "
        "timeout; size 256; }\n"
        "add chain inet sourceknock_t service { type filter hook input "
        "priority 0; policy accept; }\n"
        "flush chain inet sourceknock_t service\n"
        "add rule inet sourceknock_t service ct state established,related "
        "accept\n"
        "add rule inet sourceknock_t service ip saddr @allowed_v4 tcp dport "
        "22 accept\n"
        "add rule inet sourceknock_t service ip6 saddr @allowed_v6 tcp dport "
        "22 accept\n"
        "add rule inet sourceknock_t service tcp dport 22 tcp flags & (syn | "
        "ack) == ack accept\n"
        "add rule inet sourceknock_t service iifname \"eth0\" tcp dport 22 "
        "drop\n"
        "add rule inet sourceknock_t service ip saddr @allowed_v4 tcp dport "
        "2222 accept\n"
        "add rule inet sourceknock_t service ip6 saddr @allowed_v6 tcp dport "
        "2222 accept\n"
        "add rule inet sourceknock_t service tcp dport 2222 tcp flags & (syn "
        "| ack) == ack accept\n"
        "add rule inet sourceknock_t service iifname \"eth0\" tcp dport 2222 "
        "drop\n");
}

/* UDP has no stray-ACK rule. */
static void test_script_udp_one_port(void)
{
    uint16_t ports[] = {5353};
    char buf[4096];
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", OWNER, "wg0",
                           ports, 1, PROTO_UDP, 256);
    CHECK_EQ_INT(rc, 0);
    CHECK(strstr(buf, "udp dport 5353 accept") != NULL);
    CHECK(strstr(buf, "tcp flags") == NULL);
    CHECK(strstr(buf, "iifname \"wg0\" udp dport 5353 drop\n") != NULL);
    CHECK(strncmp(buf, SETS_FMT_HEAD, strlen(SETS_FMT_HEAD)) == 0);
}

/* max_allowed reaches both set sizes. */
static void test_script_max_allowed(void)
{
    uint16_t ports[] = {22};
    char buf[4096];
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", OWNER,
                           "eth0", ports, 1, PROTO_TCP, 1024);
    CHECK_EQ_INT(rc, 0);
    CHECK(strstr(buf, "allowed_v4 { type ipv4_addr; flags timeout; size "
                      "1024; }\n") != NULL);
    CHECK(strstr(buf, "allowed_v6 { type ipv6_addr; flags timeout; size "
                      "1024; }\n") != NULL);
}

/* A buffer that is too small is an error, never a truncated script. */
static void test_script_buffer_too_small(void)
{
    uint16_t ports[] = {22, 2222};
    char buf[64];
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", OWNER,
                           "eth0", ports, 2, PROTO_TCP, 256);
    CHECK_EQ_INT(rc, -1);
    rc = reward_script(buf, 0, "inet sourceknock_t", OWNER, "eth0", ports, 2,
                       PROTO_TCP, 256);
    CHECK_EQ_INT(rc, -1);
}

/* The owner mark is "sourceknock:" plus the config path. */
static void test_owner_mark(void)
{
    char m[160];
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), "/etc/sourceknock/a.conf"), 0);
    CHECK_EQ_STR(m, "sourceknock:/etc/sourceknock/a.conf");
}

/* A path that nft refuses or misreads is an error, not a bad mark. nft allows
 * 128 characters in a comment; a quote or backslash breaks the script's
 * quoting. */
static void test_owner_mark_rejects_bad_paths(void)
{
    char m[160];
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), "/etc/a\"b.conf"), -1);
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), "/etc/a\\b.conf"), -1);
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), "/etc/a\nb.conf"), -1);
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), ""), -1);
    char longp[200];
    memset(longp, 'x', sizeof(longp));
    longp[0] = '/';
    longp[117] = '\0'; /* 12 + 117 = 129 characters */
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), longp), -1);
    longp[116] = '\0'; /* 12 + 116 = 128 characters */
    CHECK_EQ_INT(reward_owner_mark(m, sizeof(m), longp), 0);
    CHECK_EQ_INT(reward_owner_mark(m, 10, "/etc/a.conf"), -1);
}

/* The script builder refuses a path that cannot be a safe comment, so a
 * hostile path cannot inject a command. */
static void test_script_rejects_bad_owner(void)
{
    uint16_t ports[] = {22};
    char buf[4096];
    CHECK_EQ_INT(reward_script(buf, sizeof(buf), "inet sourceknock_t",
                               "/etc/a\"; flush ruleset; \"", "eth0", ports, 1,
                               PROTO_TCP, 256),
                 -1);
}

/* The comment is the first thing nft prints inside the table. */
static void test_parse_owner(void)
{
    char o[160];
    const char *listing = "table inet sourceknock_ssh {\n"
                          "\tcomment \"sourceknock:/etc/a b.conf\"\n"
                          "\tset allowed_v4 {\n\t\ttype ipv4_addr\n\t}\n}\n";
    CHECK_EQ_INT(reward_parse_owner(listing, o, sizeof(o)), 1);
    CHECK_EQ_STR(o, "sourceknock:/etc/a b.conf");
}

/* No comment, no owner. A comment on a set or chain further in is not the
 * table's. */
static void test_parse_owner_none(void)
{
    char o[160];
    CHECK_EQ_INT(reward_parse_owner("table inet sourceknock_x {\n"
                                    "\tset s {\n\t\tcomment \"mine\"\n\t}\n}\n",
                                    o, sizeof(o)),
                 0);
    CHECK_EQ_INT(
        reward_parse_owner("table inet sourceknock_x {\n}\n", o, sizeof(o)), 0);
    CHECK_EQ_INT(reward_parse_owner("", o, sizeof(o)), 0);
    CHECK_EQ_INT(reward_parse_owner("table inet x {\n\tcomment \"unclosed\n", o,
                                    sizeof(o)),
                 0);
}

/* A comment that does not fit the buffer is no match, never a prefix that
 * could equal our mark. */
static void test_parse_owner_too_long(void)
{
    char o[8];
    CHECK_EQ_INT(
        reward_parse_owner("table inet x {\n\tcomment \"sourceknock:/a\"\n}\n",
                           o, sizeof(o)),
        0);
}

int main(void)
{
    TEST_RUN(test_script_tcp_two_ports);
    TEST_RUN(test_script_udp_one_port);
    TEST_RUN(test_script_max_allowed);
    TEST_RUN(test_script_buffer_too_small);
    TEST_RUN(test_owner_mark);
    TEST_RUN(test_owner_mark_rejects_bad_paths);
    TEST_RUN(test_script_rejects_bad_owner);
    TEST_RUN(test_parse_owner);
    TEST_RUN(test_parse_owner_none);
    TEST_RUN(test_parse_owner_too_long);
    TEST_SUMMARY();
}
