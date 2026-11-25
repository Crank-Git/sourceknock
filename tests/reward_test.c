/* reward_test.c - unit tests for the nft script builder. */
#include <string.h>

#include "reward.h"
#include "test.h"

static const char SETS_FMT_HEAD[] = "add table inet sourceknock_t\n";

/* TCP with two ports: every rule, in order, per port. */
static void test_script_tcp_two_ports(void)
{
    uint16_t ports[] = {22, 2222};
    char buf[4096];
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", "eth0",
                           ports, 2, PROTO_TCP, 256);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_STR(
        buf,
        "add table inet sourceknock_t\n"
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
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", "wg0", ports,
                           1, PROTO_UDP, 256);
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
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", "eth0",
                           ports, 1, PROTO_TCP, 1024);
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
    int rc = reward_script(buf, sizeof(buf), "inet sourceknock_t", "eth0",
                           ports, 2, PROTO_TCP, 256);
    CHECK_EQ_INT(rc, -1);
    rc = reward_script(buf, 0, "inet sourceknock_t", "eth0", ports, 2,
                       PROTO_TCP, 256);
    CHECK_EQ_INT(rc, -1);
}

int main(void)
{
    TEST_RUN(test_script_tcp_two_ports);
    TEST_RUN(test_script_udp_one_port);
    TEST_RUN(test_script_max_allowed);
    TEST_RUN(test_script_buffer_too_small);
    TEST_SUMMARY();
}
