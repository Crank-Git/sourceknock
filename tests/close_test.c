/* close_test.c - unit tests for the close_on_connect decision. */
#include <string.h>

#include "close.h"
#include "test.h"

static trigger_t make_trigger(trigger_mode_t mode, const uint16_t *ports,
                              size_t n)
{
    trigger_t tr;
    memset(&tr, 0, sizeof(tr));
    strcpy(tr.service, "t");
    tr.ports = (uint16_t *)ports;
    tr.n_ports = n;
    tr.protocol = PROTO_UDP;
    tr.mode = mode;
    return tr;
}

/* Not armed -> never close, even if a packet hits a service port. */
static void test_close_only_when_armed(void)
{
    uint16_t ports[] = {22};
    trigger_t tr = make_trigger(MODE_CLOSE_ON_CONNECT, ports, 1);
    CHECK(!should_close(&tr, 0, 22, KNOCK_IGNORE));
}

/* The arming knock (KNOCK_TRIGGER) must NOT close the port the instant it
 * opens; a subsequent UDP packet to the service port DOES close it. */
static void test_arming_knock_does_not_close(void)
{
    uint16_t ports[] = {22};
    trigger_t tr = make_trigger(MODE_CLOSE_ON_CONNECT, ports, 1);
    CHECK(!should_close(&tr, 1, 22, KNOCK_TRIGGER));
    CHECK(should_close(&tr, 1, 22, KNOCK_IGNORE));
    CHECK(should_close(&tr, 1, 22, KNOCK_RESET));
}

/* Only a packet to one of the service ports closes the port. */
static void test_dport_must_match(void)
{
    uint16_t ports[] = {22};
    trigger_t tr = make_trigger(MODE_CLOSE_ON_CONNECT, ports, 1);
    CHECK(!should_close(&tr, 1, 80, KNOCK_IGNORE));
}

/* Only close_on_connect mode closes; fixed_ttl never does. */
static void test_only_close_on_connect_mode(void)
{
    uint16_t ports[] = {22};
    trigger_t fixed = make_trigger(MODE_FIXED_TTL, ports, 1);
    CHECK(!should_close(&fixed, 1, 22, KNOCK_IGNORE));
}

static void test_port_in_list(void)
{
    uint16_t ports[] = {22, 80, 443};
    trigger_t tr = make_trigger(MODE_CLOSE_ON_CONNECT, ports, 3);
    CHECK(port_in_list(&tr, 80));
    CHECK(!port_in_list(&tr, 25));
}

int main(void)
{
    printf("== close decision tests ==\n");
    TEST_RUN(test_close_only_when_armed);
    TEST_RUN(test_arming_knock_does_not_close);
    TEST_RUN(test_dport_must_match);
    TEST_RUN(test_only_close_on_connect_mode);
    TEST_RUN(test_port_in_list);
    TEST_SUMMARY();
}
