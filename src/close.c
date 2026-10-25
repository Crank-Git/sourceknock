/* close.c - pure close_on_connect decision (no I/O, cross-platform). */
#include "close.h"

int port_in_list(const trigger_t *tr, uint16_t port)
{
    for (size_t i = 0; i < tr->n_ports; i++)
        if (tr->ports[i] == port)
            return 1;
    return 0;
}

int should_close(const trigger_t *tr, int armed, uint16_t dport, kn_result_t r)
{
    return tr->mode == MODE_CLOSE_ON_CONNECT && armed && r != KNOCK_TRIGGER &&
           port_in_list(tr, dport);
}
