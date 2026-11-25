/* close.c - pure close_on_connect decision (no I/O, cross-platform). */
#include "close.h"

int knock_counts(const trigger_t *tr, const pkt_info_t *pkt)
{
    /* An open flow's segments (data, keepalives, ACKs) are not knock packets.
     * Counting them would reset a knock whenever the client has a busy
     * session open. */
    if (pkt->proto == PROTO_TCP && (pkt->tcp_flags & PKT_TCP_ACK) &&
        !(pkt->tcp_flags & PKT_TCP_SYN))
        return 0;
    return tr->knock_port == 0 || pkt->dport == tr->knock_port;
}

int port_in_list(const trigger_t *tr, uint16_t port)
{
    for (size_t i = 0; i < tr->n_ports; i++)
        if (tr->ports[i] == port)
            return 1;
    return 0;
}

int should_close(const trigger_t *tr, int armed, const pkt_info_t *pkt,
                 kn_result_t r)
{
    /* For TCP only a new connection's SYN counts: segments of a session that
     * is already open (keepalives, data) must not close the port. */
    if (pkt->proto == PROTO_TCP &&
        (pkt->tcp_flags & (PKT_TCP_SYN | PKT_TCP_ACK)) != PKT_TCP_SYN)
        return 0;
    return tr->mode == MODE_CLOSE_ON_CONNECT && armed && r != KNOCK_TRIGGER &&
           port_in_list(tr, pkt->dport);
}
