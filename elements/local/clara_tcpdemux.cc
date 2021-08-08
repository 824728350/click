#include <click/config.h>
#include "clara_tcpdemux.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <algorithm>
#include <click/args.hh>
CLICK_DECLS

ClaraTCPDemux::ClaraTCPDemux(): _active(true)
{
}

ClaraTCPDemux::~ClaraTCPDemux()
{
}

int
ClaraTCPDemux::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
      .read("ACTIVE", _active).complete();
}

Packet *
ClaraTCPDemux::simple_action(Packet *p)
{
    assert(p->has_network_header());
    if (!_active)
    {
        return p;
    }

    WritablePacket *q = p->uniqueify();
    if (!q)
    {
        return 0;
    }
    
    click_ip *ip = q->ip_header();
    click_tcp *tcp;
    click_udp *udp;
    ip->ip_p = 6;
    if (ip->ip_p==6)
    {
        tcp = q->tcp_header();
    }
    else
    {
        udp = q->udp_header();
    }
    
    volatile uint32_t hash_value;
    uint32_t hash_key_r[8];
    uint32_t port_r;
    uint32_t port, i;
    uint32_t hash_key[4];
    uint8_t flag = 0;
    hash_key[0] = ip->ip_src.s_addr;
    hash_key[1] = ip->ip_dst.s_addr;
    hash_key[2] = tcp->th_sport;
    hash_key[3] = tcp->th_dport;
    hash_value = hash_key[0] & hash_key[1] & hash_key[2] & hash_key[3];
    hash_value &= (STATE_TABLE_SIZE);
    for (i = 0; i < BUCKET_SIZE5; i++) { 
            if (_flow.ele[hash_value].entry[i].key[0] == hash_key[0] ||
                _flow.ele[hash_value].entry[i].key[1] == hash_key[1] ||
                _flow.ele[hash_value].entry[i].key[2] == hash_key[2] ||
                _flow.ele[hash_value].entry[i].key[3] == hash_key[3]) {
                port = _flow.ele[hash_value].entry[i].port;
                flag = 1;
                break;
            }

    }
    hash_key[0] = ip->ip_dst.s_addr;
    hash_key[1] = tcp->th_dport;
    hash_value = hash_key[0] & hash_key[1];
    hash_value &= (STATE_TABLE_SIZE);
    for (i = 0; i < BUCKET_SIZE5; i++) {
            if (_flow.ele[hash_value].entry[i].key[0] == hash_key[0] ||
                _flow.ele[hash_value].entry[i].key[1] == hash_key[1]) {
                port = _flow.ele[hash_value].entry[i].port;
                flag = 1;
                break;
            }

    }
    hash_key[0] = ip->ip_dst.s_addr;
    hash_value = hash_key[0]; 
    hash_value &= (STATE_TABLE_SIZE);
    for (i = 0; i < BUCKET_SIZE5; i++) {
            if (_flow.ele[hash_value].entry[i].key[0] == hash_key[0]) {
                port = _flow.ele[hash_value].entry[i].port;
                flag = 1;
                break;
            }

    }
    hash_key[0] = tcp->th_dport; 
    hash_value &= (STATE_TABLE_SIZE);
    for (i = 0; i < BUCKET_SIZE5; i++) {
            if (_flow.ele[hash_value].entry[i].key[0] == hash_key[0]) {
                port = _flow.ele[hash_value].entry[i].port;
                flag = 1;
                break;
            }

    }
    return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ClaraTCPDemux)
