#include <click/config.h>
#include "clara_counter.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <algorithm>
#include <click/args.hh>
CLICK_DECLS

ClaraCounter::ClaraCounter(): _active(true)
{
}

ClaraCounter::~ClaraCounter()
{
}

int
ClaraCounter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
      .read("ACTIVE", _active).complete();
}

Packet *
ClaraCounter::simple_action(Packet *p)
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

    counter._count += 1;
    counter._byte_count += ip->ip_len;
    counter._rate += 1;
    counter._byte_rate += ip->ip_len;
    if (counter._count == counter._count_trigger && !counter._count_triggered) {
        counter._count_triggered = 1;
        if (counter._count_trigger_h)
           counter._count_trigger_h += 1;
    }
    return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ClaraCounter)
