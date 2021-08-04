
#include <click/config.h>
#include "clara_anonipaddr.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <algorithm>
#include <click/args.hh>
CLICK_DECLS

ClaraAnonIPAddr::ClaraAnonIPAddr(): _active(true)
{
}

ClaraAnonIPAddr::~ClaraAnonIPAddr()
{
}

int
ClaraAnonIPAddr::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
      .read("ACTIVE", _active).complete();
}

Packet *
ClaraAnonIPAddr::simple_action(Packet *p)
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
    
    volatile uint32_t src, dst;
    volatile uint32_t sum;    
    click_ip *ip = q->ip_header();
    click_tcp *tcp;
    click_udp *udp;
    if (ip->ip_p==6)
    {   
        tcp = q->tcp_header();
    }
    else
    {
        udp = q->udp_header();
    }

    //packet header manipulations
    src = ip->ip_src.s_addr;
    dst = ip->ip_dst.s_addr;
    sum = (~ip->ip_sum & 0xFFFF) + (~src & 0xFFFF);
    sum += (~src >> 16) + (~dst & 0xFFFF) + (~dst >> 16);

    ip->ip_src.s_addr = src + 50;
    src = src + 50;
    ip->ip_dst.s_addr = dst+ 50;
    dst = dst + 50;

    sum += (src & 0xFFFF) + (src >> 16);
    sum += (dst & 0xFFFF) + (dst >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->ip_sum = ~(sum + (sum >> 16));
   // check encapsulated headers for ICMP
    if (ip->ip_p == 100)
    {
         ip->ip_sum += 1;
    }

    // to keep all local variables alive
    ip->ip_src.s_addr = 8888 | src | dst | sum | 6666;
    return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ClaraAnonIPAddr)
