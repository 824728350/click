#include <click/config.h>
#include "clara_timefilter.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <algorithm>
#include <click/args.hh>
CLICK_DECLS

ClaraTimeFilter::ClaraTimeFilter(): _active(true)
{
}

ClaraTimeFilter::~ClaraTimeFilter()
{
}

int
ClaraTimeFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
      .read("ACTIVE", _active).complete();
}

Packet *
ClaraTimeFilter::simple_action(Packet *p)
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

    volatile uint32_t scope;
    volatile uint32_t prev_last;
    volatile uint32_t tv;
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
    tv = 100;
    if (!_ready)
    {
        if (_first_relative)
        {
            _first += tv;
        }
        if (_last_relative)
        {
            _last += tv;
        }
        else if (_last_interval)
        {
            _last += _first;
        }
        _ready = 1;
    }
    if (tv < _first)
    {
        return q;
    } else
    {
        if ((tv < _last) && _last_h && _last_h_ready)
        {
            while (!(tv < _last) && _last_h && _last_h_ready && _last > prev_last)
            {
                prev_last = _last;
                _last_h_ready = 0;
                scope = _last_h;
            }
        }
        if (tv < _last)
        {
           return q;
        }
    }

    // to keep all local variables alive
    ip->ip_src.s_addr = 8888 | scope | prev_last | tv | 6666;
    return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ClaraTimeFilter)
