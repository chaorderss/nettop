/*
*	nettop (C) 2017-2020 E. Oriani, ema <AT> fastwebnet <DOT> it
*
*	This file is part of nettop.
*
*	nettop is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	nettop is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with nettop.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "cap_mgr.h"
#include "utils.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstring>
#include <string>
#include "addr_t.h"
#include "settings.h"

namespace {

	typedef std::list<nettop::packet_stats>	st_pkt_list;

#ifdef __APPLE__
	inline uint16_t tcp_src_port(const struct tcphdr *tcp) { return ntohs(tcp->th_sport); }
	inline uint16_t tcp_dst_port(const struct tcphdr *tcp) { return ntohs(tcp->th_dport); }
	inline uint16_t udp_src_port(const struct udphdr *udp) { return ntohs(udp->uh_sport); }
	inline uint16_t udp_dst_port(const struct udphdr *udp) { return ntohs(udp->uh_dport); }
#else
	inline uint16_t tcp_src_port(const struct tcphdr *tcp) { return ntohs(tcp->source); }
	inline uint16_t tcp_dst_port(const struct tcphdr *tcp) { return ntohs(tcp->dest); }
	inline uint16_t udp_src_port(const struct udphdr *udp) { return ntohs(udp->source); }
	inline uint16_t udp_dst_port(const struct udphdr *udp) { return ntohs(udp->dest); }
#endif

	struct cap_ctx {
		st_pkt_list	p_list;
		const int	link_type;

		cap_ctx(const int link_type_) : link_type(link_type_) {
		}
	};

	// linux cooked header
	// glanced from libpcap/ssl.h
	#define SLL_ADDRLEN     	(8)               /* length of address field */
	#define SLL_PROTOCOL_IP		(0x0008)
	#define SLL_PROTOCOL_IP6	(0xDD86)
	struct sll_header {
        	u_int16_t	sll_pkttype;          /* packet type */
        	u_int16_t	sll_hatype;           /* link-layer address type */
        	u_int16_t	sll_halen;            /* link-layer address length */
        	u_int8_t	sll_addr[SLL_ADDRLEN]; /* link-layer address */
        	u_int16_t	sll_protocol;         /* protocol */
	};

	inline void process_tcp(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		if(avail < sizeof(struct tcphdr))
			return;
		const struct tcphdr	*tcp = (struct tcphdr*)data;
		const uint16_t		p_src = tcp_src_port(tcp),
					p_dst = tcp_dst_port(tcp);
		p_list.push_back(nettop::packet_stats(src, dst, p_src, p_dst, len, nettop::packet_stats::type::PACKET_TCP, ts));
	}

	inline void process_udp(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		if(avail < sizeof(struct udphdr))
			return;
		const struct udphdr	*udp = (struct udphdr*)data;
		const uint16_t		p_src = udp_src_port(udp),
					p_dst = udp_dst_port(udp);
		p_list.push_back(nettop::packet_stats(src, dst, p_src, p_dst, len, nettop::packet_stats::type::PACKET_UDP, ts));
	}

	inline void process_ip(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len) {
		if(avail < sizeof(struct ip))
			return;
		const struct ip *ip = (struct ip*)data;
		const size_t ip_hl = ip->ip_hl*4;
		if(ip_hl < sizeof(struct ip) || avail < ip_hl)
			return;
		const addr_t	src(ip->ip_src),
				dst(ip->ip_dst);
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				process_tcp(data + ip_hl, avail - ip_hl, p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + ip_hl, avail - ip_hl, p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip->ip_p << ", skipping packet" << std::endl;
				break;
		}
	}

	inline void process_ip6(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len) {
		if(avail < sizeof(struct ip6_hdr))
			return;
		const struct ip6_hdr	*ip6 = (struct ip6_hdr*)data;
		const addr_t		src(ip6->ip6_src),
					dst(ip6->ip6_dst);
		switch(ip6->ip6_nxt) {
			case IPPROTO_TCP:
				process_tcp(data + sizeof(struct ip6_hdr), avail - sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + sizeof(struct ip6_hdr), avail - sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip6->ip6_nxt << ", skipping packet" << std::endl;
				break;
		}
	}

	inline void process_raw_ip(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len) {
		if(avail < 1)
			return;
		switch(data[0] >> 4) {
			case 4:
				process_ip(data, avail, p_list, ts, len);
				break;
			case 6:
				process_ip6(data, avail, p_list, ts, len);
				break;
			default:
				break;
		}
	}

	inline void process_ethernet(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len) {
		if(avail < ETHER_HDR_LEN)
			return;
		const struct ether_header	*eth = (struct ether_header*)data;
		uint16_t			ether_type = ntohs(eth->ether_type);
		size_t				offset = ETHER_HDR_LEN;
		while(ether_type == ETHERTYPE_VLAN || ether_type == 0x88a8) {
			if(avail < offset + 4)
				return;
			uint16_t next_type = 0;
			std::memcpy(&next_type, data + offset + 2, sizeof(next_type));
			ether_type = ntohs(next_type);
			offset += 4;
		}
		if(avail < offset)
			return;
		switch(ether_type) {
			case ETHERTYPE_IP:
				process_ip(data + offset, avail - offset, p_list, ts, len);
				break;
			case ETHERTYPE_IPV6:
				process_ip6(data + offset, avail - offset, p_list, ts, len);
				break;
			default:
				break;
		}
	}

	inline void process_loopback(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len, const bool network_order) {
		if(avail < sizeof(uint32_t))
			return;
		uint32_t family = 0;
		std::memcpy(&family, data, sizeof(family));
		if(network_order)
			family = ntohl(family);
		switch(family) {
			case AF_INET:
				process_ip(data + sizeof(uint32_t), avail - sizeof(uint32_t), p_list, ts, len);
				break;
			case AF_INET6:
				process_ip6(data + sizeof(uint32_t), avail - sizeof(uint32_t), p_list, ts, len);
				break;
			default:
				break;
		}
	}

	inline void process_sll(const u_char *data, const size_t avail, st_pkt_list& p_list, const double ts, const size_t len) {
		if(avail < sizeof(struct sll_header))
			return;
		const struct sll_header *sll = (struct sll_header*)data;
		switch(sll->sll_protocol) {
			case SLL_PROTOCOL_IP:
				process_ip(data + sizeof(struct sll_header), avail - sizeof(struct sll_header), p_list, ts, len);
				break;
			case SLL_PROTOCOL_IP6:
				process_ip6(data + sizeof(struct sll_header), avail - sizeof(struct sll_header), p_list, ts, len);
				break;
			default:
				//std::cerr << "Unknown SLL protocol " << (int)sll->sll_protocol << ", skipping packet" << std::endl;
				break;
		}
	}

	void p_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
		cap_ctx& 		ctx = *(cap_ctx*)user;
		const double		ts = nettop::tv_to_sec(header->ts);
		switch(ctx.link_type) {
			case DLT_LINUX_SLL:
				process_sll(data, header->caplen, ctx.p_list, ts, header->len);
				break;
			case DLT_EN10MB:
				process_ethernet(data, header->caplen, ctx.p_list, ts, header->len);
				break;
			case DLT_NULL:
				process_loopback(data, header->caplen, ctx.p_list, ts, header->len, false);
				break;
			case DLT_LOOP:
				process_loopback(data, header->caplen, ctx.p_list, ts, header->len, true);
				break;
			case DLT_RAW:
				process_raw_ip(data, header->caplen, ctx.p_list, ts, header->len);
				break;
			default:
				break;
		}
	}

#ifdef __APPLE__
	std::string choose_device() {
		if(!nettop::settings::INTERFACE.empty())
			return nettop::settings::INTERFACE;

		char		err[PCAP_ERRBUF_SIZE+1] = {0};
		pcap_if_t	*devs = 0;
		if(-1 == pcap_findalldevs(&devs, err))
			throw nettop::runtime_error(err);
		std::string	fallback,
				selected;
		for(pcap_if_t *dev = devs; dev; dev = dev->next) {
			if(!dev->name)
				continue;
			if(fallback.empty())
				fallback = dev->name;
			bool has_ip = false;
			for(pcap_addr_t *addr = dev->addresses; addr; addr = addr->next) {
				if(addr->addr && (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6)) {
					has_ip = true;
					break;
				}
			}
			if(has_ip && !(dev->flags & PCAP_IF_LOOPBACK)) {
				selected = dev->name;
				break;
			}
		}
		if(selected.empty())
			selected = fallback;
		pcap_freealldevs(devs);
		if(selected.empty())
			throw nettop::runtime_error("No libpcap capture device found");
		return selected;
	}
#endif
}

nettop::cap_mgr::cap_mgr() : p_(0), link_type_(0) {
	// open all network devices
	char	err[PCAP_ERRBUF_SIZE+1];
#ifdef __APPLE__
	const std::string	dev = choose_device();
	p_ = pcap_open_live(dev.c_str(), BUFSIZ, 0, 250, err);
#else
	p_ = pcap_open_live(nettop::settings::INTERFACE.empty() ? NULL : nettop::settings::INTERFACE.c_str(), BUFSIZ, 0, 250, err);
#endif
	if(!p_)
		throw runtime_error(err);
	link_type_ = pcap_datalink(p_);
	switch(link_type_) {
		case DLT_LINUX_SLL:
		case DLT_EN10MB:
		case DLT_NULL:
		case DLT_LOOP:
		case DLT_RAW:
			break;
		default:
		pcap_close(p_);
			throw runtime_error("Link type: ") << link_type_ << " is not supported by this build";
	}
}

nettop::cap_mgr::~cap_mgr() {
	pcap_close(p_);
}

void nettop::cap_mgr::capture_dispatch(packet_list& p_list) {
	cap_ctx		ctx(link_type_);
	const int dres = pcap_dispatch(p_, -1, p_handler, (u_char*)&ctx);
	// we never call pcap_breakloop
	if(-1 == dres)
		throw runtime_error(pcap_geterr(p_));
	p_list.push_many(ctx.p_list);
	p_list.total_pkts += dres;
}

void nettop::cap_mgr::async_cap(packet_list& p_list, volatile bool& quit) {
	while(!quit) {
		capture_dispatch(p_list);
	}
}
