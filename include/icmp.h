// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#ifndef _ICMP_H_
#define _ICMP_H_

#include "skel.h"

// send an ICMP packet by building a new ethernet header, ip header
// into the packet, then copying old icmp header from the old
// packet and redefining it as an ICMP Echo Reply
void send_icmp(struct iphdr *ip_hdr, uint8_t *mac_src, uint8_t *mac_dest,
              u_int8_t type, u_int8_t code, packet old_packet,
              struct icmphdr *old_icmp_hdr);

// send an ICMP packet by building a new ethernet header, ip header
// and icmp header into the Packet, then copying the data from
// the old packet and redefining it as an ICMP Network Unreach
// or ICMP Time Exceeded
void send_icmp_error(struct iphdr *ip_hdr, uint8_t *mac_src, uint8_t *mac_dest,
            u_int8_t type, u_int8_t code, packet old_packet);

// complete ip header of with basic specification of a icmp header
void completing_ip_hdr(struct iphdr *new_ip_hdr, struct iphdr *old_ip_hdr);

#endif /* _ICMP_H_ */