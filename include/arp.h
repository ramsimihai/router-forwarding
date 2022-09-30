// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#ifndef _ARP_H_
#define _ARP_H_

#include "skel.h"

// sending an arp request to the interface of the next hop to get the mac of the
// next hop
void arp_request(packet *m, uint8_t *router_mac, struct route_table_entry *next);

// sending an arp reply with the mac of the router to the interface from where
// the packet came from
void arp_reply(struct arp_header *arp_hdr, packet m);

// completing an arp header with the specified arguments then creating a new
// packet which is going to be sent on the interface given
void send_arp(struct ether_header *eth_hdr, uint32_t ip_dest, uint32_t ip_src,
              int interface, uint16_t arp_op);

#endif /* _ARP_H_ */