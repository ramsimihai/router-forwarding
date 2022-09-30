// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#ifndef _UTILS_H_
#define _UTILS_H_

#include "skel.h"

#define MASK_16   0XFFFF

// checks if the destination mac corresponds with the mac of the router
// from the interface from where the packete came or if it is the broadcast
// mac address
int check_destined_router(packet m, struct ether_header *eth_hdr);

// gets the arp entry from the arp table corresponding to the destination ip given
struct arp_entry *get_arp_entry(uint32_t dest_ip, struct arp_entry *arp_table, int arp_table_len);

// calculates checksum with formula from RFC 1624
// it is used a MASK_16 for the operations on TTL
uint16_t new_checksum(struct iphdr *ip_hdr);

#endif /* _UTILS_H_ */