// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#include "utils.h"

int check_destined_router(packet m, struct ether_header *eth_hdr)
{
	uint8_t *router_mac = malloc(sizeof(router_mac));
	DIE(NULL == router_mac, "Allocation of a new router_mac failed");
	// get the interface from where the packet came
	get_interface_mac(m.interface, router_mac);

	// check if the packet is destined for router
	int counter = 0;
	for (int i = 0; i < 6; i++)
		if (router_mac[i] == eth_hdr->ether_dhost[i])
			counter++;
	
	// check if the packet is a broadcast message
	if (counter != 6) {
		counter = 0;

		for (int i = 0; i < 6; i++)
			if (eth_hdr->ether_dhost[i] == 0xFF)
				counter++;
		if (counter != 6) {
			return -1;
		}
	}

	return 1;
}

struct arp_entry *get_arp_entry(uint32_t dest_ip, struct arp_entry *arp_table, int arp_table_len)
{
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == dest_ip)
			return &arp_table[i];

	return NULL;
}

uint16_t new_checksum(struct iphdr *ip_hdr)
{
	uint16_t old_checksum = ip_hdr->check;

	// cast from uint8_t to uint16_t
	uint16_t old_value_ttl = (ip_hdr->ttl & MASK_16);
	uint16_t new_value_ttl = ((ip_hdr->ttl - 1) & MASK_16);

	// RFC 1624 equation no4
	uint16_t new_checksum = old_checksum - ~old_value_ttl - new_value_ttl - 1;

	return new_checksum;
}
