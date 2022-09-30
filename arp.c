// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#include "skel.h"
#include "arp.h"

void arp_request(packet *m, uint8_t *router_mac, struct route_table_entry *next)
{
	// creating a new ether header for an ARP REQUEST
	struct ether_header *new_eth_hdr = malloc(sizeof(struct ether_header));
	DIE(NULL == new_eth_hdr, "Allocation of a new ether header failed");
	
	// mac_dest will be the broadcast mac address
	uint8_t mac_dest[ETH_ALEN];
	memset(mac_dest, 0xFF, ETH_ALEN);

	// completing the ether header with router mac from the next hop interface
	// and the broadcast mac address
	build_ether_header(new_eth_hdr, router_mac, mac_dest, ETHERTYPE_ARP);

	// sending an arp message
	send_arp(new_eth_hdr, next->next_hop,
			inet_addr(get_interface_ip(next->interface)),
			next->interface, htons(ARPOP_REQUEST));
}

void arp_reply(struct arp_header *arp_hdr, packet m)
{
	// creating a new ether header for an ARP REQUEST
	struct ether_header *new_eth_hdr = malloc(sizeof(struct ether_header));
	DIE(NULL == new_eth_hdr, "Allocation of a new ether header failed");

	// extracting mac address of the router interface
	uint8_t router_mac[ETH_ALEN];
	get_interface_mac(m.interface, router_mac);

	// completing the ether header with router mac from the interface of the
	// incoming packet and the source mac address from the arp header
	build_ether_header(new_eth_hdr, router_mac, arp_hdr->sha, ETHERTYPE_ARP);

	// sending an arp message
	send_arp(new_eth_hdr, arp_hdr->spa,
			arp_hdr->tpa,
			m.interface, htons(ARPOP_REPLY));
}

void send_arp(struct ether_header *eth_hdr, uint32_t ip_dest,
             uint32_t ip_src, int interface, uint16_t arp_op)
{
	struct arp_header arp_hdr;
    
    // sets fields of the new arp header
	arp_hdr.hlen = ETH_ALEN;
	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.plen = 4;
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.op = arp_op;

    // sets mac_src, mac_dest & ip_src, ip_dest of the new arp header
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, ETH_ALEN); 
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, ETH_ALEN);
	arp_hdr.spa = ip_src;
	arp_hdr.tpa = ip_dest;

    // building a new packet with the old ether header and the new arp header
	packet new_packet;
	memcpy(new_packet.payload, eth_hdr, sizeof(struct ether_header));
	memcpy(new_packet.payload + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

    // updating the size of the packet
	new_packet.len = sizeof(struct arp_header) + sizeof(struct ether_header);

    // changes the interface of where the packet should be sent and send the packet
	new_packet.interface = interface;
	send_packet(&new_packet);

	free(eth_hdr);
}