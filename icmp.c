// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#include "icmp.h"

void completing_ip_hdr(struct iphdr *new_ip_hdr, struct iphdr *old_ip_hdr)
{
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->tos = 0;
	new_ip_hdr->protocol = IPPROTO_ICMP;
	new_ip_hdr->id = htons(1);
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->ttl = 64;
	new_ip_hdr->check = 0;
	new_ip_hdr->daddr = old_ip_hdr->saddr;
	new_ip_hdr->saddr = old_ip_hdr->daddr;
}

void send_icmp(struct iphdr *ip_hdr, uint8_t *mac_src, uint8_t *mac_dest, u_int8_t type, u_int8_t code, packet old_packet, struct icmphdr *old_icmp_hdr)
{
	struct ether_header eth_hdr;
	struct iphdr new_ip_hdr;

	packet packet;
	void *payload;

	// builds new ethernet header for the packet to be sent as an ICMP Echo Reply 
	build_ether_header(&eth_hdr, mac_src, mac_dest, ETHERTYPE_IP);

	// completing new ip header with basic information of the ip header specific for icmp
	completing_ip_hdr(&new_ip_hdr, ip_hdr);

	// updates total length and checksum in the new ip header
	new_ip_hdr.tot_len = ip_hdr->tot_len;
	new_ip_hdr.check = ip_checksum((uint8_t *)&new_ip_hdr, sizeof(struct iphdr));

	// iterates through the payload and copies new ethernet header and new ip header built
	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &new_ip_hdr, sizeof(struct iphdr));
	// copies old icmp header an the data from the old packet
	payload += sizeof(struct iphdr);
	memcpy(payload, (old_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr)), 64);

	// redefines old icmp header with the type and code for an ICMP Echo Reply
	struct icmphdr *new_icmp_hdr = payload;
	new_icmp_hdr->type = type;
	new_icmp_hdr->code = code;

	// calculates icmp sum of the new icmp header
	new_icmp_hdr->checksum = 0;
	new_icmp_hdr->checksum = icmp_checksum((uint16_t *) new_icmp_hdr, sizeof(struct icmphdr) + 56);

	// updates the packet length
	packet.len = old_packet.len;

	// sends the new packet out on the interface
	packet.interface = old_packet.interface;
	send_packet(&packet);
}

void send_icmp_error(struct iphdr *ip_hdr, uint8_t *mac_src, uint8_t *mac_dest, u_int8_t type, u_int8_t code, packet old_packet)
{
	struct ether_header eth_hdr;
	struct iphdr new_ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};

	packet packet;
	void *payload;
	
	// builds new ethernet header for the packet to be sent as an ICMP Echo Reply 
	build_ether_header(&eth_hdr, mac_src, mac_dest, ETHERTYPE_IP);

	// updates total length and checksum in the new ip header
	completing_ip_hdr(&new_ip_hdr, ip_hdr);

	// updates total length and checksum in the new ip header
	new_ip_hdr.tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
	new_ip_hdr.check = ip_checksum((void*) ip_hdr, sizeof(struct iphdr));
	
	// calculates icmp header checksum
	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	// iterates through the new packet and build it with the new headers
	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &new_ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	payload += sizeof(struct icmphdr);

	// copies all the data after the ip header from the old packet
	memcpy(payload, (old_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr)), 64);

	// redefines new packet length
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

	// sends the new packet out on the interface
	packet.interface = old_packet.interface;
	send_packet(&packet);
}
