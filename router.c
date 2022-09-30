// Copyright 2021-2022 -- Mihai Daniel Soare -- Grupa 321CA
#include "queue.h"
#include "skel.h"
#include "icmp.h"
#include "arp.h"
#include "utils.h"

// routing table
struct route_table_entry *rtable;
// routing table length
int rtable_len;


// ARP table
struct arp_entry *arp_table;
// ARP table length
int arp_table_len;

// get the front element of a given queue as parameter
void *front(queue q);

// create a copy of the old packet and adds it into a queue where is going
// to be stored until the destination mac would be known
void enqueue_packets(queue *queue_packets, packet *m, int *queue_size);

// iterate through the queue of the packets and sends all the packets destined
// for the mac_dest given as a parameter
void dequeue_packets(queue *queue_packets, struct arp_entry *entry, int interface, int *queue_size);

// comparator for sorting routing table by mask then by prefix
int comp(const void *a, const void *b);

// return the next hop of the given destination ip in the routing table
// by using binary search
struct route_table_entry *get_best_route_rec(uint32_t dest_ip, int left, int right);

// add a new arp table entry in the old routing table if the given entry
// isnt already in the arp table
void update_arp_table(struct arp_entry new_entry);

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// allocs a new route table
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "routing table couldnt be allocated");

	// reads the routing table from the file and sorts it
	rtable_len = read_rtable(argv[1], rtable);
	qsort((void*)rtable, rtable_len, sizeof(struct route_table_entry), comp);

	// allocs a new arp table
	arp_table = malloc(sizeof(struct arp_entry) * 10000);
	DIE(rtable == NULL, "arp table couldnt be allocated");

	// creates a new queue for the packets which are going to be stored for
	// sending
	queue queue_packets = queue_create();
	int queue_size = 0;
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "Couldn't get a packet from the wire");

		// parses headers
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct arp_header *arp_hdr = parse_arp(m.payload);
		struct icmphdr *icmp_header = parse_icmp(m.payload);

		// checks if the packet is destined for the router or is a broadcast
		// otherwise drop the packet
		if (check_destined_router(m, eth_hdr) != 1)
			continue;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				// extracts destination ip and destination mac from arp header
				uint32_t dest_ip = arp_hdr->spa;
				uint8_t mac_dest[ETH_ALEN];

				memcpy(mac_dest, arp_hdr->sha, ETH_ALEN);

				// allocs memory for new entry in ARP Table
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				DIE(NULL == new_entry, "Allocation of new entry in arp table failed.");

				memcpy(&new_entry->ip, &dest_ip, sizeof(dest_ip));
				memcpy(&new_entry->mac, &mac_dest, sizeof(mac_dest));

				// update the arp table with the new entry
				update_arp_table(*new_entry);

				// dequeue packets that are destined for the ARP Request's sender
				dequeue_packets(&queue_packets, new_entry, m.interface, &queue_size);
			} else if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				// gets an ARP REQUEST so sending back an ARP REPLY
				arp_reply(arp_hdr, m);
			}
	    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			// parses ip header
			struct iphdr *ip_hdr = (struct iphdr *)((void *)eth_hdr + sizeof(struct ether_header));

			// checksum doesnt correspond
			if (ip_checksum((void*) ip_hdr, sizeof(struct iphdr)) != 0) {
				continue;
			}

			// check TTL > 1
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m);
				continue;
			}

			// the packet is destined for router so send an icmp echo reply back
			if (((inet_addr(get_interface_ip(m.interface))) == ip_hdr->daddr) && (icmp_header->type == ICMP_ECHO)) {
				send_icmp(ip_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m, icmp_header);
				continue;
			}

			// calculates the next hop of the packet
			struct in_addr dest_ip;
			dest_ip.s_addr = ip_hdr->daddr;
			struct route_table_entry *next = get_best_route_rec(dest_ip.s_addr, 0, rtable_len - 1);

			// if the next hop doesnt exist in the routing table then drops the packet
			if (next == NULL) {
				send_icmp_error(ip_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_DEST_UNREACH, 0, m);
				continue;
			}

			// calculates new ttl and checksum with RFC 1624 method (eqn ~4)
			ip_hdr->check = new_checksum(ip_hdr);
			ip_hdr->ttl = ip_hdr->ttl - 1;

			uint8_t *router_mac = malloc(sizeof(router_mac));
			DIE(NULL == router_mac, "Allocation of a new router mac failed");
				
			// get the interface to where the packet should be sent
			get_interface_mac(next->interface, router_mac);

			// search for arp entry
			struct arp_entry *next_mac = get_arp_entry(next->next_hop, arp_table, arp_table_len);
			if (next_mac == NULL) {
				// puts the packet in queue
				enqueue_packets(&queue_packets, &m, &queue_size);
				
				// makes an ARP_REQ to get the mac of the next hop for the last sent packet
				// to the router
				arp_request(&m, router_mac, next);
				
				// gets to next packet and waits to get an ARP REPLY with the wanted mac
				continue;
			}

			// fills the fields of the ether header of the message to send it
			memcpy(eth_hdr->ether_shost, router_mac, 6);
			memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);
			m.interface = next->interface;

			send_packet(&m);
		}
	}
}

int comp(const void *a, const void *b)
{
	if (((*(struct route_table_entry *)a).mask  & (*(struct route_table_entry *)a).prefix) == 
		((*(struct route_table_entry *)b).mask & (*(struct route_table_entry *)b).prefix))
		return ntohl((*(struct route_table_entry *)a).mask) - ntohl((*(struct route_table_entry *)b).mask);
	else
		return ntohl((*(struct route_table_entry *)a).mask  & (*(struct route_table_entry *)a).prefix)
					 - ntohl(((*(struct route_table_entry *)b).mask & (*(struct route_table_entry *)b).prefix));
}

struct route_table_entry *get_best_route_rec(uint32_t dest_ip, int left, int right)
{
	if (right < left)
		return NULL;

	int mid = left + (right - left) / 2;

    if ((rtable[mid].prefix & rtable[mid].mask) == (rtable[mid].mask & dest_ip)) {
		struct route_table_entry *curr_best = &rtable[mid];
		struct route_table_entry *new_best = get_best_route_rec(dest_ip, mid + 1, right);
		return (NULL == new_best ||  ntohl(curr_best->mask) >= ntohl(new_best->mask)) ? curr_best : new_best; 
	}

	if ((ntohl(rtable[mid].prefix) & ntohl(rtable[mid].mask)) < (ntohl(rtable[mid].mask) & ntohl(dest_ip))) {
			// best match is in the right half.
			return get_best_route_rec(dest_ip, mid + 1, right);
	}

	return get_best_route_rec(dest_ip, left, mid - 1);
}

void enqueue_packets(queue *queue_packets, packet *m, int *queue_size)
{
	packet *copy_of_m = malloc(sizeof(*m));
	DIE (NULL == copy_of_m, "copy of message allocation failed");

	memcpy(copy_of_m, m, sizeof(*m));

	queue_enq(*queue_packets, copy_of_m);

	*queue_size = *queue_size + 1;
}

void dequeue_packets(queue *queue_packets, struct arp_entry *entry, int interface, int *queue_size)
{
	for (int i = 0; i < *queue_size; i++) {
		// gets the packet from the queue
		packet *found_packet = (packet *) queue_deq(*queue_packets);

		// parses ethernet and ip header from the packet which is going to be sent
		struct ether_header *eth_hdr;
		eth_hdr = (struct ether_header *)(*found_packet).payload;

		struct iphdr *curr_pack_ip_hdr = (struct iphdr *)((*found_packet).payload 
											+ sizeof(struct ether_header));

		// gets next hop of the packet
		struct in_addr dest_ip;
		dest_ip.s_addr = curr_pack_ip_hdr->daddr;
		struct route_table_entry *next = get_best_route_rec(dest_ip.s_addr, 0, rtable_len - 1);

		// checks if the next hop mac address is actually gotten from the new arp entry
		if (next->next_hop != entry->ip) {
			queue_enq(*queue_packets, found_packet);
			continue;
		}

		*queue_size = *queue_size - 1;

		// completes ethernet header with mac src as the router mac on
		// the interface and the mac dest as the next hop mac 
		get_interface_mac(interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, entry->mac, 6);

		// sends the packet out on the right interface
		found_packet->interface = next->interface;
		send_packet(found_packet);

		free(found_packet);
	}
}

void update_arp_table(struct arp_entry new_entry)
{
	int ok = 1;

	// iterates through the arp table
	for (int i = 0; i < arp_table_len; i++) {
		if (new_entry.ip == arp_table[i].ip && new_entry.mac == arp_table[i].mac) {
			ok = 0;
			break;
		}
	}

	// adds the entry in the arp table
	if (ok == 1) {
		arp_table[arp_table_len] = new_entry;
		arp_table_len++;
	}
}
