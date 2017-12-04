/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pthread.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * Ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet/* lent */,
                     unsigned int len,
                     char *interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("----------------------------------------------------------\n");
    printf("*** -> Received packet of length %d \n", len);


    //print_hdrs(packet, len);


    /* fill in code here */

    if (ethertype_ip == ethertype(packet)) {
        handle_ip_packet(sr, packet, len, interface);
    } else if (ethertype_arp == ethertype(packet)) {
        handle_arp_packet(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */


void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */)
{
    if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "Error! Cannot process IP packet because it was not long enough.\n");
        return;
    }
    
    print_hdrs(packet, len);

    /* Get Source MAC/Ethernet Address and IP Address & put in cache */
    sr_ethernet_hdr_t *ethernet_header = extract_ethernet_header(packet);
    uint8_t *addr = ethernet_header->ether_shost;
    uint32_t ip_t = extract_ip_header(packet)->ip_src;
    printf(":: Placing Source's Ethernet(MAC) and IP Address in Cache...\n");
    sr_arpcache_insert( &(sr->cache), (unsigned char*)addr, ip_t);
    sr_arpcache_dump( &(sr->cache));

    sr_ip_hdr_t *original_ip_header = extract_ip_header(packet);
    /* Check IP Header cksum */
    uint16_t original_sum = original_ip_header->ip_sum;
    original_ip_header->ip_sum = 0;
    original_ip_header->ip_sum = cksum(original_ip_header, sizeof(sr_ip_hdr_t));
    if (original_ip_header->ip_sum != original_sum) {
        fprintf(stderr, "IP Header chksum failed\n");
        original_ip_header->ip_sum = original_sum;
        return;
    }
    /* Check if packet is destined for one of my interfaces */
    struct sr_if *destination_interface = get_interface_from_ip(sr, original_ip_header->ip_dst);
    printf("~~Destination_Interface: %s\n", destination_interface->name);
    if (destination_interface) {
      printf("We are the target -- discarding packet...\n");
    } else {  /* Packet was not for one of my interfaces */
        fprintf(stderr, "Received packet on interface [[%s]] that was not for me\n", interface);

	printf("== Sender IP %x | Dest IP %x\n", original_ip_header->ip_src, original_ip_header->ip_dst);

        /* Packet is not for this router and has valid TTL. Forward the packet. */
        fprintf(stderr, "Forwarding packet that was received on interface %s\n", interface);
        struct sr_rt *next_hop_ip = calculate_LPM(sr, original_ip_header->ip_dst);
	printf("-- Next Hop IP : %x\n", next_hop_ip->dest.s_addr);

	/* Take care of IP header misc fields */
        original_ip_header->ip_ttl--;
        original_ip_header->ip_sum = 0;
        original_ip_header->ip_sum = cksum(original_ip_header, sizeof(sr_ip_hdr_t));
	

	/* Check in ARP Cache */
	printf("##Looking-Up in ARP Cache where  <<%x>> is...\n", original_ip_header->ip_dst);
        struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), original_ip_header->ip_dst);
	/* Found MAC in ARP Cache  -- Send Packet */
        if (next_hop_mac) {
            fprintf(stderr, "ARP cache entry was found. Putting the packet on interface %s toward next hop.\n", next_hop_ip->interface);
	    sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(packet);
	    memcpy(send_ethernet_header->ether_shost, sr_get_interface(sr, next_hop_ip->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
	    memcpy(send_ethernet_header->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
	    free(next_hop_mac);
	    sr_send_packet(sr, packet, len, sr_get_interface(sr, next_hop_ip->interface)->name);
	    return;
        }
	else{
	  /* Send ARP Request*/
	  fprintf(stderr, "No ARP cache entry was found. Queuing an ARP request\n");
	  struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache), original_ip_header->ip_dst, packet, len, next_hop_ip->interface);
	  handle_arpreq(sr, queued_arp_req);
	  return;
	}
    }
}

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    if (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "Error! Cannot process ARP packet because it was not long enough.\n");
        return;
    }
    sr_arp_hdr_t *original_arp_header = extract_arp_header(packet);
    sr_ethernet_hdr_t *original_ethernet_header = extract_ethernet_header(packet);
    struct sr_if *receiving_interface = sr_get_interface(sr, interface);
    /*
     * GOT ARP REQUEST
     */
    if (arp_op_request == ntohs(original_arp_header->ar_op)) { /* ARP Request */
        /* Check if the request is for this interface */
        if (original_arp_header->ar_tip != receiving_interface->ip) {
            return;
        }
        fprintf(stderr, "Received ARP request on interface [[%s]]\n", interface);
        uint8_t *arp_reply = (uint8_t *) malloc(len);
        memset(arp_reply, 0, len * sizeof(uint8_t));
        sr_ethernet_hdr_t *reply_ethernet_header = extract_ethernet_header(arp_reply);
        sr_arp_hdr_t *reply_arp_header = extract_arp_header(arp_reply);
        /* Prepare ethernet header */
        memcpy(reply_ethernet_header->ether_shost, receiving_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(reply_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
        reply_ethernet_header->ether_type = htons(ethertype_arp);
        /* Prepare ARP header*/
        memcpy(reply_arp_header, original_arp_header, sizeof(sr_arp_hdr_t));
        reply_arp_header->ar_op = htons(arp_op_reply);
        memcpy(reply_arp_header->ar_tha, original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(reply_arp_header->ar_sha, receiving_interface->addr, ETHER_ADDR_LEN);
        reply_arp_header->ar_tip = original_arp_header->ar_sip;
        reply_arp_header->ar_sip = receiving_interface->ip;
	printf("Sending ARP reply [[%s]]...\n",interface);
        sr_send_packet(sr, arp_reply, len, interface);
        free(arp_reply);
    /*
     * GOT ARP REPLY
     */
    } else if (arp_op_reply == ntohs(original_arp_header->ar_op)) { /* ARP Reply */
        fprintf(stderr, "Received ARP reply on interface %s ... Caching ARP Reply\n", interface);
        struct sr_arpreq *cached_arp_request = sr_arpcache_insert( &(sr->cache), original_arp_header->ar_sha, original_arp_header->ar_sip);
	sr_arpcache_dump( &(sr->cache));
        if (cached_arp_request) {
            fprintf(stderr, "Sending packets that were waiting on ARP reply...\n");
            struct sr_packet *waiting_packet = cached_arp_request->packets;
            while (waiting_packet) { /* Send all packets waiting on this ARP request*/
                uint8_t *send_packet = waiting_packet->buf;
                sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(send_packet);
                memcpy(send_ethernet_header->ether_dhost, original_arp_header->ar_sha, ETHER_ADDR_LEN);
                memcpy(send_ethernet_header->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, send_packet, waiting_packet->len, interface);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), cached_arp_request);
        }
    }
    return;
}

struct sr_rt *calculate_LPM(struct sr_instance *sr, uint32_t destination_ip)
{
    struct sr_rt *routing_table_node = sr->routing_table;
    struct sr_rt *best_match = NULL;
    while (routing_table_node) {
        if ((routing_table_node->dest.s_addr & routing_table_node->mask.s_addr) == (destination_ip & routing_table_node->mask.s_addr)) {
            if (!best_match || (routing_table_node->mask.s_addr > best_match->mask.s_addr)) {
                best_match = routing_table_node;
            }
        }
        routing_table_node = routing_table_node->next;
    }
    return best_match;
}
