#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <arpa/inet.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

/*
 *Check if arp request needs to be deleted or resent
 */
void check_arp_requests(struct sr_instance *sr)
{
    struct sr_arpreq *request = (&(sr->cache))->requests;
    struct sr_arpreq *next_request;
    while (request) {
        next_request = request->next;
        handle_arpreq(sr, request);
        request = next_request;
    }
}


struct sr_arpentry *get_from_arpcache(struct sr_arpcache *cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* 
 * Adds an ARP request to the ARP request queue. 
 */
struct sr_arpreq *enqueue_to_arpcache(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* 
 * Inserts a new ARP cache entry (MAC + IP) if it's not 
 * already there.
 */
struct sr_arpreq *add_to_arpcache(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    /* Check if its already in Cache */
    struct sr_arpentry* find = NULL;
    if ( (find = get_from_arpcache(cache, ip)) != NULL){
      printf("MAC and IP are already in cache (not adding)\n");
      free(find);
      pthread_mutex_unlock(&(cache->lock));
      return NULL;
    }

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            } else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid)) {
            break;
        }
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* 
 * Deletes/Removes ARP cache entry
 */
void delete_from_arpcache(struct sr_arpcache *cache, struct sr_arpreq *entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf) {
                free(pkt->buf);
            }
            if (pkt->iface) {
                free(pkt->iface);
            }
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

void dump_arpcache(struct sr_arpcache *cache)
{
    fprintf(stderr, "\nMAC                 IP                       ADDED                      VALID\n");
    fprintf(stderr, "-------------------------------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
	struct in_addr ip_addr;
	ip_addr.s_addr = cur->ip;
        fprintf(stderr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x   %s (%.8x)   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], inet_ntoa(ip_addr), ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
	if ( cur->added == 0 )
	  break;
    }

    fprintf(stderr, "\n");
}

/* 
 * Initialize table and thread lock. Return 0 if successful
 */
int init_arpcache(struct sr_arpcache *cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* 
 * Destroys table + table lock. Returns 0 on success. 
 */ 
int delete_arpcache(struct sr_arpcache *cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* 
 * Deletes/Removes old arp cahce entries that are now expired 
 */
void *check_timeout_arpcache(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        check_arp_requests(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}

/*
 * Send ARP Request
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request)
{
    if (difftime(time(NULL), request->sent) >= 1.0) {
        struct sr_if *interface = sr_get_interface(sr, request->packets->iface);
        fprintf(stderr, "Sending ARP request through [[%s]]...\n",interface->name);
        int arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *new_arp_request_packet = (uint8_t *) malloc(arp_packet_len);
        memset(new_arp_request_packet, 0, sizeof(uint8_t) * arp_packet_len);
        sr_ethernet_hdr_t *outgoing_ethernet_header = extract_ethernet_header(new_arp_request_packet);
        sr_arp_hdr_t *outgoing_arp_header = extract_arp_header(new_arp_request_packet);
        /* Prepare ethernet header */
        memcpy(outgoing_ethernet_header->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memset(outgoing_ethernet_header->ether_dhost, 0xff, sizeof(uint8_t) * ETHER_ADDR_LEN); /* Broadcast */
        outgoing_ethernet_header->ether_type = htons(ethertype_arp);
        /* Prepare ARP header*/
        outgoing_arp_header->ar_op = htons(arp_op_request);
        memset(outgoing_arp_header->ar_tha, 0xff, ETHER_ADDR_LEN); /* Broadcast */
        memcpy(outgoing_arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
        outgoing_arp_header->ar_pln = sizeof(uint32_t);
        outgoing_arp_header->ar_hln = ETHER_ADDR_LEN;
        outgoing_arp_header->ar_pro = htons(ethertype_ip);
        outgoing_arp_header->ar_hrd = htons(arp_hrd_ethernet);
        outgoing_arp_header->ar_tip = request->ip;
        outgoing_arp_header->ar_sip = interface->ip;
        request->sent = time(NULL);
        request->times_sent++;
        sr_send_packet(sr, new_arp_request_packet, arp_packet_len, interface->name);
        free(new_arp_request_packet);
    }
    return;
}

