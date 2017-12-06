
#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define SR_ARPCACHE_SZ    100
#define SR_ARPCACHE_TO    15.0

struct sr_packet {
    uint8_t *buf;               
    unsigned int len;           
    char *iface;                
    struct sr_packet *next;
};

struct sr_arpentry {
    unsigned char mac[6];
    uint32_t ip;                
    time_t added;
    int valid;
};

struct sr_arpreq {
    uint32_t ip;
    time_t sent;                
    uint32_t times_sent;        
    struct sr_packet *packets;  
    struct sr_arpreq *next;
};

struct sr_arpcache {
    struct sr_arpentry entries[SR_ARPCACHE_SZ];
    struct sr_arpreq *requests;
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
};

struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip);

struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,        
                                       unsigned int packet_len,
                                       char *iface);

struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip);

void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry);

void sr_arpcache_dump(struct sr_arpcache *cache);

int   sr_arpcache_init(struct sr_arpcache *cache);
int   sr_arpcache_destroy(struct sr_arpcache *cache);
void *sr_arpcache_timeout(void *cache_ptr);
void handle_arpreq(struct sr_instance *, struct sr_arpreq *);
void sr_arpreq_destroy_no_lock(struct sr_arpcache *, struct sr_arpreq *);

/* sr_utils.h */
sr_arp_hdr_t *extract_arp_header(uint8_t *);
sr_ethernet_hdr_t *extract_ethernet_header(uint8_t *);

/* sr_router.h */
struct sr_rt *calculate_LPM(struct sr_instance *, uint32_t);

/* sr_if.h */
struct sr_if *sr_get_interface(struct sr_instance *, const char *);
struct sr_if *get_interface_from_ip(struct sr_instance *, uint32_t);
struct sr_if *get_interface_from_eth(struct sr_instance *, uint8_t *);

#endif
