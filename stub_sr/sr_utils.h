#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t checksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

void print_hdrs(uint8_t *buf, uint32_t length);

sr_ethernet_hdr_t *extract_ethernet_header(uint8_t *);
sr_ip_hdr_t *extract_ip_header(uint8_t *);
sr_arp_hdr_t *extract_arp_header(uint8_t *);

#endif
