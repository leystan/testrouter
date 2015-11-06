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
#include <stdlib.h>
#include <string.h>


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

void sr_init(struct sr_instance* sr) 
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
 * ethernet headers.
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
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    sr_ethernet_hdr_t *eHeader = (sr_ethernet_hdr_t *) packet;

    uint16_t packageType = ntohs(eHeader->ether_type);

    /*Drop packet if its length is not large enough for an ethernet header*/
    if (len < sizeof(sr_ethernet_hdr_t)) {
        return;
    }
    
    /*Handle ARP packet*/
    if (packageType == ethertype_arp) {
        if (is_valid_arp_packet(packet, len)){
            handle_arp_packet(sr, packet, len, interface);
        }
    }
    /*Handle IP packet*/
    else if (packageType == ethertype_ip) {
        if (is_valid_ip_packet(packet, len)) {
            handle_ip_packet(sr, packet, len, interface);
        }
    }
    /*Ignore. Not an ARP or IP packet*/
    else {
        return;
    }
}/* end sr_ForwardPacket */

/*-----------------------------------------------------
 * Handle the ARP packet
 *-----------------------------------------------------*/
void handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char* interface)
{

    struct sr_arpentry *arp_entry;
    struct sr_arpreq *arp_request;
    struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *interface_rec = sr_get_interface(sr, interface);

    /*lookup entry in the cache*/
    arp_entry = sr_arpcache_lookup(&sr->cache, arpHeader->ar_sip);

    /*This ARP entry already exists. The entry must be freed*/
    if (arp_entry != 0) {
        free(arp_entry);
    }
    /*This ARP entry does not exist*/
    else {
    
        arp_request = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);

        /*send packets that are waiting on this ARP request*/
        if (arp_request != 0) {
            struct sr_packet *packet = arp_request->packets;

            while (packet != 0) {
                struct sr_ip_hdr *ipHeader = (sr_ip_hdr_t *) packet->buf;
                
                sr_add_ethernet_header(sr, packet->buf, packet->len, ipHeader->ip_dst, htons(ethertype_ip));
                packet = packet->next;
            }
            sr_arpreq_destroy(&sr->cache, arp_request);
        }
    }

    uint16_t opcode = ntohs(arpHeader->ar_op);

    /*check if it is a request*/
    if (opcode == arp_op_request) {
        handle_arp_request(sr, arpHeader, interface_rec);
    }
}

/*--------------------------------------------
 * create the arp reply then send it
 *-------------------------------------------*/

void handle_arp_request(struct sr_instance *sr,
        struct sr_arp_hdr *arpHeader,
        struct sr_if *interface_rec)
{
    /*Create a new ARP header for reply*/
    struct sr_arp_hdr arpHeader_reply;

    /*initialize the ARP header*/
    arpHeader_reply.ar_hrd = htons(arp_hrd_ethernet);
    arpHeader_reply.ar_pro = htons(ethertype_ip);
    arpHeader_reply.ar_hln = ETHER_ADDR_LEN;
    arpHeader_reply.ar_pln = sizeof(uint32_t);
    arpHeader_reply.ar_op = htons(arp_op_reply);
    memcpy(arpHeader_reply.ar_sha, interface_rec->addr, ETHER_ADDR_LEN);
    arpHeader_reply.ar_sip = interface_rec->ip;
    memcpy(arpHeader_reply.ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
    arpHeader_reply.ar_tip = arpHeader->ar_sip;

    /*send the ARP header*/
    sr_add_ethernet_header(sr,
            (uint8_t *) &arpHeader_reply,
            sizeof(sr_arp_hdr_t),
            arpHeader->ar_sip,
            htons(ethertype_arp));
}

void handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface)
{
    struct sr_if* interface_rec;
    struct sr_ip_hdr *ipHeader;
    
    ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
    interface_rec = sr_get_interface(sr, interface);
    
    if (ipHeader->ip_dst != interface_rec->ip) {
        sr_route_packet(sr, packet, interface_rec);
    }
    else {
        if (ipHeader->ip_p == ip_protocol_icmp) {
            struct sr_icmp_hdr *icmpHeader;
            icmpHeader = (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmpHeader->icmp_type != icmp_echo_request) {
                return;
            }
            
            /*check to see if the icmp checksum is correct*/
            uint16_t curr_cksum = icmpHeader->icmp_sum;
            icmpHeader->icmp_sum = 0;
            int ip_len = ntohs(ipHeader->ip_len) - ipHeader->ip_hl * 4;
            uint16_t new_cksum = cksum((uint8_t *) icmpHeader, ip_len);
            if (curr_cksum != new_cksum) {
                return;
            }
            sr_send_icmp(sr, (uint8_t *) ipHeader, icmp_echo_reply, 0);
        }
        /*port is not reachable*/
        else {
            printf("the port is not reachable");
        }
    }
}

void sr_route_packet(struct sr_instance *sr,
        uint8_t *packet,
        struct sr_if *interface)
{
    struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
    
    /*decrement the ttl*/
    uint8_t ttl = ipHeader->ip_ttl;
    ttl--;
    
    /*the icmp time to live has been exeeded -- send time exceeded*/
    if (ttl == 0) {
        sr_send_icmp(sr, (uint8_t *) ipHeader, icmp_time_exceeded, 0);
        return;
    }
    
    unsigned int len = ntohs(ipHeader->ip_len);
    
    /*recalculate the checksums*/
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl * 4);
    
    /*create a new packet*/

    uint8_t *new_packet = malloc(len);
    memcpy(new_packet, ipHeader, len);
    
    sr_add_ethernet_header(sr, new_packet, len, ipHeader->ip_dst, htons(ethertype_ip));
    
    /*clean up*/
    free(new_packet);
}

void sr_send_icmp(struct sr_instance *sr,
        uint8_t *packet,
        uint8_t type,
        uint8_t code)
{
    if (type == icmp_unreachable){
       
    }
    
    else if (type == icmp_time_exceeded) {
        struct sr_ip_hdr *ipHeader = (sr_ip_hdr_t *) packet;
        
        /*get the interface entry*/
        struct sr_rt *entry = sr_get_longest_match(sr, ipHeader->ip_src);
        
        /*check if there is an entry*/
        if (entry == 0) {
            /*drop packet -- don't know where to send*/
            return;
        }
        
        struct sr_if *interface_rec = sr_get_interface(sr, entry->interface);
        
        sr_create_icmp_t3(sr, (struct sr_ip_hdr *) packet, type, code, interface_rec);
    }
    
    else if (type == icmp_echo_reply) {
        sr_create_icmp(sr, (struct sr_ip_hdr *) packet, type, code);
    }
} 

void sr_create_icmp(struct sr_instance *sr,
        struct sr_ip_hdr *packet,
        uint8_t type,
        uint8_t code)
{
    struct sr_ip_hdr *ipHeader = packet;
    struct sr_icmp_hdr *icmpHeader = (sr_icmp_hdr_t *)((uint8_t *)(ipHeader) + (ipHeader->ip_hl *4));
    
    /*initialize icmp header*/
    icmpHeader->icmp_type = type;
    icmpHeader->icmp_code = code;
    /*calculate the checksum*/
    icmpHeader->icmp_sum = 0;
    uint16_t new_cksum = cksum((uint8_t *) icmpHeader, ntohs(ipHeader->ip_len) - ipHeader->ip_hl *4);
    icmpHeader->icmp_sum = new_cksum;

    /*initialize ip header*/
    uint32_t dest = ipHeader->ip_src;
    ipHeader->ip_src = ipHeader->ip_dst;
    ipHeader->ip_dst = dest;
    /*calculate the checksum*/
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl * 4);

    unsigned int len = ntohs(ipHeader->ip_len);
    uint8_t *new_packet = malloc(len);
    memcpy(new_packet, ipHeader, len);

    sr_add_ethernet_header(sr, new_packet, len, dest, htons(ethertype_ip));

    /*clean up*/
    free(new_packet);
}

/*
 *
 */
void sr_create_icmp_t3(struct sr_instance *sr,
        struct sr_ip_hdr *packet,
        uint8_t type,
        uint8_t code,
        struct sr_if *interface)
{
    struct sr_icmp_t3_hdr *icmpHeader;
    struct sr_ip_hdr *ipHeader;

    unsigned int len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    uint8_t *new_packet = malloc(len);
    icmpHeader = (sr_icmp_t3_hdr_t *) ((uint8_t *) new_packet + sizeof(sr_ip_hdr_t));
    ipHeader = (sr_ip_hdr_t *) new_packet;

    icmpHeader->icmp_type = type;
    icmpHeader->icmp_code = code;
    icmpHeader->icmp_sum = 0;
    memcpy((uint8_t *) icmpHeader + sizeof(sr_icmp_t3_hdr_t) - ICMP_DATA_SIZE, packet, ICMP_DATA_SIZE);

    /*initialize ip header*/
    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_id = packet->ip_id;
    ipHeader->ip_off = htons(IP_DF);
    ipHeader->ip_ttl = TTL_DEF;
    ipHeader->ip_p = ip_protocol_icmp;
    ipHeader->ip_dst = packet->ip_src;
    ipHeader->ip_src = interface->ip;
    ipHeader->ip_sum = 0;
    ipHeader->ip_len = htons(len);
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    icmpHeader->icmp_sum = cksum(new_packet + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_t3_hdr_t));

    sr_add_ethernet_header(sr, new_packet, len, ipHeader->ip_dst, htons(ethertype_ip));

    /*clean up*/
    free(new_packet);
}

void sr_add_ethernet_header(struct sr_instance* sr,
        uint8_t *packet,
        unsigned int len,
        uint32_t dest_ip,
        uint16_t type)
{
    struct sr_rt *entry = sr_get_longest_match(sr, dest_ip);
    
    /*check if there is no entry with the longest prefix match*/
    if (entry == 0) {
        sr_send_icmp(sr, packet, icmp_unreachable, icmp_port_unreachable);
        return;
    }
    
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, entry->gw.s_addr);
    
    if(arp_entry != 0) {
        unsigned int packet_len = len + sizeof(sr_ethernet_hdr_t);
        uint8_t *new_packet = malloc(packet_len);
        struct sr_ethernet_hdr *eHeader = malloc(sizeof(sr_ethernet_hdr_t));
        struct sr_if *interface_rec = sr_get_interface(sr, entry->interface);
        
        /*initialize ethernet header*/
        eHeader->ether_type = type;
        memcpy(eHeader->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eHeader->ether_shost, interface_rec->addr, ETHER_ADDR_LEN);
        
        /*initialize the new packet*/
        memcpy(new_packet, eHeader, sizeof(sr_ethernet_hdr_t));
        memcpy(new_packet + sizeof(sr_ethernet_hdr_t), packet, len);
        
        sr_send_packet(sr, new_packet, len + sizeof(struct sr_ethernet_hdr), entry->interface);
        
        /*clean up*/
        free(new_packet);
        free(eHeader);
        if (arp_entry != 0) {
            free(arp_entry);
        }
    }    
    /*add to the request queue*/   
    else {
        sr_arpcache_queuereq(&sr->cache, entry->gw.s_addr, packet, len, entry->interface);
    }  
}

void sr_broadcast_arp(struct sr_instance *sr,
        struct sr_arp_hdr arpHeader,
        struct sr_if *interface)
{
    struct sr_rt *entry = sr_get_longest_match(sr, arpHeader.ar_tip);
    /*drop the packet if the entry is not there*/
    if(entry == 0) {
        return;
    }
    /*new packet*/
    uint8_t *packet;
    
    /*initialize the packet*/
    struct sr_ethernet_hdr eHeader;
    unsigned int len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    eHeader.ether_type = htons(ethertype_arp);
    memset(eHeader.ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eHeader.ether_shost, interface->addr, ETHER_ADDR_LEN);
    
    packet = malloc(len);
    memcpy(packet, &eHeader, sizeof(sr_ethernet_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t), &arpHeader, sizeof(sr_arp_hdr_t));
    
    sr_send_packet(sr, packet, len, entry->interface);
    
    /*clean up*/
    free(packet);
}

