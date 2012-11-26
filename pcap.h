#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <arpa/inet.h>

#define ERR_MALLOC -1
#define ERR_OPEN_FILE -2
#define TCP_TYPE 0
#define UDP_TYPE 1
#define SKIPPED_TYPE -1
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ERR_USAGE -1
#define ERR_OPEN_FILE -2
#define DATA_MAX 65535

struct iphdr {
  u_char          ip_vhl;	/* version << 4 | header length >> 2 */
  u_char          ip_tos;	/* type of service */
  u_short         ip_len;	/* total length */
  u_short         ip_id;	/* identification */
  u_short         ip_off;	/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char          ip_ttl;	/* time to live */
  u_char          ip_p;	/* protocol */
  u_short         ip_sum;	/* checksum */
  struct in_addr  ip_src, ip_dst;	/* source and dest address */
};

struct pseudohdr
{
  uint32_t ip_src;
  uint32_t ip_dst;
  uint8_t  type_protocole;
  uint16_t check_sum_read;
  uint16_t length;		//Longueur totale du datagramme - longueur de l'entête : packet[16] - (uint16_t)((packet[14]&0x0F)*4);
};

struct tcp_packet
{
  uint16_t port_src;
  uint16_t port_dst;
  uint16_t length;
  uint32_t seq_number;
  uint32_t ack_number;
  uint16_t flags;
  uint16_t window_size;
  uint16_t check_sum;
  uint16_t urgent_pointer;	//Si X1X XXXX dans flag
  uint32_t options;
  uint32_t data[DATA_MAX];
};

struct udp_packet
{
  uint16_t port_src;
  uint16_t port_dst;
  uint16_t length;	//length contenue dans le pseudo header
  uint16_t check_sum;
  uint32_t data[DATA_MAX];
};

//Message de début
void begin(void);
//Vérifie le bon usage du programme
void usage(int argc, char *argv[]);
//Lis et inscrit les informations à partir des paquets pour créer le pseudo header
void init_pseudo_header(const u_char *packet, struct pseudohdr *psd_hdr);
//Lis et inscrit les informations à partir des paquets pour créer le TCP packet
void init_tcp_packet(const u_char *packet, struct tcp_packet *tcp_pck);
//Lis et inscrit les informations à partir des paquets pour créer le UDP packet
void init_udp_packet(const u_char *packet, struct udp_packet *udp_pck);
//Inverse les octets récupérés
void reverse_add(uint32_t *addr);
//Affiche les informations du pseudo header
void print_psd_hdr(const struct pseudohdr *psd_hdr);
//Calcule le checksum d'un UDP packet et l'inscrit dans la struct udp_packet
void checksum_udp(const struct pseudohdr *psd_hdr, struct udp_packet *udp_pck);
//Calcule le checksum d'un TCP packet et l'inscrit dans la struct tcp_packet
void checksum_tcp(const struct pseudohdr *psd_hdr, struct tcp_packet *tcp_pck);
//Affiche les informations du UDP packet
void print_udp_packet(const struct pseudohdr *psd_hdr, struct udp_packet *udp_pck);
//Affiche les informations du TCP packet
void print_tcp_packet(const struct pseudohdr *psd_hdr, struct tcp_packet *tcp_pck);
//Affiche les data de TCP & UDP packet
void print_data(const uint32_t *data, const uint16_t length);
//Message de fin
void end(void);

#endif
