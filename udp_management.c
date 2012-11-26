#include "pcap.h"

void init_udp_packet(const u_char *packet, struct udp_packet *udp_pck)
{
  udp_pck->port_src = (packet[34]<<8) | packet[35];
  udp_pck->port_dst = (packet[36]<<8) | packet[37];
  udp_pck->check_sum = 0;
  udp_pck->length = ((packet[16]<<8) | packet[17])-((packet[14]&0x0F)*4)-8;
  for(int i = 0; i < udp_pck->length; i++)
    udp_pck->data[i] = packet[42+i];
}

void print_udp_packet(const struct pseudohdr *psd_hdr, struct udp_packet *udp_pck)
{
  if(udp_pck->check_sum == 0)
    checksum_udp(psd_hdr, udp_pck);
  const uint32_t *data = udp_pck->data;
  printf("Source port :\t\t%d\n", udp_pck->port_src);
  printf("Destination port :\t%d\n", udp_pck->port_dst);
  printf("Checksum read :\t\t0x%04X\n", psd_hdr->check_sum_read);
  printf("Checksum calc :\t\t0x%04X\n", udp_pck->check_sum);
  printf("Length UDP :\t\t%d\n", udp_pck->length);
  print_data(udp_pck->data, udp_pck->length);
  putchar('\n');
}

void checksum_udp(const struct pseudohdr *psd_hdr, struct udp_packet *udp_pck)
{
  if(udp_pck->check_sum != 0)//si déjà calculé, on saute la fonction
    return;
  uint16_t padd = 0;
  uint32_t word32 = 0;
  uint32_t sum = 0;
  int i = 0;

  // Find out if the length of data is even or odd number. If odd,
  // add a padding byte = 0 at the end of packet
  if ((psd_hdr->length % 2) == 1)
  {
    padd = 1;
    udp_pck->data[udp_pck->length] = 0;
  }
  word32 = (((psd_hdr->ip_src & 0xFFFF0000)>>16) + (psd_hdr->ip_src & 0xFFFF));
  sum += word32;
  word32 = (((psd_hdr->ip_dst & 0xFFFF0000)>>16) + (psd_hdr->ip_dst & 0xFFFF));
  sum += word32;

  // the protocol number and the length of the UDP packet
  sum += psd_hdr->type_protocole + psd_hdr->length;
  sum += udp_pck->port_src + udp_pck->port_dst + udp_pck->length;

  // make 16 bit words out of every two adjacent 8 bit words and 
  // calculate the sum of all 16 bit words
  for (i = 0, word32 = 0; i < udp_pck->length + padd; i += 2)
  {
    word32 = ((udp_pck->data[i]<<8) & 0xFF00) + (udp_pck->data[i+1] & 0xFF);
    sum += (uint32_t)word32;
  }
  // keep only the last 16 bits of the 32 bit calculated sum and add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  // Take the one's complement of sum
  udp_pck->check_sum = (~sum-8);
}