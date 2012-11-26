#include "pcap.h"

void init_tcp_packet(const u_char *packet, struct tcp_packet *tcp_pck)
{
  tcp_pck->port_dst = (packet[36]<<8) | packet[37];
  tcp_pck->port_src = (packet[34]<<8) | packet[35];
  tcp_pck->seq_number = (packet[38]<<24) | packet[39]<<16 | packet[40]<<8 | packet[41];
  tcp_pck->flags = (packet[46]<<8) | packet[47];
  if(tcp_pck->flags & 0x10) //Option ack_number
    tcp_pck->ack_number = (packet[42]<<24) | packet[43]<<16 | packet[44]<<8 | packet[45];
  if(tcp_pck->flags & 0x40) //Option urgent_pointer
    tcp_pck->urgent_pointer = 1;
  tcp_pck->window_size = (packet[48]<<8) | packet[49];
  tcp_pck->options = 0;
  tcp_pck->check_sum = 0;
  tcp_pck->length = ((packet[16]<<8) | packet[17])-((packet[14]&0x0F)*4);
  for(int i = 0; i < tcp_pck->length; i++)
    tcp_pck->data[i] = packet[42+i];
}

void print_tcp_packet(const struct pseudohdr *psd_hdr, struct tcp_packet *tcp_pck)
{
  if(tcp_pck->check_sum == 0)
    checksum_tcp(psd_hdr, tcp_pck);
  const uint32_t *data = tcp_pck->data;
  printf("Source port :\t\t%d\n", tcp_pck->port_src);
  printf("Destination port :\t%d\n", tcp_pck->port_dst);
  printf("Seq number :\t\t0X%08X\n", tcp_pck->seq_number);
  printf("Ack number :\t\t0X%08X\n", tcp_pck->ack_number);
  printf("Flag :\t\t\t0X%04X\n", tcp_pck->flags);
  printf("Window :\t\t0X%04X\n", tcp_pck->window_size);
  printf("Checksum read :\t\t0x%04X\n", psd_hdr->check_sum_read);
  printf("Checksum calc :\t\t0x%04X\n", tcp_pck->check_sum);
  printf("Length TCP :\t\t%d\n", tcp_pck->length);
  print_data(tcp_pck->data, tcp_pck->length);
  putchar('\n');
}

void checksum_tcp(const struct pseudohdr *psd_hdr, struct tcp_packet *tcp_pck)
{
  if(tcp_pck->check_sum != 0)//si déjà calculé, on saute la fonction
    return;
  //Non implémentée
}