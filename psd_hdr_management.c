#include "pcap.h"

void init_pseudo_header(const u_char *packet, struct pseudohdr *psd_hdr)
{
  //Verification du protocole. On *return*
  //si protocole différent de TCP ou UDP
  psd_hdr->type_protocole = packet[23];
  if( !(psd_hdr->type_protocole == 0x06) && !(psd_hdr->type_protocole == 0x11) )
  {
    printf("Ethernet type skipped : 0x%02X\n", psd_hdr->type_protocole);
    return;
  }

  const struct iphdr *ip_header = (struct iphdr *) (packet + 14);
  if( (ip_header == NULL))
  {
    fprintf(stderr,"init_pseudo_header aborted. Cause : error malloc.\n");
    return;
  }

  if(psd_hdr->type_protocole == 0x06) //TCP protocol
    psd_hdr->check_sum_read = (packet[50]<<8) | packet[51];
  else
    psd_hdr->check_sum_read = (packet[40]<<8) | packet[41];
  //Calcul de la taille UDP
  psd_hdr->length = packet[39];
  //Lecture de l'adresse ip emettrice
  psd_hdr->ip_src = ip_header->ip_src.s_addr;
  reverse_add(&psd_hdr->ip_src);
  //Lecture de l'adresse ip receptrice
  psd_hdr->ip_dst = ip_header->ip_dst.s_addr;
  reverse_add(&psd_hdr->ip_dst);
  //affichage des informations
//   print_psd_hdr(psd_hdr->ip_src, psd_hdr->ip_dst, psd_hdr->type_protocole, check_sum, psd_hdr->length);
}

void print_psd_hdr(const struct pseudohdr *psd_hdr)
{
    printf("Source address :\t%d.%d.%d.%d\t[0x%08X]\n",
	 (((psd_hdr->ip_src) & (0xFF000000))>>24),
	 (((psd_hdr->ip_src) & (0x00FF0000))>>16),
	 (((psd_hdr->ip_src) & (0x0000FF00))>>8),
	  ((psd_hdr->ip_src) & (0x000000FF)),
	    psd_hdr->ip_src);
  printf("Destination address :\t%d.%d.%d.%d\t[0x%08X]\n",
	 (((psd_hdr->ip_dst) & (0xFF000000))>>24),
	 (((psd_hdr->ip_dst) & (0x00FF0000))>>16),
	 (((psd_hdr->ip_dst) & (0x0000FF00))>>8),
	  ((psd_hdr->ip_dst) & (0x000000FF)),
	    psd_hdr->ip_dst);
  printf("Ethernet type :\t\t0x%02X\n", psd_hdr->type_protocole);
//   printf("Checksum :\t\t0x%04X\n", check_sum);
  printf("Length (psd_hdr) :\t%d\n", psd_hdr->length);
}