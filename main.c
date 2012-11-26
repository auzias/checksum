#include "pcap.h"

int main(int argc, char *argv[])
{
  begin();
  usage(argc, argv);

  char *file = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  //Ouverture en mode lecture du fichier $(file).
  //handle_pcap est un pointeur sur pcap_t si succès
  pcap_t *handle_pcap = pcap_open_offline(file, errbuf);
  if(handle_pcap == NULL)
  {
    fprintf(stderr,"Couldn't open pcap file %s: %s\n", file, errbuf);
    exit(ERR_OPEN_FILE);
  }

  struct pseudohdr *psd_hdr = malloc(sizeof(struct pseudohdr));
  if(psd_hdr == NULL)
  {
    fprintf(stderr,"Couldn't allocate memory for struct psd_hdr.\n");
    exit(ERR_MALLOC);
  }
  pcap_dumper_t *dest = pcap_dump_open(handle_pcap, "pcap_corrected.pcap");

  //Le header que pcap nous donne	
  struct pcap_pkthdr *header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
  uint8_t *packet;
  int i = 1;
  while((packet = pcap_next(handle_pcap, header)))
  {
    printf("\n**Packet #%d\n", i++);
    init_pseudo_header(packet, psd_hdr);
    //Si le protocole est TCP :
    if(psd_hdr->type_protocole == 0x06)
    {
      struct tcp_packet *tcp_pck = malloc(sizeof(struct tcp_packet));
      if(tcp_pck == NULL)
      {
	fprintf(stderr,"Couldn't allocate memory for struct psd_hdr.\n");
	exit(ERR_MALLOC);
      }
      init_tcp_packet(packet, tcp_pck);
      checksum_tcp(psd_hdr, tcp_pck);
      print_psd_hdr(psd_hdr);
      print_tcp_packet(psd_hdr, tcp_pck);
      putchar('\n');
    }
    //Si le protocole est UDP :
    else if(psd_hdr->type_protocole == 0x11)
    {
      struct udp_packet *udp_pck = malloc(sizeof(struct udp_packet));
      if(udp_pck == NULL)
      {
	fprintf(stderr,"Couldn't allocate memory for struct psd_hdr.\n");
	exit(ERR_MALLOC);
      }
      init_udp_packet(packet, udp_pck);
      checksum_udp(psd_hdr, udp_pck);
      print_psd_hdr(psd_hdr);
      print_udp_packet(psd_hdr, udp_pck);
      //Si le checksum n'est pas correct, on le corrige
      if(psd_hdr->check_sum_read != udp_pck->check_sum)
      {
 	packet[40] = (udp_pck->check_sum & 0XFF00)>>8;
	packet[41] = udp_pck->check_sum & 0X00FF;
      }
      putchar('\n');
    }
    pcap_dump((u_char*)dest, header, packet);
  }

  //On libère la mémoire
  free(psd_hdr);
  //On ferme le fichier
  pcap_close(handle_pcap);
  //On clos le programme
  end();
  return 0;
}