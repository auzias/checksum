#include "pcap.h"

void begin(void)
{
 printf("********************************\n") ;
 printf("****** Debut du programme ******\n") ;
 printf("********************************\n\n") ;
}

void usage(int argc, char *argv[])
{
  if(argc != 2) {
    fprintf(stderr, "Usage: %s *chemin vers fichier .pcap*\n", argv[0]);
    exit(ERR_USAGE);
  }
  printf("Paquets du fichier pcap: %s\n", argv[1]);
}

void reverse_add(uint32_t *addr)
{
  uint32_t addr_temp;
//   printf("#1 : temp = [0x%08X]\taddr = [0x%08X]\n", addr_temp, *addr);
  addr_temp = (*addr & 0xFF000000)>>24;
//   printf("#2 : temp = [0x%08X]\taddr = [0x%08X]\n", addr_temp, *addr);
  addr_temp |= (*addr & 0x00FF0000)>>8;
//   printf("#3 : temp = [0x%08X]\taddr = [0x%08X]\n", addr_temp, *addr);
  addr_temp |= (*addr & 0x0000FF00)<<8;
//   printf("#4 : temp = [0x%08X]\taddr = [0x%08X]\n", addr_temp, *addr);
  addr_temp |= (*addr & 0x000000FF)<<24;
//   printf("#5 : temp = [0x%08X]\taddr = [0x%08X]\n", addr_temp, *addr);
  *addr = addr_temp;
  //printf("Source address :\t[0x%08X]\n", addr_temp);
}

void print_data(const uint32_t *data, uint16_t length)
{
  for (int i = 0; i <= length/16; i++)
  {
    if(i*16 != length)
      printf("0x%.2x\t", i*16);
    int k = (((i+1)*16) > length) ? length-(i*16) : 16;
    for (int j = 0; j < k; j++)
      {
	printf("%.2x ", *data);
	if(j == 7)
	  putchar(' ');
	data++;
      }
      if (k != 16)
      for (int j = k; j < 16; j++)
	printf("   ");
    if (i*16 != length)
      putchar('\n');
  }
}

void end(void)
{
  printf("\n******************************\n") ;
  printf("****** Fin du programme ******\n") ;
  printf("******************************\n") ;
}