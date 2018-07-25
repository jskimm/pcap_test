#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#include <netinet/ip.h> 
#include <netinet/ether.h>
#include <netinet/tcp.h> 
#include <stdlib.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test ens33\n");
}

char *macBeautify(u_int8_t *data){
  char *tmp = (char *)malloc(20);
  sprintf(tmp,
    "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
    data[0], data[1], data[2],
    data[3], data[4], data[5] );
  return tmp;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  char error_buf[PCAP_ERRBUF_SIZE];  
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  char *shost, *dhost;
  char *src_ip, *dst_ip;
  int src_port, dst_port;
  
  printf("[bob7][%s]pcap_test[%s]\n", "취약점", "김지섭");
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct ether_header *ether_hdr;
    char *data;

    ether_hdr = (struct ether_header *)packet;
    ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header)+sizeof(struct ip));

    switch( htons(ether_hdr->ether_type) ){
      case ETHERTYPE_IP:
        if( ip_hdr->ip_p != IPPROTO_TCP ) break; // tcp only 

        shost = macBeautify(ether_hdr->ether_shost);
        dhost = macBeautify(ether_hdr->ether_dhost);

        src_ip = inet_ntoa(ip_hdr->ip_src);
        dst_ip = inet_ntoa(ip_hdr->ip_dst);

        src_port = ntohs(tcp_hdr->source);
        dst_port = ntohs(tcp_hdr->dest);

        data = (char *)tcp_hdr + (tcp_hdr->th_off * 4);
        printf("[%s] %15s:%-5d -> [%s] %15s:%-5d\n", 
          shost, src_ip, src_port,
          dhost, dst_ip, dst_port
        );
        for(int i=0;i<16;i++) printf("%c", data[i]); 

        printf("\n\n");
        free(shost);
        free(dhost);
        break;

        case ETHERTYPE_ARP:
        default: break;
    }
  }

  pcap_close(handle);
  return 0;
}
