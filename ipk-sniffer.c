#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <netinet/if_ether.h> 
#include <stdbool.h>
#include <pcap.h> 
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

 
void printdev()
{
    pcap_if_t *alldevs;
    pcap_if_t *i;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    int index = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    printf("List of interfaces:\n");
    for (i = alldevs; i != NULL; i = i->next) {
        printf("%d:\t\t%s\n", ++index, i->name);
    }

    pcap_freealldevs(alldevs);

}

void timeprint()
{
    char timebuff[200];
    time_t my_time;
    time(&my_time);
    struct tm * tm_inf = localtime(&my_time);
    size_t len = strftime(timebuff, sizeof timebuff - 1, "%FT%T%z", tm_inf);
    if (len > 1)
    {
        char minute[] = {timebuff[len - 2], timebuff[len - 1], '\0'};
        sprintf(timebuff + len - 2, ":%s", minute);
    }
    printf("timestamp: %s\n", timebuff);
}



void print_ipv4_address(char *msg, __uint32_t ip_address)
{
    struct in_addr ip;
    ip.s_addr = ip_address;
    printf("%s: %s\n", msg, inet_ntoa(ip));
}

void arp_packet_parser(const u_char* packet)
{
  
}

void packetPrinter(const unsigned char *addr, const int len) {
    int perLine = 16;
    unsigned char buff[perLine + 1];
    const unsigned char *pc = addr;

  

    if (len == 0) {
        fprintf(stderr, "ZERO LENGTH\n");
        exit(EXIT_FAILURE);
    }
    if (len < 0) {
        fprintf(stderr, "NEGATIVE LENGTH: %d\n", len);
        exit(EXIT_FAILURE);
    }


    printf("\n");

    for (int i = 0; i < len; i++) {
       

        if ((i % perLine) == 0) {
            

            if (i != 0)
                printf("  %s\n", buff);

          
            printf("0x%.4x: ", i);
        }

        if (i % 8 == 0 && i % 16 != 0)
            printf(" ");
        printf(" %02x", pc[i]);
        buff[i % perLine] = (pc[i] < 0x20 || pc[i] > 0x7e) ? '.' : pc[i];
        buff[(i % perLine) + 1] = '\0';
    }
    printf("  %s\n", buff);
}


void print_src_ip(const struct iphdr *iph) {
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    printf("src IP: %s\n", inet_ntoa(source.sin_addr));
}



void print_dst_ip(const struct iphdr *iph) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    printf("dst IP: %s\n", inet_ntoa(dest.sin_addr));
}
void print_igmp(const u_char* packet)
{
struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
print_src_ip(iph);
print_dst_ip(iph);
}

void print_ip_header(const u_char* packet) {
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));

    print_src_ip(iph);
    print_dst_ip(iph);
}


void print_ip6_header(const u_char* packet){
    struct sockaddr_in6 src, dst;
    char addrString[INET6_ADDRSTRLEN];
    struct ip6_hdr *iph = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

    memset(&src, 0, sizeof(src));
    src.sin6_addr = iph->ip6_src;
    inet_ntop(AF_INET6, &(src.sin6_addr), addrString,  INET6_ADDRSTRLEN);
    printf("src IP: %s\n", addrString);

    memset(&dst, 0, sizeof(dst));
    dst.sin6_addr = iph->ip6_dst;
    inet_ntop(AF_INET6, &(dst.sin6_addr), addrString,  INET6_ADDRSTRLEN);
    printf("dst IP: %s\n", addrString);

}

void print_mld(const u_char *packet) {
    struct ip6_hdr *iph = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    printf("src IP: ");
    char src_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &iph->ip6_src, src_ip_str, INET6_ADDRSTRLEN);
    printf("%s\n", src_ip_str);
    printf("dst IP: ");
    char dest_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &iph->ip6_dst, dest_ip_str, INET6_ADDRSTRLEN);
    printf("%s\n", dest_ip_str);
}


void print_tcp_packet(const u_char *packet, unsigned short iphdrlen){

    struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("src port: %u\n",ntohs(tcph->source));
    printf("dst port: %u\n",ntohs(tcph->dest));
}


void print_udp_packet(const u_char *packet, unsigned short iphdrlen){

    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("src port: %d\n",ntohs(udph->source));
    printf("dst port: %d\n",ntohs(udph->dest));
}


void print_arp_header(const u_char* packet) {
    const u_char* arp_header = packet + sizeof(struct ether_header);

    printf("src IP: %d.%d.%d.%d\n",
           arp_header[14], arp_header[15], arp_header[16], arp_header[17]);

    
    printf("dst IP: %d.%d.%d.%d\n",
           arp_header[24], arp_header[25], arp_header[26], arp_header[27]);
}

void packetParser(u_char *args, const struct pcap_pkthdr *header, const u_char* packet){
    unsigned short iphdrlen;
    timeprint();
    struct ether_header *eth = (struct ether_header *) packet;
    printf("src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5] );
    printf("dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5] );
    printf("frame length: %d bytes\n", header->len);
    
    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ether_header));
        if(iph->protocol == 1){
            print_ip_header(packet); 
        }else if(iph->protocol == 2){
            
            print_igmp(packet);
        }else if(iph->protocol == 6){
            print_ip_header(packet); //
            iphdrlen = iph->ihl*4;
            print_tcp_packet(packet, iphdrlen);
        }else if(iph->protocol == 17){
            print_ip_header(packet); // UDP Protocol
            iphdrlen = iph->ihl*4;
            print_udp_packet(packet, iphdrlen);
        }
    }else if(ntohs(eth->ether_type) == ETHERTYPE_IPV6){
        struct ip6_hdr *iph = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == 1){
            print_ip6_header(packet); 
        }else if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == 2){
          
            print_ip6_header(packet);
        }else if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){
            print_ip6_header(packet); 
            iphdrlen = sizeof(struct ip6_hdr);
            print_tcp_packet(packet, iphdrlen);
        }else if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17){
            print_ip6_header(packet); 
            iphdrlen = sizeof(struct ip6_hdr);
            print_udp_packet(packet, iphdrlen);
        }
    }else if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
        print_arp_header(packet);
       
    }else if(ntohs(eth->ether_type) == 0x86DD){
    
        print_mld(packet);
    }
    packetPrinter(packet, (int)header->len);
}


void getPackets(pcap_t* handle, int packets){
    if(pcap_loop(handle, packets, packetParser, 0) < 0){
        fprintf(stderr, "Error: Couldn't install filter %s\n", pcap_geterr(handle));
    }
}


pcap_t* socket_open(char* dev, char* filter_exp){
    pcap_t *handle;
    struct bpf_program bfp;
    char error[PCAP_ERRBUF_SIZE];
    uint32_t netmask;
    uint32_t script;

     if (pcap_lookupnet(dev, &script, &netmask, error) == -1) 
    {
        fprintf(stderr, "faliure with netmask %s\n %s", dev, error);

    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error);
    if (handle == NULL) {
        fprintf(stderr, "cant open device %s\n %s", dev, error);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev, &script, &netmask, error) == -1) {
        fprintf(stderr, "cant get source ip %s\n %s", dev, error);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &bfp, filter_exp, 1, netmask) == -1) {
        fprintf(stderr, "Error: could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
   
    if (pcap_setfilter(handle, &bfp) == -1) {
        fprintf(stderr, "cant connect filter into libcap  %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    return handle;

}

int main(int argc, char **argv) {
int c = -1;
char* dev = NULL;
int printed = 0;
bool tcp = false;
bool udp = false;
bool arp = false;
bool icmp4 = false;
bool icmp6 = false;
bool ndp = false;
bool igmp = false;
bool mld = false;
int number = 1;
int p = 0;
char port[20] = "";
char filter_exp[100] = "";

for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0|| strcmp(argv[i], "--interface") == 0) {
        if (argv[i + 1] != NULL && argv[i + 1][0] != '-') {
            dev = argv[i + 1];
            i++;
        } else {
            printdev();
            printed = 1;
        }
    } else if (strcmp(argv[i], "-p") == 0) {
        if (argv[i + 1] != NULL && atoi(argv[i + 1])) {
            p = atoi(argv[i + 1]);
            if (!(p > 0 && p < 65536)) {
                printf("ERROR: port out of range");
                exit(EXIT_FAILURE);
            } else {
                sprintf(port, "port %d", p);
            }
            i++;
        } else {
            printf("ERROR: port must be a number");
            exit(EXIT_FAILURE);
        }
    } else if (strcmp(argv[i], "-t") == 0|| strcmp(argv[i], "--tcp") == 0) {
        tcp = true;
    } else if (strcmp(argv[i], "-u") == 0|| strcmp(argv[i], "--udp") == 0) {
        udp = true;
    } else if (strcmp(argv[i], "-arp") == 0) {
        arp = true;
    } 
    else if (strcmp(argv[i], "-icmp6") == 0) {
        icmp6 = true;
    }
    else if (strcmp(argv[i], "-icmp4") == 0) {
        icmp4 = true;
    }
    else if (strcmp(argv[i], "-ndp") == 0) {
        ndp = true;
    }
    else if (strcmp(argv[i], "-igmp") == 0) {
        igmp = true;
    }
    else if (strcmp(argv[i], "-mld") == 0) {
        mld = true;
    }else if (strcmp(argv[i], "-n") == 0) {
        if (argv[i + 1] != NULL && atoi(argv[i + 1])) {
            number = atoi(argv[i + 1]);
            i++;
        } else {
            printf("ERROR: packet number must be a number");
            exit(EXIT_FAILURE);
        }
    } else {
        printf("ERROR: Invalid option: %s\n", argv[i]);
        exit(EXIT_FAILURE);
    }
}
    if(tcp == true){
        strcat(filter_exp, "tcp");
        if (strcmp(port, "") != 0){
            strcat(filter_exp, " ");
            strcat(filter_exp, port);
        }
    }
    if(udp == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "udp");
        }else{
            strcat(filter_exp, " or udp");
        }
        if (strcmp(port, "") != 0){
            strcat(filter_exp, " ");
            strcat(filter_exp, port);
        }
    }
    if(icmp4 == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "icmp");
        }else{
            strcat(filter_exp, " or icmp");
        }
    }
    if(arp == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "arp");
        }else{
            strcat(filter_exp, " or arp");
        }
    }
    
    
    if(icmp6 == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "icmp6");
        }else{
            strcat(filter_exp, " or icmp6");
        }
    }
    if(igmp == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "igmp");
        }else{
            strcat(filter_exp, " or igmp");
        }
    }
    if(mld == true){
        if(strcmp(filter_exp, "") == 0){
            strcat(filter_exp, "mld");
        }else{
            strcat(filter_exp, " or mld");
        }
    }
    if( arp == true && udp == true && tcp == true && icmp4 == true && icmp6 == true && igmp == true && mld == true && strcmp(port, "") != 0){
        strcat(filter_exp, "tcp");
        strcat(filter_exp, " ");
        strcat(filter_exp, port);
        strcat(filter_exp, " or udp");
        strcat(filter_exp, " ");
        strcat(filter_exp, port);
        strcat(filter_exp, " or icmp");
        strcat(filter_exp, " or arp");
      
        strcat(filter_exp, " or icmp6");
        strcat(filter_exp, " or igmp");
        strcat(filter_exp, " or mld");
    }else if(arp == true && udp == true && tcp == true && icmp4 == true && icmp6 == true && igmp == true && mld == true && strcmp(port, "")== 0){
        strcat(filter_exp, "tcp");
        strcat(filter_exp, " or udp");
        strcat(filter_exp, " or icmp");
        strcat(filter_exp, " or arp");
        
        strcat(filter_exp, " or icmp6");
        strcat(filter_exp, " or igmp");
        strcat(filter_exp, " or mld");
    }

    if(dev == NULL || strcmp(dev, "") == 0){
        if (printed == 0){
            printdev();
        }
    }else{
        pcap_t *handle = socket_open(dev, filter_exp);
        getPackets(handle, number);
        pcap_close(handle);
        return(0);
    }
}