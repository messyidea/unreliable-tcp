#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "pcap.h"

#define snaplen 4000

int fd;
struct sockaddr_in dst_addr;
socklen_t slen;


void callback(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content) {
    struct ether_header *ethernet;
    struct iphdr *ip;
    struct tcphdr *tcp;
    const u_char *buf;
    int rst;
    int packet_lenth = packet_header->len;
    int dst_port = atoi((char *)argument);

    buf = packet_content;

    ethernet = (struct ether_header *)packet_content;
    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP) return ;
    ip = (struct iphdr*)(packet_content + 14);

    //tcp
    if(ip->protocol != 6) return ;
    tcp = (struct tcphdr*)(packet_content + 14 + 20);

    if(tcp->dest != dst_port) return ;

    //send
    rst = sendto(fd, (const void*)(packet_content + 14 + 20 + 20), packet_lenth - 14 - 20 - 20, 0, (struct sockaddr *)&dst_addr, slen);
    if(rst < 0) {
        printf("send udp error");
        return ;
    }

}


int main(int argc, char *argv[]) {
    if(argc < 5) {
        printf("Usage: ./in device port baddr bport\n");
        return -1;
    }

    pcap_t *handle;
    // pcap_if_t *alldev;
    pcap_if_t *p;

    struct in_addr net_ip_addr, net_mask_addr;
    bpf_u_int32 net_ip;
    bpf_u_int32 net_mask;

    char *net_ip_string;
    char *net_mask_string;
    char *interface;

    char errorbuf[PCAP_ERRBUF_SIZE];

    // fd init 
    slen = sizeof(dst_addr);
    memset((void *) &dst_addr, 0, slen);
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(atoi(argv[4]));
    inet_aton(argv[3], &dst_addr.sin_addr);

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    interface = argv[1];

    if((handle = pcap_open_live(interface, snaplen, 1, 0, errorbuf)) == NULL) {
        printf("%s\n", errorbuf);
        exit(1);
    }

    if(pcap_lookupnet(interface, &net_ip, &net_mask, errorbuf) == -1) {
        printf("%s\n", errorbuf);
        exit(1);
    }

    printf("Interface is: %s\n", interface);

    net_ip_addr.s_addr = net_ip;
    net_ip_string = inet_ntoa(net_ip_addr);
    printf("The ip is: %s\n", net_ip_string);

    net_mask_addr.s_addr = net_mask;
    net_mask_string = inet_ntoa(net_mask_addr);
    printf("The mask is: %s\n", net_mask_string);
    while(1) {
        pcap_loop(handle, 1, callback, (u_char *)argv[2]);
    }
    // pcap_freealldevs(alldev);

    return 0;
}