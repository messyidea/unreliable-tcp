#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "pcap.h"

#define BUF_SIZE 2000
#define snaplen 4000

char *interface;
int fd;
struct sockaddr_in dst_addr;
socklen_t slen;
int remote_port;
char *remote_addr;
pthread_t libnet_thread;


void* handle_out(void *arg) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t ip_tag = 0, tcp_tag = 0;
    u_short proto = IPPROTO_TCP;
    int packet_size;
    libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, interface, errbuf);
    if(NULL == libnet_handler) {
        printf("libnet init failed: %s\n", errbuf);
        exit(1);
    }

    u_long dst_ip = libnet_name2addr4(libnet_handler, remote_addr, LIBNET_RESOLVE);
    u_long src_ip = libnet_name2addr4(libnet_handler, "0.0.0.0", LIBNET_RESOLVE);

    u_char buf[BUF_SIZE];
    ssize_t recvlen;

    while(1) {
        recvlen = recvfrom(fd, buf, BUF_SIZE, 0, NULL, NULL);
        tcp_tag = libnet_build_tcp(
            11111,                    /* 源端口 */
            remote_port,                    /* 目的端口 */
            8888,                    /* 序列号 */
            8889,                    /* 确认号 */
            TH_PUSH | TH_ACK,        /* Control flags */
            14600,                    /* 窗口尺寸 */
            0,                        /* 校验和,0为自动计算 */
            0,                        /* 紧急指针 */
            LIBNET_TCP_H + recvlen, /* 长度 */
            buf,                    /* 负载内容 */
            recvlen,                /* 负载内容长度 */
            libnet_handler,                    /* libnet句柄 */
            tcp_tag                        /* 新建包 */
        );
        if (tcp_tag == -1) {
            printf("libnet_build_tcp failure\n");
            continue;
        };

        /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
        ip_tag = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H + recvlen, /* IP协议块的总长,*/
            0, /* tos */
            (u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
            0, /* frag 片偏移 */
            (u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
            proto, /* 上层协议 */
            0, /* 校验和，此时为0，表示由Libnet自动计算 */
            src_ip, /* 源IP地址,网络序 */
            dst_ip, /* 目标IP地址,网络序 */
            NULL, /* 负载内容或为NULL */
            0, /* 负载内容的大小*/
            libnet_handler, /* Libnet句柄 */
            ip_tag /* 协议块标记可修改或创建,0表示构造一个新的*/
        );
        if (ip_tag == -1) {
            printf("libnet_build_ipv4 failure\n");
            continue;
        };

        packet_size = libnet_write(libnet_handler);
        //libnet_clear_packet(libnet_handler);
    }

    libnet_destroy(libnet_handler);
}

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

    if(ntohs(tcp->dest) != dst_port) return ;

    //send
    rst = sendto(fd, (const void*)(packet_content + 14 + 20 + 20), packet_lenth - 14 - 20 - 20, 0, (struct sockaddr *)&dst_addr, slen);
    if(rst < 0) {
        printf("send udp error");
        return ;
    }
}

int main(int argc, char *argv[]) {
    if(argc < 7) {
        printf("Usage: ./in device port backend_addr backend_port remote_addr remote_port\n");
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

    char errorbuf[PCAP_ERRBUF_SIZE];

    // fd init 
    slen = sizeof(dst_addr);
    memset((void *) &dst_addr, 0, slen);
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(atoi(argv[4]));
    inet_aton(argv[3], &dst_addr.sin_addr);

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    interface = argv[1];

    remote_port = atoi(argv[6]);
    remote_addr = argv[5];

    pthread_create(&libnet_thread, NULL, handle_out, NULL);

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
