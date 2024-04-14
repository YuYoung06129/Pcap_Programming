#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <arpa/inet.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    const u_char *Message;
    int Message_length;
    int i;

    // Ethernet header 
    eth_header = (struct ether_header *)pkt_data;

    // IP header 
    ip_header = (struct ip *)(pkt_data + sizeof(struct ether_header)); // 수정

    // TCP header 
    tcp_header = (struct tcphdr *)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip));

    // TCP Protocol check
    if (ip_header->ip_p == IPPROTO_TCP) {
        printf("Src MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", 
                eth_header->ether_shost[0], eth_header->ether_shost[1], 
                eth_header->ether_shost[2], eth_header->ether_shost[3], 
                eth_header->ether_shost[4], eth_header->ether_shost[5]);
        printf("Dst MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", 
                eth_header->ether_dhost[0], eth_header->ether_dhost[1], 
                eth_header->ether_dhost[2], eth_header->ether_dhost[3], 
                eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

        printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

        printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));

        // Print TCP Message 
        Message = pkt_data + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + sizeof(struct tcphdr); // 수정
        Message_length = header->len - (sizeof(struct ether_header) + (ip_header->ip_hl * 4) + sizeof(struct tcphdr)); // 수정
        printf("Message: ");

        for (i = 0; i < Message_length; i++) {
            printf("%c", isprint(Message[i]) ? Message[i] : '.');
        }

        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;

    // 네트워크 디바이스 얻기
    pcap_if_t *netdev;
    if (pcap_findalldevs(&netdev, errbuf) == -1) { // 수정
        fprintf(stderr, "No Search Network Device: %s\n", errbuf); // 수정
        return 1;
    }

    // 디바이스 선택
    char *dev = netdev->name;

    // 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 캡처 반복
    pcap_loop(handle, 0, packet_handler, NULL);

    // 반복 종료
    pcap_close(handle);
    return 0;
}
