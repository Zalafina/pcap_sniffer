/* packet capture and display UDP/IPv4 header */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define INFINITY_COUNT 0            /* number to capture packets(INFINITY) */
#define TIMEOUT -1                  /* for pcap_open_live() */
#define NOT_PROMISCUOUS_MODE 0      /* Do not set promiscuous mode */
#define PROMISCUOUS_MODE 1          /* Set promiscuous mode */

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet);

int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *interfaces;
    char *custom_port = "30005";

    if(pcap_findalldevs(&interfaces,errbuf)==-1)
    {
        printf("\nerror in pcap findall devs");
        return -1;
    }

    printf("\nFirst network interfaces: %s\n\n", interfaces->name);
    if ((handle = pcap_open_live(interfaces->name, BUFSIZ, NOT_PROMISCUOUS_MODE, TIMEOUT, errbuf)) == NULL) {
        printf("%s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, INFINITY_COUNT, callback, (u_char *)custom_port) < 0) {
        puts("Can not capture packets");
        return 1;
    }

    pcap_close(handle);

    return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet)
{
    (void)(user);
    struct ether_header *e_hdr;
    struct ip *ip_hdr;
    struct udphdr *u_hdr;

    if (p_hdr->len < sizeof(struct ether_header)) {
//        puts("Defevtive packet\n");
        return;
    }

    e_hdr = (struct ether_header *)packet;

    if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
//        printf("This packet is 0x%04x\n", ntohs(e_hdr->ether_type));
        return;
    }

    ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    if (ip_hdr->ip_v != 4){
//        printf("Unkown packet");
        return;
    }

    if (ip_hdr->ip_p != 17) {
//        puts("This packet is not UDP");
        return;
    }

    u_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    uint num;
    num = atoi((char *)user);
    if (num == ntohs(u_hdr->dest)){
        printf("Source port\t: %u\n", ntohs(u_hdr->source));
        printf("Destination port: %u\n", ntohs(u_hdr->dest));
        printf("Length\t\t: %u\n", ntohs(u_hdr->len));
        printf("Checksum\t: %u\n", ntohs(u_hdr->check));
        printf("UserPort\t: %u\n", num);
        putchar('\n');
    }
}
