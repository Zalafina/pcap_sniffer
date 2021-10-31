/* packet capture and display UDP/IPv4 header */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define DEBUG_LOG_OUTPUT                /* Startup log output switch */
//#define CAPTURE_PACKET_LOG_OUTPUT     /* Log output switch */
//#define LOG_OUTPUT_EXTRA              /* Log output extra switch */

//#define USE_IMMEDIATE_MODE            /* Use immediate mode switch */

#define INFINITY_COUNT 0            /* number to capture packets(INFINITY) */
#define TIMEOUT         200         /* for pcap_open_live() capture time out in unit of ms */
#define NOT_PROMISCUOUS_MODE 0      /* Do not set promiscuous mode */
#define PROMISCUOUS_MODE 1          /* Set promiscuous mode */


#define SNAP_BUFFER_SIZE    0x10000
#define BUFFER_SIZE         5242880      /* 5M bytes */
#define DEV_NAME 20
#define TIME_STR    50
#define FILTER_EXP_MAX_SIZE 200
#define DST_HOST  "dst "
#define SRC_HOST  "src "
#define UDP_PORT_PRE_STR  " and udp dst port "
#define UDP_PORT1  " and udp"

//链路层数据包格式
typedef struct{
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;

//IP层数据包格式
typedef struct{
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEADER;

//UDP层数据包格式
typedef struct{
    u_char sourceporth:8;
    u_char sourceportl:8;
    u_char destporth:8;
    u_char destportl:8;
    int total_len:16;
    int checksum:16;
}UDPHEADER;
//协议映射表
char *Proto[]={
    "Peserved","ICMP","IGMP","GGP","IP","ST","TCP"
};

static int packet_count = 0;
static pcap_t *pd;
static pcap_t* pd_send = NULL;
//char customersip[FILTER_EXP_MAX_SIZE];
char dev[DEV_NAME] = {0};
pthread_t processcapture_thread;

char *CUSTOM_PORT = "30005";
char *customersip = "192.168.3.116";

void getPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int* id = (int *)arg;
    (*id)++;

#ifdef CAPTURE_PACKET_LOG_OUTPUT
    printf("************************************\n");
    printf("Packet id:%d\n",(*id));
    printf("Packet length:%d\n",pkthdr->len);
    printf("Packet of bytes:%d\n",pkthdr->caplen);
    char time[TIME_STR] = {0};
    char time_us[TIME_STR] = {0};
    strcat(time, ctime((const time_t *)&pkthdr->ts.tv_sec));
    size_t time_len = strlen(time);
    if (time_len>6){
        strncpy(time_us, time, time_len-6);
    }
    printf("Packet time:%s.%05ld\n", time_us, pkthdr->ts.tv_usec);
#endif

    ETHHEADER *eth_header = (ETHHEADER*)packet;
    if(pkthdr->len >= 14){
        IPHEADER *ip_header = (IPHEADER*)(packet+14);
        char strType[100];
        if(17 == ip_header->proto)
            strcpy(strType,"UDP");
        else if(ip_header->proto>7)
            strcpy(strType,"IP/UNKNWN");
        else
            strcpy(strType,Proto[ip_header->proto]);

#ifdef CAPTURE_PACKET_LOG_OUTPUT
        printf("Source MAC: %02X-%02X-%02X-%02X-%02X-%02X ==> ",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        printf("Dest MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);
        printf("Source IP: %d.%d.%d.%d ==> ",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        printf("Dest IP: %d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        printf("Protocol: %s\n",strType);
#endif

        //print packet
        UDPHEADER *udp_header = (UDPHEADER*)(packet+14+20);

#ifdef CAPTURE_PACKET_LOG_OUTPUT
        //printf("Source Portl: %02X Source Porth %02X\n",udp_header->sourceportl,udp_header->sourceporth);
        //printf("Dest Portl: %02X Dest Porth %02X\n",udp_header->destportl,udp_header->destporth);

        printf("Source Port: %d ==> ",(((0x00FF)&(udp_header->sourceportl))|((0xFF00)&(udp_header->sourceporth <<8))));
        printf("Dest Port: %d\n",(((0x00FF)&(udp_header->destportl))|((0xFF00)&(udp_header->destporth <<8))));

        //printf("UDP checksum: %04X\n",udp_header->checksum);
        //printf("UDP data len: %d\n",udp_header->total_len - 8);
#endif

#ifdef CAPTURE_PACKET_LOG_OUTPUT
        u_int start;
        start = 14 + 20 + 8; //eth header + ip header
        for(u_int i = start; i < pkthdr->len; ++i){
            printf("%02x",packet[i]);
        }
        printf("\n\n");
#endif


#ifdef LOG_OUTPUT_EXTRA
        for(u_int i = 0; i < pkthdr->len; ++i){
            printf("%02x",packet[i]);
        }
        printf("\n\n");
#endif

        u_char * buffer = (u_char *)malloc(pkthdr->len);
        if(NULL == buffer){
            pcap_close(pd_send);
        }
        else{
            memset(buffer,0x00,sizeof(pkthdr->len));
            ETHHEADER* pether_header =   (ETHHEADER*)buffer;
            IPHEADER* pip_herder       =   (IPHEADER*)(buffer + sizeof(ETHHEADER));
            UDPHEADER* pudp_herder         =   (UDPHEADER*)(buffer + sizeof(ETHHEADER) + sizeof(IPHEADER));

            memcpy(pether_header->DestMac,eth_header->SrcMac,6);
            memcpy(pether_header->SrcMac,eth_header->DestMac,6);
            memcpy(pether_header->Etype,eth_header->Etype,2);

#ifdef LOG_OUTPUT_EXTRA
            printf("[pether_header:\n");
            for(u_int i = 0;i<sizeof(ETHHEADER); ++i){
                printf("%02x",buffer[i]);
            }
            printf("\n");
#endif

            memcpy(pip_herder,ip_header,sizeof(IPHEADER));
            memcpy(pip_herder->sourceIP,ip_header->destIP,4);
            memcpy(pip_herder->destIP,ip_header->sourceIP,4);

#ifdef LOG_OUTPUT_EXTRA
            for(u_int i = 0;i<(sizeof(ETHHEADER) + sizeof(IPHEADER)); ++i){
                printf("%02x",buffer[i]);
            }
            printf("\n");
#endif
            //pip_herder->checksum  = in_cksum((int*)pip_herder, sizeof(ip_header));

            memcpy(pudp_herder,udp_header,sizeof(UDPHEADER));
            pudp_herder->destporth = udp_header->sourceporth;
            pudp_herder->destportl = udp_header->sourceportl;
            pudp_herder->sourceporth = udp_header->destporth;
            pudp_herder->sourceportl = udp_header->destportl;

#ifdef LOG_OUTPUT_EXTRA
            for(u_int i = 0;i<(sizeof(ETHHEADER) + sizeof(IPHEADER) + sizeof(UDPHEADER)); ++i){
                printf("%02x",buffer[i]);
            }
            printf("\n");
#endif

            int datepre = sizeof(ETHHEADER) + sizeof(IPHEADER) + sizeof(UDPHEADER);//eth header + ip header + udp header

            memcpy((buffer + datepre),(packet + datepre),(pkthdr->len - datepre));

#ifdef LOG_OUTPUT_EXTRA
            for(u_int i = 0; i < pkthdr->len; ++i){
                printf("%02x",buffer[i]);
            }
            printf("\n\n");
#endif

            int ret;
            ret = pcap_sendpacket(pd_send, (const u_char*)buffer, pkthdr->len);

            if (ret < 0) {
                printf("\n[pcap_sendpacket error]\n");
                exit(1);
            }

            free(buffer);
        }
    }
    else{
    }
}

static void* capture_packetThread() {
    packet_count = 0;

    if (pcap_loop(pd, INFINITY_COUNT, getPacket, (u_char *)&packet_count) < 0) {
        puts("Can not capture packets");
        return NULL;
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
//    pcap_t *handle;
    pcap_if_t *interfaces;
    char filter_exp[FILTER_EXP_MAX_SIZE] = {0};
    struct bpf_program fp;
    bpf_u_int32 netp,maskp;
    int status;

    (void)argc;
    (void)argv;

    strcat(filter_exp,SRC_HOST);
    strcat(filter_exp,customersip);
    strcat(filter_exp,UDP_PORT_PRE_STR);
    strcat(filter_exp,CUSTOM_PORT);

#ifdef DEBUG_LOG_OUTPUT
    printf("filter_exp : %s\n",filter_exp);
#endif

    if(pcap_findalldevs(&interfaces,errbuf)==-1)
    {
        printf("\nerror in pcap findall devs");
        return -1;
    }

    printf("\nFirst network interfaces: %s\n\n", interfaces->name);
//    if ((handle = pcap_open_live(interfaces->name, BUFSIZ, NOT_PROMISCUOUS_MODE, TIMEOUT, errbuf)) == NULL) {
//        printf("%s\n", errbuf);
//        return 1;
//    }

    /* Create Capture handle >>> */
    pd = pcap_create(interfaces->name, errbuf);
    if (pd == NULL){
        printf("couldn't pcap_create:%s\n",errbuf);
        return -1;
    }

    status = pcap_set_snaplen(pd, SNAP_BUFFER_SIZE);
    if (status != 0){
        printf("%s: pcap_set_snaplen failed: %s\n", interfaces->name, pcap_statustostr(status));
    }

    status = pcap_can_set_rfmon(pd);

    if (1 == status){
        status = pcap_set_rfmon(pd, 1);
        if (status != 0){
            printf("%s: pcap_set_rfmon failed: %s\n", interfaces->name, pcap_statustostr(status));
        }
        else{
            printf("%s: pcap_set_rfmon success.\n", interfaces->name);
        }
    }
    else if(0 == status){
        printf("Interface [%s] does not support monitor mode!!!\n", interfaces->name);
    }
    else{
        printf("%s: pcap_can_set_rfmon failed: %s\n", interfaces->name, pcap_statustostr(status));
    }

    status = pcap_set_buffer_size(pd, BUFFER_SIZE);
    if (status != 0){
        printf("%s: pcap_set_buffer_size failed: %s\n", interfaces->name, pcap_statustostr(status));
    }

#ifdef USE_IMMEDIATE_MODE
    status = pcap_set_immediate_mode(pd, 1);
    if (status != 0){
        printf("%s: pcap_set_immediate_mode failed: %s", interfaces->name, pcap_statustostr(status));
    }
#else
    status = pcap_set_timeout(pd, TIMEOUT);
    if (status != 0){
        printf("%s: pcap_set_timeout failed: %s\n", interfaces->name, pcap_statustostr(status));
    }
#endif

    status= pcap_set_promisc(pd, 0);

    if (status != 0){
        printf("%s: pcap_set_promisc failed: %s", interfaces->name, pcap_statustostr(status));
    }

    (void)status;

    status = pcap_activate(pd);
    if (status < 0) {
        printf("pcap_activate -> %s: %s\n(%s)", interfaces->name, pcap_statustostr(status), pcap_geterr(pd));
    }
    else if (status > 0) {
        printf("warring pcap_activate -> %s: %s\n(%s)", interfaces->name, pcap_statustostr(status), pcap_geterr(pd));
    }

    if (pcap_lookupnet(interfaces->name, &netp, &maskp, errbuf) < 0) {
        netp = 0;
        maskp = 0;
        printf("warring pcap_lookupnet : %s", errbuf);
    }

    if (pcap_compile(pd, &fp, filter_exp, 1, netp) < 0){
        printf("pcap_compile : %s", pcap_geterr(pd));
    }

    if (pcap_setfilter(pd, &fp) < 0){
        printf("pcap_setfilter : %s", pcap_geterr(pd));
    }
    /* Create Capture handle <<< */


    /* Create Send handle >>> */
    pd_send = pcap_create(interfaces->name, errbuf);
    if (pd_send == NULL){
        printf("SEND -> couldn't pcap_create:%s\n",errbuf);
        return -1;
    }

    status = pcap_set_snaplen(pd_send, SNAP_BUFFER_SIZE);
    if (status != 0){
        printf("SEND -> %s: pcap_set_snaplen failed: %s\n", interfaces->name, pcap_statustostr(status));
    }

//    status = pcap_set_buffer_size(pd_send, BUFFER_SIZE);
//    if (status != 0){
//        printf("SEND -> %s: pcap_set_buffer_size failed: %s\n", interfaces->name, pcap_statustostr(status));
//    }

#ifdef USE_IMMEDIATE_MODE
    status = pcap_set_immediate_mode(pd_send, 1);
    if (status != 0){
        printf("SEND -> %s: pcap_set_immediate_mode failed: %s", interfaces->name, pcap_statustostr(status));
    }
#else
    status = pcap_set_timeout(pd_send, TIMEOUT);
    if (status != 0){
        printf("SEND -> %s: pcap_set_timeout failed: %s\n", interfaces->name, pcap_statustostr(status));
    }
#endif

    status= pcap_set_promisc(pd_send, 0);

    if (status != 0){
        printf("SEND -> %s: pcap_set_promisc failed: %s\n", interfaces->name, pcap_statustostr(status));
    }

    (void)status;

    status = pcap_activate(pd_send);
    if (status < 0) {
        printf("SEND -> pcap_activate -> %s: %s\n(%s)\n", interfaces->name, pcap_statustostr(status), pcap_geterr(pd));
    }
    else if (status > 0) {
        printf("SEND -> warring pcap_activate -> %s: %s\n(%s)\n", interfaces->name, pcap_statustostr(status), pcap_geterr(pd));
    }
    /* Create Send handle <<< */


    /* Create capture thread >>> */
    int error = 0;
    error = pthread_create(&processcapture_thread, NULL, capture_packetThread, NULL);
    if (0 != error){
        printf("Failed to create processcapture_thread. (retval=%d[%s])\n", error, strerror(error));
    }
    /* Create capture thread <<< */


    pcap_freealldevs(interfaces);

    while(1){
        sleep(5);
#ifdef DEBUG_LOG_OUTPUT
        static int printed_packet_count = 0;
        if (printed_packet_count != packet_count){
            printed_packet_count = packet_count;
            printf("Captured packet count [%d]\n", printed_packet_count);
        }
#endif
    }

    pcap_close(pd);
    printf("Program Exit.\n");
}
