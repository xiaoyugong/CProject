#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include "ndpi_api.h"

//static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
pthread_t thread;
//void * print() {
//    printf("Hello World!, \n");
//    return NULL;
//}

//void thread_print() {
//    printf("-------------------");
//    pthread_create(&thread, NULL, print, NULL);
//    pthread_join(thread, NULL);
//    printf("+++++++++++++++++++");
//}

//int main()
//{
////    ndpi_info_mod = ndpi_init_detection_module();
////    if (ndpi_info_mod == NULL) return -1;
////    printf("ts: %d\n", ndpi_info_mod->current_ts);

////    for(int i=0; i<(int) ndpi_info_mod->ndpi_num_supported_protocols; i++) {
////      printf("protos[%d].name: %s\n", i, ndpi_info_mod->proto_defaults[i].protoName);
////    }
//    for(int i = 1; i <= 5; i++) {
//        thread_print();
//        printf("xxxx, %d\n", i);
//        sleep(2);
//    }
//    return 0;
//}

//#include <stdlib.h>
//#include <string.h>
//#include <ctype.h>
//#include <pcap.h>



//#define MAXBYTE2CAPTURE 2048

//static int total = 0;
//int capture_until = 0;
//int capture_for = 2;
//void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
//{
//    unsigned int i = 0;
//    int *counter = (int *)arg;

////    printf("Packet Count: %d\n", ++(*counter));
////    printf("Received Packet Size: %d\n", pkthdr->len);
////    printf("Payload:\n");

////    for (i = 0; i < pkthdr->len; i++) {
////        if (isprint(packet[i]))
////            printf("%c ", packet[i]);
////        else
////            printf(". ");

////        if ((i % 16 == 0 && i != 0) || i == pkthdr->len-1)
////            printf("\n");
////    }

//    total += 1;
//    if((capture_until != 0) && (pkthdr->ts.tv_sec >= capture_until)) {
//        printf("total : %d\n", total);
//        capture_until = capture_for + time(NULL);
//        total = 0;
//    }

//    return;
//}

//int main(int argc, char **argv)
//{
//    int i = 0, count = 0;
//    pcap_t *descr = NULL;
//    char errbuf[PCAP_ERRBUF_SIZE] = {0};
//    char *device = "eno2";

//    /* Get the name of the first device suitable for capture */
////    device = pcap_lookupdev(errbuf);

//    printf("Opening device %s\n", device);

//    /* Open device in promiscuous mode */
//    descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 512, errbuf);
//    capture_until = capture_for + time(NULL);

//    /* Loop forever & call processPacket() for every received packet */
//    pthread_create(&thread, NULL, pcap_loop(descr, -1, processPacket, (u_char *)&count), NULL);
//    pthread_join(thread, NULL);

//    return 0;
//



#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

//链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;
//IP层数据包格式
typedef struct {
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
//协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};
//回调函数
void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    ETHHEADER *eth_header=(ETHHEADER*)pkt_data;
    printf("---------------Begin Analysis-----------------\n");
    printf("----------------------------------------------\n");
    printf("Packet length: %d \n",header->len);
    //解析数据包IP头部
    if(header->len>=14){
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);

        //解析协议类型
        char strType[100];
        if(ip_header->proto>7)
            strcpy(strType,"IP/UNKNWN");
        else
            strcpy(strType,Proto[ip_header->proto]);

        printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);

        printf("Source IP : %d.%d.%d.%d==>",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        printf("Dest   IP : %d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);

        printf("Protocol : %s\n",strType);
        printf("ttl : %ld\n",ip_header->ttl);

        //显示数据帧内容
        int i;
        for(i=0; i<(int)header->len; ++i)  {
            printf(" %02x", pkt_data[i]);
            if( (i + 1) % 16 == 0 )
                printf("\n");
        }
        printf("\n\n");
    }
}

int main(int argc, char **argv)
{
    char *device="enp2s0";
    char errbuf[1024];
    pcap_t *phandle;

    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    int datalink;

    if((device=pcap_lookupdev(errbuf))==NULL){
        perror(errbuf);
        return 1;
    }
    else
        printf("device: %s\n",device);

    phandle=pcap_open_live(device,200,0,500,errbuf);
    if(phandle==NULL){
        perror(errbuf);
        return 1;
    }

    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return 1;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("inet_ntop error");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("inet_ntop error");
        printf("IP address: %s, Network Mask: %s\n",ip,mask);
    }

    int flag=1;
    while(flag){
        //input the design filter
        printf("Input packet Filter: ");
        char filterString[1024];
        scanf("%s",filterString);

        if(pcap_compile(phandle,&fcode,filterString,0,ipmask)==-1)
            fprintf(stderr,"pcap_compile: %s,please input again....\n",pcap_geterr(phandle));
        else
            flag=0;
    }

    if(pcap_setfilter(phandle,&fcode)==-1){
        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
        return 1;
    }

    if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return 1;
    }

    printf("datalink= %d\n",datalink);

    pcap_loop(phandle,-1,pcap_handle,NULL);

    return 0;
}
