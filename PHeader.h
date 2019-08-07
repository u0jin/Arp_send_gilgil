//header
#pragma once


struct ethernet_header {
    u_char ether_dhost[6] ={0,}; /* Destination host address */
    u_char ether_shost[6]={0,0,0,0,0,0}; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct arp_header{

    u_short hd_type = htons(0x0001);
    u_short pr_type = htons(0x0800);
    u_char hd_size = 0x06;
    u_char pr_size = 0x04;
    u_short opCode;
    u_char send_mac_ad[6]={0,0,0,0,0,0};
    u_char send_ip_ad[4]={0,0,0,0};
    u_char target_mac_ad[6] = {0,0,0,0,0,0};
    u_char target_ip_ad[4] = {0,0,0,0};

};

struct combine_packet{

    struct ethernet_header ether;
    struct arp_header arp;


};

