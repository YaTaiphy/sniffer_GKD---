/* write by Lai, 2021E8018682138, 2022.4.2*/

#pragma once
#include <stdio.h>
#include <iostream>
#define HAVE_REMOTE
#include "pcap.h"
#include "protocals.h"
#include "AllStructs.h"

void sprintPacket_content(u_char* target, u_int target_len, struct message& m) {
    for (u_int i = 0; i < target_len; i++) {
        char code[8] = "";
        sprintf(code, "0x%02x ", target[i]);
        strcat(m.analyse_infor, code);
    }
}

void tcp_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    const u_int ip_header_len,
    const u_int ip_len,
    struct message& m
) {
    // TCPpayloads = IP报文长度 - （IP Header /Option/Padding）长度 - Data Offset * 4
    struct tcp_header* tcp_protocol;

    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char dataOffset;
    u_char reserve;
    u_char signs;
    u_short windows;            // 窗口大小
    u_short checksum;            // 校验和
    u_short urgent_pointer;        // 紧急指针

    strcat(m.analyse_infor, "=====TCP=====\n");
    tcp_protocol = (tcp_header*)(packet_content + 14 + ip_header_len);
    sport = ntohs(tcp_protocol->sport);
    dport = ntohs(tcp_protocol->dport);
    seq = ntohl(tcp_protocol->sequence);
    ack = ntohl(tcp_protocol->ack);
    char sdsa[64] = "";
    sprintf(sdsa, "sport:%d, dport:%d, sequence:%u, ack:%u\n", sport, dport, seq, ack);
    strcat(m.analyse_infor, sdsa);

    dataOffset = (tcp_protocol->dataOffset_reserve_sign & 0xf000) >> 12;
    reserve = (tcp_protocol->dataOffset_reserve_sign & 0x0f00) >> 8; //其中包含了NS位
    signs = (tcp_protocol->dataOffset_reserve_sign & 0x00ff);

    char dors[128] = "";
    sprintf(dors, "dataOffset:%d, reserver:%d %d %d, NS:%d\nCWR:%d, ECE:%d, URG:%d, ACK:%d, PSH:%d, RST:%d, SYN:%d, FIN:%d\n",
        dataOffset,
        (reserve & 0x8) >> 3,
        (reserve & 0x4) >> 2,
        (reserve & 0x2) >> 1,
        reserve & 0x1,
        (signs & 0x80) >> 7,
        (signs & 0x40) >> 6,
        (signs & 0x20) >> 5,
        (signs & 0x10) >> 4,
        (signs & 0x8) >> 3,
        (signs & 0x4) >> 2,
        (signs & 0x2) >> 1,
        signs & 0x1
    );
    strcat(m.analyse_infor, dors);
    
    windows = ntohs(tcp_protocol->windows);
    checksum = ntohs(tcp_protocol->checksum);
    urgent_pointer = ntohs(tcp_protocol->urgent_pointer);
    char wcu[64] = "";
    sprintf(wcu, "Window Size:%d, CheckSum:%d, Urgent Pointer:%d\n", windows, checksum, urgent_pointer);
    strcat(m.analyse_infor, dors);

    strcat(m.analyse_infor, "Options:");
    if (dataOffset > 5) {
        u_char options[72] = "";
        int options_len = dataOffset * 4 - 20;
        memcpy(options, (packet_content + 14 + ip_header_len + 20), sizeof(u_char) * options_len);
        sprintPacket_content(options, options_len, m);
    }
    else {
        strcat(m.analyse_infor, "None");
    }
    strcat(m.analyse_infor, "\n");

    strcat(m.analyse_infor, "TCP message:\n");
    u_char tcp_m[65535] = "";
    int m_len = ip_len - ip_header_len - dataOffset * 4;
    if (m_len <= 0)
        strcat(m.analyse_infor, "None");
    else {
        memcpy(tcp_m, (packet_content + 14 + ip_header_len + dataOffset * 4), sizeof(u_char) * m_len);
        sprintPacket_content(tcp_m, m_len, m);
    }
    strcat(m.analyse_infor, "\n");

    m.sport = sport;
    m.dport = dport;
    strcat(m.protocalType, "TCP");
}

void udp_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    const u_int ip_header_len,
    struct message &m
) {
    struct udp_header* udp_protocol;
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;

    udp_protocol = (udp_header*)(packet_content + 14 + ip_header_len);
    /* convert from network byte order to host byte order */
    sport = ntohs(udp_protocol->sport);
    dport = ntohs(udp_protocol->dport);
    len = ntohs(udp_protocol->len);
    crc = ntohs(udp_protocol->crc);

    strcat(m.analyse_infor, "======UDP=====\n");
    char infor[64] = "";
    sprintf(infor, "sport:%d, dport:%d, length:%d, crc:%d\n", sport, dport, len, crc);
    m.sport = sport;
    m.dport = dport;
    strcat(m.analyse_infor, infor);

    strcat(m.analyse_infor, "UDP message:\n");

    u_char udp_m[65535] = "";
    int m_len = len - 8;
    if (m_len <= 0)
        strcat(m.analyse_infor, "None");
    else {
        memcpy(udp_m, (packet_content + 14 + 20), sizeof(u_char) * m_len);
        sprintPacket_content(udp_m, m_len, m);
    }
    strcat(m.analyse_infor, "\n");
    strcat(m.protocalType, "UDP");
}

void arp_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    struct message &m
) {
    struct arp_header* arp_protocol;
    u_short protocol_type;
    u_short hardware_type;
    u_short operation_code;
    u_char hardware_length;
    u_char protocol_length;

    arp_protocol = (struct arp_header*)(packet_content + 14);

    strcat(m.analyse_infor, "--------ARP--------\n");
    hardware_type = ntohs(arp_protocol->arp_hardware_type);
    strcat(m.analyse_infor, "hardware_type:");
    char ht[8] = "";
    sprintf(ht, "0x%04x\n", hardware_type);
    strcat(m.analyse_infor, ht);

    protocol_type = ntohs(arp_protocol->arp_protocol_type);
    strcat(m.analyse_infor, "protocol_type:");
    char pt[8] = "";
    sprintf(pt, "0x%04x\n", protocol_type);
    strcat(m.analyse_infor, pt);

    strcat(m.analyse_infor, "operation_code:");
    operation_code = ntohs(arp_protocol->arp_operation_code);
    char oc[8] = "";
    sprintf(oc, "0x%04x", operation_code);
    strcat(m.analyse_infor, oc);
    switch (operation_code)
    {
    case 1:
        strcat(m.analyse_infor, "    ARP request\n");
        break;
    case 2:
        strcat(m.analyse_infor, "    ARP reply\n");
        break;
    case 3:
        strcat(m.analyse_infor, "    RARP request\n");
        break;
    case 4:
        strcat(m.analyse_infor, "    RARP reply\n");
        break;
    default:
        break;
    }

    hardware_length = arp_protocol->arp_hardware_length;
    strcat(m.analyse_infor, "hardware_length:  ");
    char hl[8] = "";
    sprintf(hl, "0x%02x\n", hardware_length);
    strcat(m.analyse_infor, hl);
    protocol_length = arp_protocol->arp_protocol_length;
    strcat(m.analyse_infor, "protocol_length:  ");
    char pl[8] = "";
    sprintf(pl, "0x%02x\n", protocol_length);
    strcat(m.analyse_infor, pl);

    strcat(m.analyse_infor, "arp_source_ethernet_address:");

    char source_mac[48] = "";
    sprintf(source_mac, "%02x:%02x:%02x:%02x:%02x:%02x   ",
        *arp_protocol->arp_source_ethernet_address,
        *(arp_protocol->arp_source_ethernet_address + 1),
        *(arp_protocol->arp_source_ethernet_address + 2),
        *(arp_protocol->arp_source_ethernet_address + 3),
        *(arp_protocol->arp_source_ethernet_address + 4),
        *(arp_protocol->arp_source_ethernet_address + 5));
    strcat(m.analyse_infor, source_mac);

    strcat(m.analyse_infor, "arp_destination_ethernet_address:");
    char destiny_mac[48] = "";
    sprintf(destiny_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",
        *arp_protocol->arp_destination_ethernet_address,
        *(arp_protocol->arp_destination_ethernet_address + 1),
        *(arp_protocol->arp_destination_ethernet_address + 2),
        *(arp_protocol->arp_destination_ethernet_address + 3),
        *(arp_protocol->arp_destination_ethernet_address + 4),
        *(arp_protocol->arp_destination_ethernet_address + 5));
    strcat(m.analyse_infor, destiny_mac);

    strcat(m.analyse_infor, "arp_source_ip_address:");

    char source_ip[48] = "";
    sprintf(source_ip, "%d:%d:%d:%d",
        *arp_protocol->arp_source_ip_address,
        *(arp_protocol->arp_source_ip_address + 1),
        *(arp_protocol->arp_source_ip_address + 2),
        *(arp_protocol->arp_source_ip_address + 3));
    strcat(m.analyse_infor, source_ip);
    strcat(m.source, source_ip);
    m.sport = 0;

    strcat(m.analyse_infor, ",arp_destination_ip_address:");
    char destiny_ip[48] = "";
    sprintf(destiny_ip, "%d:%d:%d:%d",
        *arp_protocol->arp_destination_ip_address,
        *(arp_protocol->arp_destination_ip_address + 1),
        *(arp_protocol->arp_destination_ip_address + 2),
        *(arp_protocol->arp_destination_ip_address + 3));
    strcat(m.analyse_infor, destiny_ip);
    strcat(m.destiny, destiny_ip);
    m.dport = 0;
    strcat(m.analyse_infor, "\n");

    strcat(m.protocalType, "ARP");
}


//目前只支持头部，具体内容有时间再做了
void icmp_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    struct message& m
) {
    struct icmp_header* icmp_protocol;
    u_char type;                // ICMP类型
    u_char code;                // 代码
    u_short checksum;            // 校验和

    icmp_protocol = (icmp_header*)(packet_content + 14 + 20);

    strcat(m.analyse_infor, "=====ICMP=====");
    type = icmp_protocol->type;
    code = icmp_protocol->code;
    checksum = ntohs(icmp_protocol->checksum);
    char tcc[64] = "";
    sprintf(tcc, "type:%d, code:%d, checksum:%u", type, code, checksum);
    strcat(m.analyse_infor, tcc);


    strcat(m.analyse_infor, "The Rest is still in progress.......");

    strcat(m.protocalType, "ICMP");
}


//ipv6依然在施工中，对于理解比较难和麻烦
void ipv6_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    struct message& m) {

    struct ipv6_header* ip_protocol;

    ip_protocol = (struct ipv6_header*)(packet_content + 14);
    strcat(m.analyse_infor, "========ipv6========\n");
    u_char version; 
    u_short  traffic_class;
    u_int flow_label;
    u_short length;
    u_char  next_header;
    u_char  hop_limit;
    version = ip_protocol->version;
    traffic_class = ntohs(ip_protocol->traffic_class);
    flow_label = ntohl(ip_protocol->flow_label);
    length = ntohs(ip_protocol->length);
    next_header = ip_protocol->next_header;
    hop_limit = ip_protocol->hop_limit;
    char vtflnh[128] = "";
    sprintf(vtflnh, "Version:%d, Traffic Class:%u, Flow Label:%u, PayLoad Length:%u, Next Header:%d, Hop Limit:%d\n",
        version,
        traffic_class,
        flow_label,
        length,
        next_header,
        hop_limit
    );
    strcat(m.analyse_infor, vtflnh);


    char source[48] = "";
    char destiny[48] = "";
    sprintf(source, "%x:%x:%x:%x:%x:%x:%x:%x",
        ntohs(ip_protocol->saddr.add1),
        ntohs(ip_protocol->saddr.add2),
        ntohs(ip_protocol->saddr.add3),
        ntohs(ip_protocol->saddr.add4),
        ntohs(ip_protocol->saddr.add5),
        ntohs(ip_protocol->saddr.add6),
        ntohs(ip_protocol->saddr.add7),
        ntohs(ip_protocol->saddr.add8)
    );
    sprintf(destiny, "%x:%x:%x:%x:%x:%x:%x:%x",
        ntohs(ip_protocol->daddr.add1),
        ntohs(ip_protocol->daddr.add2),
        ntohs(ip_protocol->daddr.add3),
        ntohs(ip_protocol->daddr.add4),
        ntohs(ip_protocol->daddr.add5),
        ntohs(ip_protocol->daddr.add6),
        ntohs(ip_protocol->daddr.add7),
        ntohs(ip_protocol->daddr.add8)
    );
    strcat(m.source, source);
    strcat(m.destiny, destiny);
    strcat(m.analyse_infor, "source_ip_address:\n");
    strcat(m.analyse_infor, source);
    strcat(m.analyse_infor, "\ndestination_ip_address:\n");
    strcat(m.analyse_infor, destiny);
    strcat(m.analyse_infor, "\n");


    strcat(m.analyse_infor, "HeaderType:");
    switch (next_header)
    {
    case 0:
        strcat(m.analyse_infor, "Hop-by-Hop Options\n");
        strcat(m.protocalType, "unknown");
        break;
    case 43:
        strcat(m.analyse_infor, "Routing Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 44:
        strcat(m.analyse_infor, "Fragment Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 51:
        strcat(m.analyse_infor, "Authentication Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 50:
        strcat(m.analyse_infor, "Encapsulation Security Payload Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 60:
        strcat(m.analyse_infor, "Destination Options\n");
        strcat(m.protocalType, "unknown");
        break;
    case 125:
        strcat(m.analyse_infor, "Mobility Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 59:
        strcat(m.analyse_infor, "No Next Header\n");
        strcat(m.protocalType, "unknown");
        break;
    case 6:
        strcat(m.analyse_infor, "TCP\n");
        strcat(m.protocalType, "TCP");
        break;
    case 17:
        strcat(m.analyse_infor, "UDP\n");
        strcat(m.protocalType, "UDP");
        break;
    case 58:
        strcat(m.analyse_infor, "ICMPv6\n");
        strcat(m.protocalType, "ICMPv6");
        break;
    default:
        break;
    }


    strcat(m.analyse_infor, "The Rest is still in progress.......\n");
}

void ip_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    struct message& m)
{

    struct ipv4_header* ip_protocol;
    u_int header_length;
    u_char tos;        //服务质量
    u_short checksum; //校验和

    ipv4_address saddr;//源IP地址
    ipv4_address daddr;//目的IP地址
    u_char ttl;      //生命周期
    u_short tlen;    //总长度
    u_short identification; //身份识别
    u_short offset; //分组偏移
    u_char flags; //flags

    strcat(m.analyse_infor, "========ipv4========\n");

    ip_protocol = (struct ipv4_header*)(packet_content + 14);
    header_length = (ip_protocol->ver_ihl & 0x0f) * 4;
    strcat(m.analyse_infor, "IHL(header length):");
    char hl[8] = "";
    sprintf(hl, "%d, ", header_length);
    strcat(m.analyse_infor, hl);

    strcat(m.analyse_infor, "type of service:");
    tos = ntohs(ip_protocol->tos);
    char tos_char[8] = "";
    sprintf(tos_char, "0x%02x\n", tos);
    strcat(m.analyse_infor, tos_char);

    strcat(m.analyse_infor, "Ip total length:");
    tlen = ntohs(ip_protocol->tlen);
    char tlen_char[16] = "";
    sprintf(tlen_char, "%d,  ", tlen);
    strcat(m.analyse_infor, tlen_char);

    strcat(m.analyse_infor, "identification:");
    identification = ntohs(ip_protocol->identification);
    char idtf[10] = "";
    sprintf(idtf, "%d\n", identification);
    strcat(m.analyse_infor, idtf);

    strcat(m.analyse_infor, "flags:");
    flags = (ip_protocol->flags_fo & 0xe000) >> 13;
    u_char reserve = flags >> 2;
    u_char DF = (flags >> 1) - reserve * 2;
    u_char MF = reserve % 2;
    char flag_[32] = "";
    sprintf(flag_, "Reserve:%d, DF:%d, MF:%d.\n", reserve, DF, MF);
    strcat(m.analyse_infor, flag_);

    strcat(m.analyse_infor, "offset:");
    char offs[20] = "";
    sprintf(offs, "%d, ", (ip_protocol->flags_fo & 0x1fff) * 8);
    strcat(m.analyse_infor, offs);

    strcat(m.analyse_infor, "time to live:");
    char ttl_[10] = "";
    sprintf(ttl_, "%d, ", ip_protocol->ttl);
    strcat(m.analyse_infor, ttl_);

    strcat(m.analyse_infor, "Header CheckSum:");
    char hcs[10] = "";
    sprintf(hcs, "%d\n", ntohs(ip_protocol->crc));
    strcat(m.analyse_infor, hcs);

    strcat(m.analyse_infor, "source_ip_address:");
    char source_ip[48] = "";
    sprintf(source_ip, "%d:%d:%d:%d",
        ip_protocol->saddr.byte1,
        ip_protocol->saddr.byte2,
        ip_protocol->saddr.byte3,
        ip_protocol->saddr.byte4
        );
    strcat(m.analyse_infor, source_ip);
    strcat(m.source, source_ip);

    strcat(m.analyse_infor, "\ndestination_ip_address:");
    char destiny_ip[48] = "";
    sprintf(destiny_ip, "%d:%d:%d:%d",
        ip_protocol->daddr.byte1,
        ip_protocol->daddr.byte2,
        ip_protocol->daddr.byte3,
        ip_protocol->daddr.byte4
    );
    strcat(m.analyse_infor, destiny_ip);
    strcat(m.destiny, destiny_ip);
    strcat(m.analyse_infor, "\n");

    u_int option_len = header_length - 20;
    //packet_content + 14 + 20
    
    strcat(m.analyse_infor, "option and padding:");
    u_char options[65535] = "";
    if (option_len == 0 || option_len > 15)
        strcat(m.analyse_infor, "0");
    else {
        memcpy(options, (packet_content + 14 + 20), sizeof(u_char) * option_len);
        sprintPacket_content(options, option_len, m);
    }
    strcat(m.analyse_infor, "\n");


    strcat(m.analyse_infor, "protocol:");
    //https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml 有哪些协议细看
    switch (ip_protocol->proto) {
    case 6:
        strcat(m.analyse_infor, "tcp(6)");
        tcp_protocol_packet_handle(packet_header, packet_content, header_length, tlen, m);
        break;
    case 17:
        strcat(m.analyse_infor, "udp(17)");
        udp_protocol_packet_handle(packet_header, packet_content, header_length, m);
        break;
    case 1:
        strcat(m.analyse_infor, "icmp(1)");
        icmp_protocol_packet_handle(packet_header, packet_content, m);
        break;
    case 41:
        strcat(m.analyse_infor, "ENCAP(41) ipv6 packet, The Rest is still in progress.......\n");
        strcat(m.protocalType, "unkonwn");
    default:
        strcat(m.analyse_infor, "The detailed information is still in progress.......\n");
        strcat(m.protocalType, "unkonwn");
        break;
    }

}


void ethernet_protocol_packet_handle(
    const struct pcap_pkthdr* packet_header,
    const u_char* packet_content,
    struct message &m
) {
    u_short ethernet_type;        // 以太网类型
    struct ether_header* ethernet_protocol;        // 以太网协议变量
    u_char* mac_string;            // 以太网地址

    ethernet_protocol = (struct ether_header*)packet_content;        // 获取以太网数据内容
    ethernet_type = ntohs(ethernet_protocol->ether_type);    // 获取以太网类型
    char layer[24] = "Ethernet layer:\n";
    strcat(m.analyse_infor, layer);

    //printf("    %04x\n", ethernet_type);
    char ethernet_type_char[64] = "";


    switch(ethernet_type) {
    case 0x0800:
        //printf("The network layer is IP protocol\n");
        sprintf(ethernet_type_char, "ethernet_type:0x%04x\nThe network layer is IPv4 protocol\n", ethernet_type);
        break;
    case 0x0806:
        //printf("The network layer is ARP protocol\n");
        sprintf(ethernet_type_char, "ethernet_type:0x%04x\nThe network layer is ARP protocol\n", ethernet_type);
        break;
    case 0x86dd:
        sprintf(ethernet_type_char, "ethernet_type:0x%04x\nThe is IPv6 protocol\n", ethernet_type);
        break;
    case 0x8644:
        sprintf(ethernet_type_char, "ethernet_type:%04x\nThe is ppoE protocol\n", ethernet_type);
        break;
    default:
        sprintf(ethernet_type_char, "ethernet_type:%04x\nThis programme is not support it for now\n", ethernet_type);
        break;
    }

    strcat(m.analyse_infor, ethernet_type_char);

// 获取以太网源地址
//    printf("MAC Source Address is : \n");
    strcat(m.analyse_infor, "Mac Source address is: ");
    mac_string = ethernet_protocol->ether_shost;
    char source_mac[64] = "";
    sprintf(source_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n", 
        *mac_string,
        *(mac_string + 1),
        *(mac_string + 2),
        *(mac_string + 3),
        *(mac_string + 4),
        *(mac_string + 5));
    strcat(m.analyse_infor, source_mac);

    // 获取以太网目的地址
//    printf("MAC Target Address is : \n");
    strcat(m.analyse_infor, "Mac Target address is: ");
    mac_string = ethernet_protocol->ether_dhost;
    char destiny_mac[64] = "";
    sprintf(destiny_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",
        *mac_string,
        *(mac_string + 1),
        *(mac_string + 2),
        *(mac_string + 3),
        *(mac_string + 4),
        *(mac_string + 5));
    strcat(m.analyse_infor, destiny_mac);


    switch (ethernet_type) {
    case 0x0800:
        ip_protocol_packet_handle(packet_header, packet_content, m);
        break;
    case 0x0806:
        arp_protocol_packet_handle(packet_header, packet_content, m);
        break;
    case 0x86dd:
        ipv6_protocol_packet_handle(packet_header, packet_content, m);
        break;
    default:
        m.couldBeJudged = false;
        strcat(m.source, source_mac);
        strcat(m.destiny, destiny_mac);
        strcat(m.protocalType, "unknown");
        strcat(m.analyse_infor, "The Rest is still in progress.......");
        break;
    }
}