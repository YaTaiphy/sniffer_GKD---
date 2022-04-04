/* write by Lai, 2021E8018682138, 2022.4.2*/
#pragma once
#include <stdio.h>
#include <iostream>
#define HAVE_REMOTE
#include "pcap.h"

using namespace std;


// ��̫��Э���ʽ�Ķ���
typedef struct ether_header {
    u_char ether_dhost[6];        // Ŀ���ַ
    u_char ether_shost[6];        // Դ��ַ
    u_short ether_type;            // ��̫������
}ether_header;

// �û�����4�ֽڵ�IP��ַ
typedef struct ipv4_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ipv4_address;

typedef struct ipv6_address {
    u_short add1;
    u_short add2;
    u_short add3;
    u_short add4;
    u_short add5;
    u_short add6;
    u_short add7;
    u_short add8;
}ipv6_address;

// ���ڱ���IPV4���ײ�
typedef struct ipv4_header {
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service 
    u_short tlen;			// Total length 
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    ipv4_address	saddr;		// Source address
    ipv4_address	daddr;		// Destination address
    u_int	op_pad;			// Option + Padding
}ipv4_header;

/* IPv6 header */
typedef struct ipv6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    u_short length;
    u_char  next_header;
    u_char  hop_limit;
    ipv6_address saddr;
    ipv6_address daddr;
} ipv6_header;

// ����TCP�ײ�
typedef struct tcp_header {
    u_short sport;        //Դ�˿�
    u_short dport;        //Ŀ�Ķ˿�
    u_int sequence;        // ������
    u_int ack;            // �ظ���

    u_short dataOffset_reserve_sign; //4λoffset��3λ������URG + ACK + PSH + RST + SYN + FIN
    u_short windows;            // ���ڴ�С
    u_short checksum;            // У���
    u_short urgent_pointer;        // ����ָ��
}tcp_header;

typedef struct udp_header {
    u_short sport;            // Դ�˿�
    u_short dport;            // Ŀ��˿�
    u_short len;			// Datagram length
    u_short crc;			// Checksum
}udp_header;

typedef struct icmp_header {
    u_char type;                // ICMP����
    u_char code;                // ����
    u_short checksum;            // У���
    //���沿����icmpЭ�����ݣ��кܶ࣬��Ҫ���ݲ�ͬ��������з���
    //https://zh.wikipedia.org/wiki/%E4%BA%92%E8%81%94%E7%BD%91%E6%8E%A7%E5%88%B6%E6%B6%88%E6%81%AF%E5%8D%8F%E8%AE%AE
    //����ķ�����ʱ�������ˡ�
}icmp_header;

typedef struct arp_header {
    u_short arp_hardware_type;
    u_short arp_protocol_type;
    u_char arp_hardware_length;
    u_char arp_protocol_length;
    u_short arp_operation_code;
    u_char arp_source_ethernet_address[6];
    u_char arp_source_ip_address[4];
    u_char arp_destination_ethernet_address[6];
    u_char arp_destination_ip_address[4];
}arp_header;