#ifndef _PAC_ANA_H
#define _PAC_ANA_H

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */

#define _CRT_SECURE_NO_WARNINGS
#endif

/*set the environment head files*/
#define WIN32
#pragma comment (lib, "ws2_32.lib")  //load ws2_32.dll

/*set the C++ head files*/
#include <iostream>
#include <stdio.h>
#include <map>
#include <string>
#include <iomanip>
#include <sstream>

/*set the wpcap head files*/
#include "pcap.h"
#include <WinSock2.h>


#define DIVISION "--------------------"
#define B_DIVISION "==================="


 /* 4 bytes IP address */
typedef struct ip_address ip_address;

/*8 bytes MAC addresss*/
typedef struct mac_address mac_address;

/*ethernet header*/
typedef struct ethernet_header ethernet_header;

/* IPv4 header */
typedef struct ip_header ip_header;

/*arp header*/
typedef struct arp_header arp_header;

/*TCP header*/
typedef struct tcp_header tcp_header;

/* UDP header*/
typedef struct udp_header udp_header;

/*ICMP header*/
typedef struct icmp_header icmp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the ethernet packet*/
void ethernet_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the ip packet*/
void ip_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the arp packet*/
void arp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the udp packet*/
void udp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the tcp packet*/
void tcp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the icmp packet*/
void icmp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*count the package with c++ std::map*/
void add_to_map(std::map<std::string, int> &counter, ip_address ip);

/*print the map info*/
void print_map(std::map<std::string, int> counter);

#endif // !_PAC_ANA_H

