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
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*8 bytes MAC addresss*/
typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

/*ethernet header*/
typedef struct ethernet_header
{
	mac_address des_mac_addr;
	mac_address src_mac_addr;
	u_short type;
}ethernet_header;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short checksum;			// Header checksum
	ip_address	src_ip_addr;		// Source address
	ip_address	des_ip_addr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/*arp header*/
typedef struct arp_header
{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_length;
	u_char protocol_length;
	u_short operation_code;
	mac_address source_mac_addr;
	ip_address source_ip_addr;
	mac_address des_mac_addr;
	ip_address des_ip_addr;
}arp_header;

/*TCP header*/
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int acknowledgement;
	u_char offset;
	u_char flags;
	u_short windows;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short checksum;			// Checksum
}udp_header;

/*ICMP header*/
typedef struct icmp_header
{
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short sequence;
}icmp_header;

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

