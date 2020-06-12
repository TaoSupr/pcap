//#ifdef _MSC_VER
///*
// * we do not want the warnings about the old deprecated and unsecure CRT functions
// * since these examples can be compiled under *nix as well
// */
//#define _CRT_SECURE_NO_WARNINGS
//#endif // _MSC_VER
//
//#define WIN32
//#pragma comment (lib, "ws2_32.lib")  //load ws2_32.dll
//#include <iostream>
//#include "pcap.h"
//#include<winsock.h>
//
//
//using namespace std;
//
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//
//int main()
//{
//	pcap_if_t *alldevs;
//	pcap_if_t *d;
//	int inum;
//	int pktnum;
//	int i = 0;
//	pcap_t *adhandle;
//	char errbuf[PCAP_ERRBUF_SIZE];
//
//	
//	if (pcap_findalldevs(&alldevs, errbuf) == -1)
//	{
//		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
//		exit(1);
//	}
//
//
//	for (d = alldevs; d; d = d->next)
//	{
//		cout << ++i << "." << d->name;
//		if (d->description)
//			cout << d->description << endl;
//		else
//			cout << " (No description available)\n";
//	}
//
//	if (i == 0)
//	{
//		cout << "\nNo interfaces found! Make sure WinPcap is installed.\n";
//		return -1;
//	}
//
//	cout << "Enter the interface number (1-" << i << "): ";
//	cin >> inum;
//
//	if (inum < 1 || inum > i)
//	{
//		cout << "\nInterface number out of range.\n";
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//	
//	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
//	
//	if ((adhandle = pcap_open_live(d->name,	// name of the device
//												65536,			// portion of the packet to capture. 
//																 65536 grants that the whole packet will be captured on all the MACs.
//												1,				// promiscuous mode (nonzero means promiscuous)
//												1000,			// read timeout
//												errbuf			// error buffer
//											)) == NULL)
//	{
//		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//		cout << "\nlistening on " << d->description << endl;
//
//		pcap_freealldevs(alldevs);
//
//		cout << "please input the num of packets you want to catch(0 for keeping catching): ";
//		cin >> inum;
//	
//		pcap_loop(adhandle, inum, packet_handler, NULL);
//
//		return 0;
//}
//
//
//
//void packet_handler(u_char *param, const struct pcap_pkthdr* header, const u_char *pkt_data)
//{
//	struct tm *ltime;
//	char timestr[16];
//	time_t local_tv_sec;
//
//	/* convert the timestamp to readable format */
//	local_tv_sec = header->ts.tv_sec;
//	ltime = localtime(&local_tv_sec);
//	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//
//	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//}
