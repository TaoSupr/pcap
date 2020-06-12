#include "pac_ana.h"

using namespace std;

/*ip counter*/
std::map<std::string, int> counter;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	int pktnum;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask = 0xffffff;;
	struct bpf_program fcode;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	for (d = alldevs; d; d = d->next)
	{
		cout << ++i << "." << d->name;
		if (d->description)
			cout << d->description << endl;
		else
			cout << " (No description available)" << endl;
	}

	if (i == 0)
	{
		cout << "\nNo interfaces found! Make sure WinPcap is installed." << endl;
		return -1;
	}

	cout << "Enter the interface number (1-" << i << "): ";
	cin >> inum;

	if (inum < 1 || inum > i)
	{
		cout << "\nInterface number out of range." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}


	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open_live(d->name,	// name of the device
												65536,			// portion of the packet to capture. 
																// 65536 grants that the whole packet will be captured on all the MACs.
												1,				// promiscuous mode (nonzero means promiscuous)
												1000,			// read timeout
												errbuf			// error buffer
												)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << "listening on " << d->description << "...." << endl;

	pcap_freealldevs(alldevs);

	if (pcap_compile(adhandle, &fcode, "ip or arp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_close(adhandle);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_close(adhandle);
		return -1;
	}


	//if (pcap_setmode(adhandle, MODE_STAT) < 0)
	//{
	//	fprintf(stderr, "\nError setting the mode.\n");
	//	pcap_close(adhandle);
	//	return;
	//}

	cout << "please input the num of packets you want to catch(0 for keeping catching): ";
	cin >> pktnum;
	cout << endl;
	pcap_loop(adhandle, pktnum, packet_handler, NULL);
	pcap_close(adhandle);

	getchar();
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	cout << B_DIVISION << "time:" << timestr << ","
		<< header->ts.tv_usec << "  len:" << header->len << B_DIVISION<<endl;
	ethernet_package_handler(param, header, pkt_data);
}

void ethernet_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ethernet_header* eh = (ethernet_header*)pkt_data;
	cout << DIVISION << "��̫��Э������ṹ" << DIVISION << endl;
	u_short type = ntohs(eh->type);
	cout << "���ͣ�" << type;
	switch (type)
	{
	case 0x0800:
		cout << " (IP)" << endl;
		break;
	case 0x0806:
		cout << " (ARP)" << endl;
		break;
	case 0x0835:
		cout << " (RARP)" << endl;
	default:
		break;
	}
	cout << "Ŀ�ĵ�ַ��" << int(eh->des_mac_addr.byte1) << ":"
		<< int(eh->des_mac_addr.byte2) << ":"
		<< int(eh->des_mac_addr.byte3) << ":"
		<< int(eh->des_mac_addr.byte4) << ":"
		<< int(eh->des_mac_addr.byte5) << ":"
		<< int(eh->des_mac_addr.byte6) << endl;
	cout << "Դ��ַ��" << int(eh->src_mac_addr.byte1) << ":"
		<< int(eh->src_mac_addr.byte2) << ":"
		<< int(eh->src_mac_addr.byte3) << ":"
		<< int(eh->src_mac_addr.byte4) << ":"
		<< int(eh->src_mac_addr.byte5) << ":"
		<< int(eh->src_mac_addr.byte6) << endl;
	switch (type)
	{
	case 0x0800:
		ip_package_handler(param, header, pkt_data);
		break;
	case 0x0806:
		arp_package_handler(param, header, pkt_data);
		break;
	default:
		break;
	}
	cout << endl << endl;
}

void arp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	arp_header* ah;
	ah = (arp_header*)(pkt_data + 14);
	cout << DIVISION << "ARPЭ������ṹ" << DIVISION << endl;
	u_short operation_code = ntohs(ah->operation_code);
	cout << "Ӳ�����ͣ�" << ntohs(ah->hardware_type) << endl;
	cout << "Э�����ͣ�" << ntohs(ah->protocol_type) << endl;
	cout << "Ӳ����ַ���ȣ�" << ah->hardware_length << endl;
	cout << "Э���ַ���ȣ�" << ah->protocol_length << endl;
	switch (operation_code)
	{
	case 1:
		cout << "ARP����Э��" << endl;
		break;
	case 2:
		cout << "ARPӦ��Э��" << endl;
		break;
	case 3:
		cout << "ARP����Э��" << endl;
		break;
	case 4:
		cout << "RARPӦ��Э��" << endl;
		break;
	default:
		break;
	}
	cout << "ԴIP��ַ��"
		<< int(ah->source_ip_addr.byte1) << "."
		<< int(ah->source_ip_addr.byte2) << "."
		<< int(ah->source_ip_addr.byte3) << "."
		<< int(ah->source_ip_addr.byte4) << endl;

	cout << "Ŀ��IP��ַ��"
		<< int(ah->des_ip_addr.byte1) << "."
		<< int(ah->des_ip_addr.byte2) << "."
		<< int(ah->des_ip_addr.byte3) << "."
		<< int(ah->des_ip_addr.byte4) << endl;

	add_to_map(counter, ah->source_ip_addr);
	print_map(counter);
}

void ip_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header *ih;
	ih = (ip_header *)(pkt_data + 14); //14 measn the length of ethernet header
	cout << DIVISION << "IPЭ������ṹ" << DIVISION << endl;
	cout << "�汾�ţ�" << ((ih->ver_ihl & 0xf0) >> 4) << endl;
	cout << "�ײ����ȣ�" << (ih->ver_ihl & 0xf) << "("
		<< ((ih->ver_ihl & 0xf)<<2) << "B)" << endl;
	cout << "�������" << int(ih->tos) << endl;
	cout << "�ܳ��ȣ�" << ntohs(ih->tlen) << endl;
	cout << "��ʶ��" << ntohs(ih->identification) << endl;
	cout << "��־��" << ((ih->flags_fo & 0xE000) >> 12) << endl;
	cout << "Ƭƫ�ƣ�" <<  (ih->flags_fo & 0x1FFF) << "("
		<< ((ih->flags_fo & 0x1FFF) << 3) << "B)" <<endl;
	cout << "�������ڣ�" << int(ih->ttl) << endl;
	cout << "Э�飺";
	switch (ih->proto)
	{
		case 6:
			cout << "TCP" << endl;
			break;
		case 17:
			cout << "UDP" << endl;
			break;
		case 1:
			cout << "ICMP" << endl;
			break;
		default:
			cout <<  endl;
			break;
	}
	cout << "У��ͣ�" << ntohs(ih->checksum) << endl;
	cout << "ԴIP��ַ��" 
		<< int(ih->src_ip_addr.byte1) << "."
		<< int(ih->src_ip_addr.byte2) << "."
		<< int(ih->src_ip_addr.byte3) << "."
		<< int(ih->src_ip_addr.byte4) <<  endl;

	cout << "Ŀ��IP��ַ��" 
		<< int(ih->des_ip_addr.byte1) << "."
		<< int(ih->des_ip_addr.byte2) << "."
		<< int(ih->des_ip_addr.byte3) << "."
		<< int(ih->des_ip_addr.byte4) << endl;
	switch (ih->proto)
	{
		case 6:
			tcp_package_handler(param, header, pkt_data);
			break;
		case 17:
			udp_package_handler(param, header, pkt_data);
			break;
		case 1:
			icmp_package_handler(param, header, pkt_data);
			break;
		default:
			break;
	}
	add_to_map(counter, ih->src_ip_addr);
	print_map(counter);
}


void udp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	udp_header *uh;
	uh = (udp_header *)(pkt_data + 20 + 14);
	cout << DIVISION << "UDPЭ������ṹ" << DIVISION << endl;
	cout << "Դ�˿ڣ�" << ntohs(uh->sport) << endl;
	cout << "Ŀ�Ķ˿ڣ�" << ntohs(uh->dport) << endl;
	cout << "���ȣ�" << ntohs(uh->len) << endl;
	cout << "����ͣ�" << ntohs(uh->checksum) << endl;
}


void tcp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	tcp_header* th;
	th = (tcp_header*)(pkt_data + 14 + 20);
	cout << DIVISION << "TCPЭ������ṹ" << DIVISION << endl;
	cout << "Դ�˿ڣ�" <<  ntohs(th->sport) << endl;
	cout << "Ŀ�Ķ˿ڣ�" << ntohs(th->dport) << endl;
	cout << "��ţ�" << ntohl(th->sequence) << endl;
	cout << "ȷ�Ϻţ�" << ntohl(th->acknowledgement) << endl;
	cout << "����ƫ�ƣ�" << ((th->offset & 0xf0) >> 4) << "("
		<< ((th->offset & 0xf0) >> 2) << "B)"<< endl;
	cout << "��־��" ;
	if (th->flags & 0x01) 
	{
		cout << "FIN ";
	}
	if (th->flags & 0x02) 
	{
		cout << "SYN ";
	}
	if (th->flags & 0x04)
	{
		cout << "RST ";
	}
	if (th->flags & 0x08)
	{
		cout << "PSH ";
	}
	if (th->flags & 0x10)
	{
		cout << "ACK ";
	}
	if (th->flags & 0x20)
	{
		cout << "URG ";
	}
	cout << endl;
	cout << "���ڣ�" << ntohs(th->windows) << endl;
	cout << "����ͣ�" << ntohs(th->checksum) << endl;
	cout << "����ָ�룺" << ntohs(th->urgent_pointer) << endl;
}


void icmp_package_handler(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	icmp_header* ih;
	ih = (icmp_header*)(pkt_data + 14 + 20);
	cout << DIVISION << "ICMPЭ������ṹ" << DIVISION << endl;
	cout << "ICMP���ͣ�" << ih->type;
	switch (ih->type)
	{
	case 8:
		cout << "ICMP��������Э��" << endl;
		break;
	case 0:
		cout << "ICMP����Ӧ��Э��" << endl;
		break;
	default:
		break;
	}
	cout << "ICMP���룺" << ih->code << endl;
	cout << "��ʶ����" << ih->id << endl;
	cout << "�����룺" << ih->sequence << endl;
	cout << "ICMPУ��ͣ�" << ntohs(ih->checksum) << endl;
}

void add_to_map(map<string, int> &counter, ip_address ip) 
{
	string ip_string;
	int amount = 0;
	map<string,int>::iterator iter;
	ip_string = to_string(ip.byte1) + "."
					+ to_string(ip.byte2) + "."
					+ to_string(ip.byte3) + "."
					+ to_string(ip.byte4);
	iter = counter.find(ip_string);
	if (iter != counter.end())
	{
		amount = iter->second;
	}
	counter.insert_or_assign(ip_string, ++amount);
}

void print_map(map<string, int> counter)
{
	map<string, int>::iterator iter;
	cout << DIVISION << "����ͳ��" << DIVISION << endl;
	cout << "IP" << setw(45) << "����" << endl;
	for (iter = counter.begin(); iter != counter.end(); iter++)
	{
		cout << iter->first  << setfill('.') << setw(45-iter->first.length()) << iter->second<<endl;
	}
}