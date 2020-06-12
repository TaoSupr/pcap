//#include "pac_ana.h"
//
//int main()
//{
//	pcap_if_t *alldevs;
//	pcap_if_t *d;
//	int inum;
//	int i = 0;
//	int pktnum;
//	pcap_t *adhandle;
//	char errbuf[PCAP_ERRBUF_SIZE];
//	u_int netmask;
//	struct bpf_program fcode;
//	struct timeval st_ts;
//
//	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
//	{
//		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
//		exit(1);
//	}
//
//	for (d = alldevs; d; d = d->next)
//	{
//		printf("%d. %s", ++i, d->name);
//		if (d->description)
//		{
//			printf(" (%s)\n", d->description);
//		}
//		else
//		{
//			printf(" (No description available)\n");
//		}
//	}
//
//	if (i == 0)
//	{
//		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
//		return -1;
//	}
//
//	printf("Enter the interface number (1-%d):", i);
//	scanf("%d", &inum);
//
//	if (inum < 1 || inum > i)
//	{
//		printf("\nInterface number out of range.\n");
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
//
//
//	if ((adhandle = pcap_open_live(d->name,	// name of the device
//		65536,			// portion of the packet to capture. 
//					   // 65536 grants that the whole packet will be captured on all the MACs.
//		1,				// promiscuous mode (nonzero means promiscuous)
//		1000,			// read timeout
//		errbuf			// error buffer
//	)) == NULL)
//	{
//		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//	printf("\nlistening on %s...\n", d->description);
//
//	pcap_freealldevs(alldevs);
//
//	/* ���ù������룬������������У������ᱻʹ�� */
//	netmask = 0xffffff;
//
//	// ���������
//	if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) < 0)
//	{
//		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
//		/* �ͷ��豸�б� */
//		return;
//	}
//
//	//���ù�����
//	if (pcap_setfilter(adhandle, &fcode) < 0)
//	{
//		fprintf(stderr, "\nError setting the filter.\n");
//		pcap_close(adhandle);
//		/* �ͷ��豸�б� */
//		return;
//	}
//
//	/* ���ӿ�����Ϊͳ��ģʽ */
//	if (pcap_setmode(adhandle, MODE_STAT) < 0)
//	{
//		fprintf(stderr, "\nError setting the mode.\n");
//		pcap_close(adhandle);
//		/* �ͷ��豸�б� */
//		return;
//	}
//
//	printf("\nintput the num of packets you want to catch(0 for keep catching): ");
//	scanf_s("%d", &pktnum);
//
//	pcap_loop(adhandle, pktnum, packet_handler, (PUCHAR)&st_ts);
//	pcap_close(adhandle);
//
//	getchar();
//	return 0;
//}
//
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//	struct timeval *old_ts = (struct timeval *)param;
//	u_int delay;
//	LARGE_INTEGER Bps, Pps;
//	struct tm *ltime;
//	char timestr[16];
//	time_t local_tv_sec;
//
//	/* �Ժ��������һ�β������ӳ�ʱ�� */
//	/* ���ֵͨ����������ʱ������ */
//	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
//	/* ��ȡÿ��ı�����b/s */
//	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
//	/*																			^      ^
//																			    |      |
//																				|      |
//																				|      |
//													 ���ֽ�ת���ɱ��� -- |
//																						|
//														   ��ʱ���Ժ����ʾ�� --
//	*/
//
//	/* �õ�ÿ������ݰ����� */
//	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));
//
//	/* ��ʱ���ת��Ϊ��ʶ��ĸ�ʽ */
//	local_tv_sec = header->ts.tv_sec;
//	ltime = localtime(&local_tv_sec);
//	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//
//	/* ��ӡʱ���*/
//	printf("%s ", timestr);
//
//	/* ��ӡ������� */
//	printf("BPS=%I64u ", Bps.QuadPart);
//	printf("PPS=%I64u\n", Pps.QuadPart);
//
//	//�洢��ǰ��ʱ���
//	old_ts->tv_sec = header->ts.tv_sec;
//	old_ts->tv_usec = header->ts.tv_usec;
//}