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
//	/* 不用关心掩码，在这个过滤器中，它不会被使用 */
//	netmask = 0xffffff;
//
//	// 编译过滤器
//	if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) < 0)
//	{
//		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
//		/* 释放设备列表 */
//		return;
//	}
//
//	//设置过滤器
//	if (pcap_setfilter(adhandle, &fcode) < 0)
//	{
//		fprintf(stderr, "\nError setting the filter.\n");
//		pcap_close(adhandle);
//		/* 释放设备列表 */
//		return;
//	}
//
//	/* 将接口设置为统计模式 */
//	if (pcap_setmode(adhandle, MODE_STAT) < 0)
//	{
//		fprintf(stderr, "\nError setting the mode.\n");
//		pcap_close(adhandle);
//		/* 释放设备列表 */
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
//	/* 以毫秒计算上一次采样的延迟时间 */
//	/* 这个值通过采样到的时间戳获得 */
//	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
//	/* 获取每秒的比特数b/s */
//	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
//	/*																			^      ^
//																			    |      |
//																				|      |
//																				|      |
//													 将字节转换成比特 -- |
//																						|
//														   延时是以毫秒表示的 --
//	*/
//
//	/* 得到每秒的数据包数量 */
//	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));
//
//	/* 将时间戳转化为可识别的格式 */
//	local_tv_sec = header->ts.tv_sec;
//	ltime = localtime(&local_tv_sec);
//	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//
//	/* 打印时间戳*/
//	printf("%s ", timestr);
//
//	/* 打印采样结果 */
//	printf("BPS=%I64u ", Bps.QuadPart);
//	printf("PPS=%I64u\n", Pps.QuadPart);
//
//	//存储当前的时间戳
//	old_ts->tv_sec = header->ts.tv_sec;
//	old_ts->tv_usec = header->ts.tv_usec;
//}