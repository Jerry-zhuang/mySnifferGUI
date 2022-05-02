#pragma warning(disable:4996)
#include "mySnifferCMD.h"

using namespace std;

/* 将数字类型的IP地址转换成字符串类型的 */
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}


#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef _WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */


/**
 * @brief 获取网络适配器列表的函数
 * @return 网络适配器列表
*/
pcap_if_t* getDeviceList()
{
	pcap_if_t* alldevs;	/*所有网络适配器*/
	pcap_if_t* d;	/*指向网络适配器的指针*/
	pcap_addr_t* a;	/*指向地址信息的指针*/
	bpf_u_int32 net_ip;
	struct in_addr net_ip_address;
	bpf_u_int32 net_mask;
	struct in_addr net_mask_address;

	int i = 0;	/*适配器数量*/
	char ip6str[128];
	char errbuf[PCAP_ERRBUF_SIZE];

	/*获取网络适配器列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
		exit(1);
	}

	/*打印网络适配器*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		i++;
		cout << "ID: " << i << endl;
		cout << "NAME: " << d->name << endl;
		if (d->description)
			cout << "DESCRIPTION: " << d->description << endl;
		cout << "ADDRESS:" << endl;
		for (a = d->addresses; a; a = a->next)
		{
			switch (a->addr->sa_family)
			{
			case AF_INET:
				cout << "Address Family: #" << a->addr->sa_family << endl;
				cout << "\tAddress Family Name: AF_INET" << endl;
				if (a->addr)
					cout << "\tAddress: " << iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr) << endl;
				/*if (a->netmask)
					cout << "\tNetmask: " << iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr) << endl;
				if (a->broadaddr)
					cout << "\tBroadcast Address: " << iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr) << endl;
				if (a->dstaddr)
					cout << "\tDestination Address: " << iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr) << endl;*/
				break;
			case AF_INET6:
				/*cout << "\tAddress Family Name: AF_INET6" << endl;
				if (a->addr)
					printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));*/
				break;
			default:
				cout << "\tAddress Family Name: Unknown" << endl;
				break;
			}

		}
	}

	return alldevs;
	// pcap_freealldevs(alldevs);
}

/**
 * @brief 打开指定的网卡
 * @param inum 网卡的id
 * @param allAdapters 指向所有网卡的指针
 * @return 打开的网卡
*/
pcap_t* openAdapter(int inum = NULL, pcap_if_t* allAdapters = NULL) {
	// 参数
	pcap_if_t* d;
	pcap_t* fp;		// 要打开的网卡
	char errbuf[PCAP_ERRBUF_SIZE];		// 错误信息

	// 如果没有传入网卡信息，则获取网卡列表
	if (allAdapters == NULL) {
		allAdapters = getDeviceList();
	}

	// 如果参数没有传入网卡id，则让用户通过命令行输入
	if (inum == NULL) {
		cout << "请输入选取的网卡ID：" << endl;
		cin >> inum;
	}

	// 将d指针指向选择的网卡
	int i = 0;	// 计数器
	for (d = allAdapters; d != NULL && i < inum - 1; d = d->next, i++);
	if (d == NULL || inum < 1) {
		cerr << "[ERROR] 输入的ID有误，请重新执行程序!" << endl;
		// return -1;
		exit(-1);
	}

	// 打开网卡
	if ((fp = pcap_open_live(d->name,	// 网卡的名称
		65536,							// MAC数据报的长度为65536
		1,
		1000,							// 超时时限
		errbuf							// 错误
	)) == NULL) {
		cerr << "[ERROR] 无法启动网卡！" << endl;
		// return -1;
		exit(-1);
	}

	return fp;
}

/**
 * @brief 获取原始数据包
 * @param fp 打开的网卡
*/
const u_char* getPackets(pcap_t* fp, int &res) {

	//// 参数
	//pcap_if_t* d;
	//pcap_t* fp;		// 要打开的网卡
	//struct pcap_pkthdr* header;
	//const u_char* pkt_data;
	//int res;
	//char errbuf[PCAP_ERRBUF_SIZE];		// 错误信息
	//
	//// 如果没有传入网卡信息，则获取网卡列表
	//if (allAdapters == NULL) {
	//	allAdapters = getDeviceList();
	//}

	//// 如果参数没有传入网卡id，则让用户通过命令行输入
	//if (inum == NULL) {
	//	cout << "请输入选取的网卡ID：" << endl;
	//	cin >> inum;
	//}

	//// 将d指针指向选择的网卡
	//int i = 0;	// 计数器
	//for (d = allAdapters; d != NULL && i < inum-1; d = d->next, i++);
	//if (d == NULL || inum < 1) {
	//	cerr << "[ERROR] 输入的ID有误，请重新执行程序!" << endl;
	//	return -1;
	//}

	//// 打开网卡
	//if ((fp = pcap_open_live(d->name,	// 网卡的名称
	//	65536,							// MAC数据报的长度为65536
	//	1,
	//	1000,							// 超时时限
	//	errbuf							// 错误
	//)) == NULL) {
	//	cerr << "[ERROR] 无法启动网卡！" << endl;
	//	return -1;
	//}

	// 参数
	const u_char* pkt_data;
	struct pcap_pkthdr* header;

	// 读取数据报，并返回数据
	res = pcap_next_ex(fp, &header, &pkt_data);
	return pkt_data;
	// 循环读取数据报
	//while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
	//	if (res == 0) {
	//		// 超时跳过
	//		continue;
	//	}

	//	// 将时间戳转为时间，并输出
	//	time_t local_tv_sec = header->ts.tv_sec;
	//	struct tm* ltime = localtime(&local_tv_sec);
	//	char timestr[16];
	//	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	//	cout << timestr << " " << header->ts.tv_usec << " 长度: " << header->len << endl;
	//	// cout << header->ts.tv_sec << ":" << header->ts.tv_usec << " " << header->len << endl;



	//	// 输出数据报
	//	for (int i = 1; (i < header->caplen + 1); i++) {
	//		// cout << setw(2) << setfill('0') << setbase(16) << (u_int)pkt_data[i - 1] << " ";
	//		printf("%.2x ", pkt_data[i - 1]);
	//		if ((i % 16) == 0)	// 一行输出16个
	//			cout << endl;
	//	}

	//	cout << endl << endl;
	//}

	//if (res == -1) {
	//	cout << "[ERROR] 无法读取该数据报：" << pcap_geterr(fp) << endl;
	//	return -1;
	//}

	//// 关闭网卡
	//pcap_close(fp);
}

/**
 * @brief 打印数据链路层
 * @param packetData 二进制数据包
*/
void PrintEtherHeader(const u_char* packetData)
{
	typedef struct ether_header {
		u_char ether_dhost[6];    // 目标地址
		u_char ether_shost[6];    // 源地址
		u_short ether_type;       // 以太网类型
	} ether_header;

	struct ether_header* eth_protocol;
	eth_protocol = (struct ether_header*)packetData;

	u_short ether_type = ntohs(eth_protocol->ether_type);  // 以太网类型
	u_char* ether_src = eth_protocol->ether_shost;         // 以太网原始MAC地址
	u_char* ether_dst = eth_protocol->ether_dhost;         // 以太网目标MAC地址

	printf("类型: 0x%x \t", ether_type);
	printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

/**
 * @brief 打印IP数据包
 * @param packetData 二进制数据包
*/
void PrintIPHeader(const u_char* packetData)
{
	typedef struct ip_header
	{
		char version : 4;
		char headerlength : 4;
		char cTOS;
		unsigned short totla_length;
		unsigned short identification;
		unsigned short flags_offset;
		char time_to_live;
		char Protocol;
		unsigned short check_sum;
		unsigned int SrcAddr;
		unsigned int DstAddr;
	}ip_header;

	struct ip_header* ip_protocol;

	// +14 跳过数据链路层
	ip_protocol = (struct ip_header*)(packetData + 14);
	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

	u_short check_sum = ntohs(ip_protocol->check_sum);
	int ttl = ip_protocol->time_to_live;
	int proto = ip_protocol->Protocol;

	Src_Addr.sin_addr.s_addr = ip_protocol->SrcAddr;
	Dst_Addr.sin_addr.s_addr = ip_protocol->DstAddr;

	printf("源地址: %15s --> ", inet_ntoa(Src_Addr.sin_addr));
	printf("目标地址: %15s --> ", inet_ntoa(Dst_Addr.sin_addr));

	printf("校验和: %5X --> TTL: %4d --> 协议类型: ", check_sum, ttl);
	switch (ip_protocol->Protocol)
	{
	case 1: printf("ICMP \n"); break;
	case 2: printf("IGMP \n"); break;
	case 6: printf("TCP \n");  break;
	case 17: printf("UDP \n"); break;
	case 89: printf("OSPF \n"); break;
	default: printf("None \n"); break;
	}
}

/**
 * @brief 打印TCP数据包
 * @param packetData 二进制数据包
*/
void PrintTCPHeader(const unsigned char* packetData)
{
	typedef struct tcp_header
	{
		short SourPort;                 // 源端口号16bit
		short DestPort;                 // 目的端口号16bit
		unsigned int SequNum;           // 序列号32bit
		unsigned int AcknowledgeNum;    // 确认号32bit
		unsigned char reserved : 4, offset : 4; // 预留偏移

		unsigned char  flags;               // 标志 

		short WindowSize;               // 窗口大小16bit
		short CheckSum;                 // 检验和16bit
		short surgentPointer;           // 紧急数据偏移量16bit
	}tcp_header;

	struct tcp_header* tcp_protocol;
	// +14 跳过数据链路层 +20 跳过IP层
	tcp_protocol = (struct tcp_header*)(packetData + 14 + 20);

	u_short sport = ntohs(tcp_protocol->SourPort);
	u_short dport = ntohs(tcp_protocol->DestPort);
	int window = tcp_protocol->WindowSize;
	int flags = tcp_protocol->flags;

	printf("源端口: %6d --> 目标端口: %6d --> 窗口大小: %7d --> 标志: (%d)",
		sport, dport, window, flags);

	if (flags & 0x08) printf("PSH 数据传输\n");
	else if (flags & 0x10) printf("ACK 响应\n");
	else if (flags & 0x02) printf("SYN 建立连接\n");
	else if (flags & 0x20) printf("URG \n");
	else if (flags & 0x01) printf("FIN 关闭连接\n");
	else if (flags & 0x04) printf("RST 连接重置\n");
	else printf("None 未知\n");
}


//int main() {
//	struct pcap_pkthdr* header;
//	int res;
//	pcap_t *fp = openAdapter();
//	const u_char* pkt_data = NULL;
//	//PrintEtherHeader(pkt_data);
//	//PrintIPHeader(pkt_data);
//	//PrintTCPHeader(pkt_data);
//
//	// 循环读取数据报
//	while ((pkt_data = getPackets(fp, res)) >= 0) {
//		if (res == 0) {
//			// 超时跳过
//			continue;
//		}
//
//		// 将时间戳转为时间，并输出
//		//time_t local_tv_sec = header->ts.tv_sec;
//		//struct tm* ltime = localtime(&local_tv_sec);
//		//char timestr[16];
//		//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//		//cout << timestr << " " << header->ts.tv_usec << " 长度: " << header->len << endl;
//		//// cout << header->ts.tv_sec << ":" << header->ts.tv_usec << " " << header->len << endl;
//
//		PrintEtherHeader(pkt_data);
//		PrintIPHeader(pkt_data);
//		PrintTCPHeader(pkt_data);
//
//		// 输出数据报
//		//for (int i = 1; (i < header->caplen + 1); i++) {
//		//	// cout << setw(2) << setfill('0') << setbase(16) << (u_int)pkt_data[i - 1] << " ";
//		//	printf("%.2x ", pkt_data[i - 1]);
//		//	if ((i % 16) == 0)	// 一行输出16个
//		//		cout << endl;
//		//}
//
//		cout << endl << endl;
//	}
//
//	if (res == -1) {
//		cout << "[ERROR] 无法读取该数据报：" << pcap_geterr(fp) << endl;
//		return -1;
//	}
//
//	// 关闭网卡
//	pcap_close(fp);
//	return 0;
//}