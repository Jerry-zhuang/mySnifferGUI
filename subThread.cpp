#include "subThread.h"

/**
 * @brief 构造函数
*/
subThread::subThread()
{
	this->isDone = true;
}

subThread::~subThread()
{
}

/**
 * @brief 设置开启的网卡指针
 * @param openAdapter 网卡指针
 * @return true/false
*/
bool subThread::setOpenAdapter(pcap_t* openAdapter) {
	if (openAdapter) {
		this->openAdapter = openAdapter;
		return true;
	}
	else {
		return false;
	}
	
}

/**
 * @brief 设置isDone为false
*/
void subThread::setFlag() {
	this->isDone = false;
}

/**
 * @brief 设置isDone为true
*/
void subThread::resetFlag() {
	this->isDone = true;
}

/**
 * @brief 重写run函数
*/
void subThread::run() {
	while (true) {
		if (isDone) {
			break;
		}
		else {
			if ((pcap_next_ex(openAdapter, &header, &pkt_data)) == 0) {
				continue;
			}
			else {
				local_tv_sec = header->ts.tv_sec;
				ltime = localtime(&local_tv_sec);
				strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
				// qDebug() << timestr << " length: " << header->len << endl;
				QString info = "";
				int type = ethernetPacketHandle(pkt_data, info);
				if (type) {
					DataPacket data;
					int len = header->len;
					data.setPacketInfo(info);
					data.setDataLength(len);
					data.setTimeStamp(timestr);
					data.setPacketType(type);
					data.setPacketContent(pkt_data, len);
					emit send(data);
				}
			}
		}
	}
}

/**
 * @brief 以太网数据包处理
 * @param pkt_content 
 * @param info 
 * @return 
*/
int subThread::ethernetPacketHandle(const u_char* pkt_content, QString& info)
{
	ETHER_HEADER* ethernet;
	u_short content_type;
	ethernet = (ETHER_HEADER*)pkt_content;
	content_type = ntohs(ethernet->ether_type);
	
	switch (content_type){
	case 0x0800: {	// IP
		int ipPacket;
		int res = ipPacketHandle(pkt_content, ipPacket);
		switch (res)
		{
		case 1: {// ICMP
			info = "ICMP";
			return 2;
		}
		case 6: {// TCP
			return tcpPacketHandle(pkt_content, info, ipPacket);
		}
		case 17: {// UDP
			return udpPacketHandle(pkt_content, info);
		}
		default:
			break;
		}
		break;
	}
	case 0x806: {	// ARP
		info = arpPacketHandle(pkt_content);
		return 1;
	}
	default:
		break;
	}
	return 0;
}

/**
 * @brief IP数据包处理
 * @param pkt_content 
 * @param ipPacket 
 * @return 
*/
int subThread::ipPacketHandle(const u_char *pkt_content, int& ipPacket)
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->protocol;
	ipPacket = (ntohs(ip->total_length) - (ip->headerlength) * 4);
	return protocol;
}

/**
 * @brief TCP数据包处理
 * @param pkt_content 
 * @param info 
 * @param ipPacket 
 * @return 
*/
int subThread::tcpPacketHandle(const u_char* pkt_content, QString& info, int ipPacket)
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	u_short src = ntohs(tcp->SrcPort);
	u_short dst = ntohs(tcp->DstPort);

	QString proSend = "";
	QString proRecv = "";

	int type = 3;
	int delta = (tcp->reserved) * 4;
	int tcpLoader = ipPacket - delta;

	if (src == 443 || dst == 443) {
		if (src == 443)
			proSend = "(https)";
		else
			proRecv = "(https)";
	}
	info += QString::number(src) + proSend + "->" + QString::number(dst) + proRecv;

	QString flag = "";
	if(tcp->flags & 0x08) flag += "PSH,";
	if(tcp->flags & 0x10) flag += "ACK,";
	if(tcp->flags & 0x02) flag += "SYN,";
	if(tcp->flags & 0x20) flag += "URC,";
	if(tcp->flags & 0x01) flag += "FIN,";
	if(tcp->flags & 0x04) flag += "RST,";
	if (flag != "") {
		flag = flag.left(flag.length() - 1);
		info += "[" + flag + "]";
	}

	u_int sequence = ntohl(tcp->SequNum);
	u_int ack = ntohl(tcp->AcknowledgeNum);
	u_short window = ntohs(tcp->WindowSize);

	info += " Seq=" + QString::number(sequence) + " ACK=" + QString::number(ack) + " WIN=" + QString::number(window) + " LEN:" + QString::number(tcpLoader);

	return type;
}

/**
 * @brief UDP数据包处理
 * @param pkt_content 
 * @param info 
 * @return 
*/
int subThread::udpPacketHandle(const u_char* pkt_content, QString& info)
{
	UDP_HEADER* udp;
	udp = (UDP_HEADER*)(pkt_content + 14 + 20);
	u_short src = ntohs(udp->SrcPort);
	u_short dst = ntohs(udp->DstPort);

	if (src == 53 || dst == 53) {
		info = "DNS";
		return 5;
	}
	else {
		QString res = QString::number(src) + "->" + QString::number(dst);
		u_short data_len = ntohs(udp->len);
		res += " LEN=" + QString::number(data_len);
		info = res;
	}
	return 4;
}

/**
 * @brief ARP数据包处理
 * @param pkt_content 
 * @return 
*/
QString subThread::arpPacketHandle(const u_char* pkt_content)
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);

	u_short op = ntohs(arp->OpCode);
	QString res = "";

	u_char* dst_ip = arp->DstIp;
	QString dstIp = QString::number(*dst_ip) + "."
		+ QString::number(*(dst_ip+1)) + "."
		+ QString::number(*(dst_ip+2)) + "."
		+ QString::number(*(dst_ip+3));

	u_char* src_ip = arp->SrcIp;
	QString srcIp = QString::number(*src_ip) + "."
		+ QString::number(*(src_ip + 1)) + "."
		+ QString::number(*(src_ip + 2)) + "."
		+ QString::number(*(src_ip + 3));

	u_char* src_mac = arp->SrcMac;
	QString srcMac = byteToHex(src_mac, 1) + ":"
		+ byteToHex((src_mac+1), 1) + ":"
		+ byteToHex((src_mac+2), 1) + ":"
		+ byteToHex((src_mac+3), 1) + ":"
		+ byteToHex((src_mac+4), 1) + ":"
		+ byteToHex((src_mac+5), 1);

	if (op == 1) {
		res = "who has " + dstIp + "? Tell" + srcIp;
	}
	else if (op == 2) {
		res = srcIp + " is at " + srcMac;
	}

	return res;
}

/**
 * @brief 【工具】将Byte转为HEX String
 * @param str byte的数据
 * @param size 长度
 * @return Hex String
*/
QString subThread::byteToHex(u_char* str, int size)
{
	QString res = "";
	for (int i = 0; i < size; i++) {
		char hex1 = str[i] >> 4;
		if (hex1 >= 0x0A)
			hex1 += 0x37;
		else
			hex1 += 0x30;
		char hex2 = str[i] & 0x0F;
		if (hex2 >= 0x0A)
			hex2 += 0x37;
		else
			hex2 += 0x30;
		res.append(hex1);
		res.append(hex2);
	}
	return res;
}