#include "DataPacket.h"
#include <QDebug>
/**
 * @brief ���캯��
*/
DataPacket::DataPacket()
{
	qRegisterMetaType<DataPacket>("DataPacket");
	this->dataLength = 0;
	this->timeStamp = "";
	this->information = "";
	this->packetType = 0;
}

/**
 * @brief �����ߡ���ByteתΪHEX String
 * @param str byte������
 * @param size ����
 * @return Hex String
*/
QString DataPacket::byteToHex(u_char* str, int size)
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

/**
 * @brief set���ݳ���
 * @param length ���ݳ���
*/
void DataPacket::setDataLength(unsigned int length)
{
	this->dataLength = length;
}

/**
 * @brief setʱ���
 * @param timeStamp ʱ��� 
*/
void DataPacket::setTimeStamp(QString timeStamp)
{
	this->timeStamp = timeStamp;
}

/**
 * @brief set���ݰ�����
 * @param type ���ݰ�����
*/
void DataPacket::setPacketType(int type)
{
	this->packetType = type;
}

/**
 * @brief set���ݰ�������
 * @param pkt_content ָ�����ݵ�ָ��
 * @param size ����
*/
void DataPacket::setPacketContent(const u_char* pkt_content, int size)
{
	this->pkt_content =(u_char*)malloc(size);
	memcpy((char *)(this->pkt_content), pkt_content, size);
}

/**
 * @brief set���ݰ���Ϣ
 * @param info ��Ϣ
*/
void DataPacket::setPacketInfo(QString info)
{
	this->information = info;
}

/**
 * @brief get���ݳ���
 * @return ���ݳ���
*/
QString DataPacket::getDataLength()
{
	return QString::number(this->dataLength);
}

/**
 * @brief getʱ���
 * @return ʱ���
*/
QString DataPacket::getTimeStamp()
{
	return this->timeStamp;
}

/**
 * @brief get���ݰ�����
 * @return ���ݰ�����
*/
QString DataPacket::getPacketType()
{
	switch (this->packetType){
	case 1: return "ARP";
	case 2: return "ICMP";
	case 3: return "TCP";
	case 4: return "UDP";
	case 5: return "DNS";
	case 6: return "TLS";
	case 7: return "SSL";
	default: return "";
	}
	return QString::number(this->packetType);
}

/**
 * @brief get���ݰ���Ϣ
 * @return ���ݰ���Ϣ
*/
QString DataPacket::getPacketInfo()
{
	return this->information;
}

/**
 * @brief ��ȡԴ��ַ
 * @return 
*/
QString DataPacket::getSource()
{
	if (this->packetType == 1)
		return this->getSrcMacAddr();
	else
		return this->getSrcIPAddr();
}

/**
 * @brief ��ȡĿ�ĵ�ַ
 * @return
*/
QString DataPacket::getDestination()
{
	if (this->packetType == 1)
		return this->getDstMacAddr();
	else
		return this->getDstIPAddr();
}

/**
 * @brief ��ȡԴmac��ַ
 * @return 
*/
QString DataPacket::getSrcMacAddr()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)(pkt_content);
	u_char* addr = eth->ether_shost;
	if (addr) {
		QString res = byteToHex(addr, 1) + ":"
			+ byteToHex((addr + 1), 1) + ":"
			+ byteToHex((addr + 2), 1) + ":"
			+ byteToHex((addr + 3), 1) + ":"
			+ byteToHex((addr + 4), 1) + ":"
			+ byteToHex((addr + 5), 1);
		if (res == "FF:FF:FF:FF:FF:FF")
			return "FF:FF:FF:FF:FF:FF(Broadcast)";
		else
			return res;
	}
}

/**
 * @brief ��ȡĿ��mac��ַ
 * @return
*/
QString DataPacket::getDstMacAddr()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)(pkt_content);
	u_char* addr = eth->ether_dhost;
	if (addr) {
		QString res = byteToHex(addr, 1) + ":"
			+ byteToHex((addr + 1), 1) + ":"
			+ byteToHex((addr + 2), 1) + ":"
			+ byteToHex((addr + 3), 1) + ":"
			+ byteToHex((addr + 4), 1) + ":"
			+ byteToHex((addr + 5), 1);
		if (res == "FF:FF:FF:FF:FF:FF")
			return "FF:FF:FF:FF:FF:FF(Broadcast)";
		else
			return res;
	}
}

/**
 * @brief ��ȡ������·���²�����
 * @return 
*/
QString DataPacket::getMacType()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)(pkt_content);
	u_short type = ntohs(eth->ether_type);
	if (type == 0x0800)
		return "IPv4(0x0800)";
	else if (type == 0x0806)
		return	"ARP(0x0806)";
	else
		return "";
}

/**
 * @brief ��ȡԴIP
 * @return 
*/
QString DataPacket::getSrcIPAddr()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	sockaddr_in srcAddr;
	srcAddr.sin_addr.s_addr = ip->SrcAddr;

	return QString(inet_ntoa(srcAddr.sin_addr));
}

/**
 * @brief ��ȡĿ��IP��ַ
 * @return 
*/
QString DataPacket::getDstIPAddr()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	sockaddr_in dstAddr;
	dstAddr.sin_addr.s_addr = ip->DstAddr;

	return QString(inet_ntoa(dstAddr.sin_addr));
}

/**
 * @brief ��ȡIP version
 * @return 
*/
QString DataPacket::getIPVersion()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ip->version);
}

/**
 * @brief ��ȡIP header length
 * @return 
*/
QString DataPacket::getIPHeaderLength()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ip->headerlength * 4) + " bytes (" + QString::number(ip->headerlength) + ")";
}

/**
 * @brief ��ȡIP type of server
 * @return 
*/
QString DataPacket::getIPTOS()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ntohs(ip->cTOS));
}

/**
 * @brief ��ȡIP total length
 * @return 
*/
QString DataPacket::getIPTotalLength()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);

	return QString::number(ntohs(ip->total_length));
}
/**
 * @brief ��ȡIP identification
 * @return 
*/
QString DataPacket::getIPIdentification()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return "0x" + QString::number(ntohs(ip->identification), 16) + " (" + QString::number(ntohs(ip->identification)) + ")";
}

/**
 * @brief ��ȡIP flag
 * @return 
*/
QString DataPacket::getIPFlags()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	QString flags = QString::number((ntohs(ip->flags_offset) & 0xe000) >> 8, 16);
	return flags.size() < 2? "0x0" + flags : "0x" + flags;
}

/**
 * @brief ��ȡflags �µ� Reversved bit
 * @return 
*/
QString DataPacket::getIPFlagsRB()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number((ntohs(ip->flags_offset) & 0x8000) >> 15);
}

/**
 * @brief ��ȡIP flags�µ�Don't fragment
 * @return 
*/
QString DataPacket::getIPFlagsDF()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number((ntohs(ip->flags_offset) & 0x4000) >> 14);
}

/**
 * @brief ��ȡIP flags�µ�More fragment
 * @return 
*/
QString DataPacket::getIPFlagsMF()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number((ntohs(ip->flags_offset) & 0x2000) >> 13);
}

/**
 * @brief ��ȡIP �� FragmentOffset
 * @return 
*/
QString DataPacket::getIPFragmentOffset()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ntohs(ip->flags_offset) & 0x1FFF);
}

/**
 * @brief ��ȡip TTL
 * @return 
*/
QString DataPacket::getIPTimeToLive()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ip->time_to_live);
}

/**
 * @brief ��ȡIPЭ��
 * @return 
*/
QString DataPacket::getIPProtocol()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->protocol;
	switch (protocol) {
	case 1: return "ICMP (1)";
	case 6: return "TCP (6)";
	case 17:return "UDP (17)";
	default: {
		return "";
	}
	}
}

/**
 * @brief ��ȡIP CheckSum
 * @return 
*/
QString DataPacket::getIPCheckSum()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	return QString::number(ntohs(ip->check_sum), 16);
}

QString DataPacket::getTCPSrcPort()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohs(tcp->SrcPort));
}

QString DataPacket::getTCPDstPort()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohs(tcp->DstPort));
}

QString DataPacket::getTCPSeq()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohl(tcp->SequNum));
}

QString DataPacket::getTCPAck()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohl(tcp->AcknowledgeNum));
}

QString DataPacket::getTCPHeaderLength()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	int length = tcp->offset;
	qDebug() << length;
	return QString::number(length * 4) + " bytes (" + QString::number(length) + ")";
}

QString DataPacket::getTCPRawHeaderLength()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(tcp->reserved);
}

QString DataPacket::getTCPFlags()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	QString flags = QString::number(tcp->flags, 16);
	return flags.size() < 2 ? "0x0" + flags : "0x" + flags;
}

QString DataPacket::getTCPFlagsURG()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number((tcp->flags & 0x20) >> 5);
}

QString DataPacket::getTCPFlagsACK()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number((tcp->flags & 0x10) >> 4);
}

QString DataPacket::getTCPFlagsPSH()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number((tcp->flags & 0x08) >> 3);
}

QString DataPacket::getTCPFlagsRST()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number((tcp->flags & 0x04) >> 2);
}

QString DataPacket::getTCPFlagsSYN()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number((tcp->flags & 0x02) >> 1);
}

QString DataPacket::getTCPFlagsFIN()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(tcp->flags & 0x01);
}

QString DataPacket::getTCPWindows()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohs(tcp->WindowSize));
}

QString DataPacket::getTCPCheckSum()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return "0x" + QString::number(ntohs(tcp->CheckSum), 16);
}

QString DataPacket::getTCPUrgenPointer()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
	return QString::number(ntohs(tcp->urgentPointer));
}

