#pragma once

#include <QThread>
#include <QDebug>
#include "pcap.h"
#include "HeaderFormat.h"
#include "DataPacket.h"

class subThread : public QThread
{
	Q_OBJECT
private:
	bool isDone;

	pcap_t* openAdapter;		// 开启的网卡指针
	struct pcap_pkthdr* header;	// 数据包头部
	const u_char* pkt_data;	// 数据包的数据部分

	// -----时间转换相关参数-----
	time_t local_tv_sec;
	struct tm* ltime;
	char timestr[16];
	// --------------------------

public:
	subThread();
	~subThread();
	void run() override;
	bool setOpenAdapter(pcap_t* openAdapter);
	void setFlag();
	void resetFlag();

	int ethernetPacketHandle(const u_char* pkt_content, QString& info);
	int ipPacketHandle(const u_char *pkt_content, int& ipPacket);
	int tcpPacketHandle(const u_char* pkt_content, QString& info, int ipPacket);
	int udpPacketHandle(const u_char* pkt_content, QString& info);
	QString arpPacketHandle(const u_char* pkt_content);

	QString byteToHex(u_char* str, int size);
signals:
	void send(DataPacket data);
};
