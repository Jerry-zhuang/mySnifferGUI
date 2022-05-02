#pragma once
#include "HeaderFormat.h"
#include "winsock.h"
#include <QString>
#include <QMetaType>

class DataPacket
{
private:
	u_int dataLength;	// ���ݳ���
	QString timeStamp;	// ʱ���
	QString information;	// ��Ϣ
	int packetType;			// ������

public:
	const u_char* pkt_content;	// ���ݰ����������

protected:
	static QString byteToHex(u_char* str, int size);

public:
	DataPacket();

	void setDataLength(unsigned int length);
	void setTimeStamp(QString timeStamp);
	void setPacketType(int type);
	void setPacketContent(const u_char *pkt_content, int size);
	void setPacketInfo(QString info);

	QString getDataLength();
	QString getTimeStamp();
	QString getPacketType();
	QString getPacketInfo();

	QString getSource();
	QString getDestination();

	QString getSrcMacAddr();
	QString getDstMacAddr();
	QString getMacType();

	QString getSrcIPAddr();
	QString getDstIPAddr();
	QString getIPVersion();
	QString getIPHeaderLength();
	QString getIPTOS();
	QString getIPTotalLength();
	QString getIPIdentification();
	QString getIPFlags();
	QString getIPFlagsRB();
	QString getIPFlagsDF();
	QString getIPFlagsMF();
	QString getIPFragmentOffset();
	QString getIPTimeToLive();
	QString getIPProtocol();
	QString getIPCheckSum();

	QString getTCPSrcPort();
	QString getTCPDstPort();
	QString getTCPSeq();
	QString getTCPAck();
	QString getTCPHeaderLength();
	QString getTCPRawHeaderLength();
	QString getTCPFlags();
	QString getTCPFlagsURG();
	QString getTCPFlagsACK();
	QString getTCPFlagsPSH();
	QString getTCPFlagsRST();
	QString getTCPFlagsSYN();
	QString getTCPFlagsFIN();
	QString getTCPWindows();
	QString getTCPCheckSum();
	QString getTCPUrgenPointer();
};







