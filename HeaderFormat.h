#pragma once
#ifndef HEADERFORMAT_H
#define HEADERFPRMAT_H

/*
 * Basic system type definitions, taken from the BSD file sys/types.h.
 * �����������WinSock2.h�����ֱ���ù�����
 */
typedef unsigned char   u_char;		// 1
typedef unsigned short  u_short;	// 2
typedef unsigned int    u_int;		// 4
typedef unsigned long   u_long;		// 4

/**
 * @brief ��̫��ͷ
*/
typedef struct ether_header {
	u_char ether_dhost[6];    // Ŀ���ַ
	u_char ether_shost[6];    // Դ��ַ
	u_short ether_type;       // ��̫������
} ETHER_HEADER;

/**
 * @brief IPͷ
*/
typedef struct ip_header
{
	u_char headerlength : 4;	// 4 bit
	u_char version : 4;	// 4 bit 
	u_char cTOS;	// 1 Byte
	u_short total_length;	// 2 Byte
	u_short identification;	// 2 Byte
	u_short flags_offset;	// 2 Byte
	u_char time_to_live;	// 1 Byte
	u_char protocol;		// 1 Byte
	u_short check_sum;		// 2 Byte
	u_int SrcAddr;		// 4 Byte
	u_int DstAddr;		// 4 Byte
}IP_HEADER;

/**
 * @brief TCPͷ
*/
typedef struct tcp_header
{
	u_short SrcPort;                 // Դ�˿ں�16bit
	u_short DstPort;                 // Ŀ�Ķ˿ں�16bit
	u_int SequNum;           // ���к�32bit
	u_int AcknowledgeNum;    // ȷ�Ϻ�32bit
	u_char reserved : 4, offset : 4; // Ԥ��ƫ��

	u_char  flags;               // ��־ 

	u_short WindowSize;               // ���ڴ�С16bit
	u_short CheckSum;                 // �����16bit
	u_short urgentPointer;           // ��������ƫ����16bit
}TCP_HEADER;

/**
 * @brief UDPͷ
*/
typedef struct udp_header {
	u_short SrcPort;   // Դ�˿�
	u_short DstPort;   // Ŀ��˿�
	u_short len;	// ���ݳ���
	u_short crc;	// У���
}UDP_HEADER;

/**
 * @brief ARPͷ
*/
typedef struct arp_header
{
	u_short Type;    // Ӳ������
	u_short Protocol;   // Э������
	u_char Maclength;     // Ӳ����ַ����
	u_char IPlength;    // Э���ַ����
	u_short OpCode;        // �������ͣ�ARP����1����ARPӦ��2����RARP����3����RARPӦ��4����
	u_char SrcMac[6];           // ԴMAC��ַ
	u_char SrcIp[4];            // ԴIP��ַ
	u_char DstMac[6];           // Ŀ��MAC��ַ
	u_char DstIp[4];            // Ŀ��IP��ַ
}ARP_HEADER;

/**
 * @brief ICMPͷ
*/
typedef struct icmp_header {
	u_char Type;        // ICMP����
	u_char code;        // ����
	u_short checksum;   // У���
	u_short identification; // ��ʶ
	u_short sequence;       // ���к�
	u_int init_time;      // ����ʱ���
	u_short recv_time;      // ����ʱ���
	u_short send_time;      // ����ʱ���
}ICMP_HEADER;



#endif // !HEADERFORMAT_H
