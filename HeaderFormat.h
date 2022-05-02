#pragma once
#ifndef HEADERFORMAT_H
#define HEADERFPRMAT_H

/*
 * Basic system type definitions, taken from the BSD file sys/types.h.
 * 这个定义是在WinSock2.h里，这里直接拿过来了
 */
typedef unsigned char   u_char;		// 1
typedef unsigned short  u_short;	// 2
typedef unsigned int    u_int;		// 4
typedef unsigned long   u_long;		// 4

/**
 * @brief 以太网头
*/
typedef struct ether_header {
	u_char ether_dhost[6];    // 目标地址
	u_char ether_shost[6];    // 源地址
	u_short ether_type;       // 以太网类型
} ETHER_HEADER;

/**
 * @brief IP头
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
 * @brief TCP头
*/
typedef struct tcp_header
{
	u_short SrcPort;                 // 源端口号16bit
	u_short DstPort;                 // 目的端口号16bit
	u_int SequNum;           // 序列号32bit
	u_int AcknowledgeNum;    // 确认号32bit
	u_char reserved : 4, offset : 4; // 预留偏移

	u_char  flags;               // 标志 

	u_short WindowSize;               // 窗口大小16bit
	u_short CheckSum;                 // 检验和16bit
	u_short urgentPointer;           // 紧急数据偏移量16bit
}TCP_HEADER;

/**
 * @brief UDP头
*/
typedef struct udp_header {
	u_short SrcPort;   // 源端口
	u_short DstPort;   // 目标端口
	u_short len;	// 数据长度
	u_short crc;	// 校验和
}UDP_HEADER;

/**
 * @brief ARP头
*/
typedef struct arp_header
{
	u_short Type;    // 硬件类型
	u_short Protocol;   // 协议类型
	u_char Maclength;     // 硬件地址长度
	u_char IPlength;    // 协议地址长度
	u_short OpCode;        // 操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char SrcMac[6];           // 源MAC地址
	u_char SrcIp[4];            // 源IP地址
	u_char DstMac[6];           // 目的MAC地址
	u_char DstIp[4];            // 目的IP地址
}ARP_HEADER;

/**
 * @brief ICMP头
*/
typedef struct icmp_header {
	u_char Type;        // ICMP类型
	u_char code;        // 代码
	u_short checksum;   // 校验和
	u_short identification; // 标识
	u_short sequence;       // 序列号
	u_int init_time;      // 发起时间戳
	u_short recv_time;      // 接受时间戳
	u_short send_time;      // 传输时间戳
}ICMP_HEADER;



#endif // !HEADERFORMAT_H
