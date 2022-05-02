//mySnifferCMD 
#ifndef CIRCLE_QUEUE_H //就是头文件名（全大写后加个_H
#define CIRCLE_QUEUE_H

#include "pcap.h"
#include <iostream>
#include <iomanip>
#include <ws2tcpip.h>
#include <exception>

using namespace std;

/* 输出数据链路层 */
#define hcons(A) (((WORD)(A)&0xFF00)>>8) | (((WORD)(A)&0x00FF)<<8)
void PrintEtherHeader(const u_char* packetData);


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS	12
char* iptos(u_long in);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);


/**
 * @brief 获取网络适配器列表的函数
 * @return 网络适配器列表
*/
pcap_if_t* getDeviceList();
#endif
