//mySnifferCMD 
#ifndef CIRCLE_QUEUE_H //����ͷ�ļ�����ȫ��д��Ӹ�_H
#define CIRCLE_QUEUE_H

#include "pcap.h"
#include <iostream>
#include <iomanip>
#include <ws2tcpip.h>
#include <exception>

using namespace std;

/* ���������·�� */
#define hcons(A) (((WORD)(A)&0xFF00)>>8) | (((WORD)(A)&0x00FF)<<8)
void PrintEtherHeader(const u_char* packetData);


/* ���������͵�IP��ַת�����ַ������͵� */
#define IPTOSBUFFERS	12
char* iptos(u_long in);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);


/**
 * @brief ��ȡ�����������б�ĺ���
 * @return �����������б�
*/
pcap_if_t* getDeviceList();
#endif
