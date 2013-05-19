#pragma once

#include "stdAfx.h"

//Dlc Header 14 byte
struct EtherHeader
{
public:
	unsigned char desMAC[6];//destination MAC
	unsigned char srcMAC[6];//source MAC
	unsigned short etherType;//frame type
};

//Arp Frame 28+18 byte
struct Arp
{
	unsigned short hwType;//hardware type
	unsigned short protType;//upper level protocol
	unsigned char hwAddrLen;//hardware add. length
	unsigned char protAddrLen;//protocol add. length
	unsigned short op;//1-request;2-reply;

	unsigned char sendMacAddr[6];
	unsigned char sendIpAddr[4];
	unsigned char targMacAddr[6];
	unsigned char targIpAddr[4];
	unsigned char padding[18];//fillings
};

//Arp Packet = DlcHeader+Arp Frame
struct ArpFrame
{
	EtherHeader etherHeader;
	Arp arp;
};

class ArpFrameSender
{
	ArpFrame arpFrame;//arp frame
	pcap_t *adhandle;//pointer to the object which opens the NIC
	int openNIC();
	void closeNIC();
	int fillIP(char*,unsigned char *);//fill IP address
	int fillMAC(char*,unsigned char *);//fill MAC address
	bool checkIP(char*);
	bool checkMac(char*);
	void copyStrBuf(unsigned char * src,unsigned char * des,int len);//like strcpy()
	void copyStrBuf(char * src,char * des,int len);
	//void inputStr(char * s)
public:
	void setEtherHeader(char*desMac,char*srcMac);
	void setArp(unsigned short opcode,char*sendMac,char*sendIp,char*targetMac,char*targetIp);
	bool send(int num);
	void run();
};

