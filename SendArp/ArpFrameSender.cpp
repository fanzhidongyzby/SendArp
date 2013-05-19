#include "StdAfx.h"
#include "ArpFrameSender.h"

void ArpFrameSender::setEtherHeader(char*desMac,char*srcMac)
{
	this->fillMAC(desMac,arpFrame.etherHeader.desMAC);
	this->fillMAC(srcMac,arpFrame.etherHeader.srcMAC);
	arpFrame.etherHeader.etherType=0x0806;
}

void ArpFrameSender::setArp(unsigned short opcode,char*sendMac,char*sendIp,char*targetMac,char*targetIp)
{
	arpFrame.arp.hwType=0x0001;
	arpFrame.arp.protType=0x0800;
	arpFrame.arp.hwAddrLen=0x0006;
	arpFrame.arp.protAddrLen=0x0004;
	arpFrame.arp.op=opcode;
	this->fillMAC(sendMac,arpFrame.arp.sendMacAddr);
	this->fillIP(sendIp,arpFrame.arp.sendIpAddr);
	this->fillMAC(targetMac,arpFrame.arp.targMacAddr);
	this->fillIP(targetIp,arpFrame.arp.targIpAddr);
	for(int i=0;i<18;i++)
		arpFrame.arp.padding[i]=0x00;
}

void ArpFrameSender::copyStrBuf(unsigned char * des,unsigned char * src,int len)
{
	for(int i=0;i<len;i++)
	{
		des[i]=src[i];
	}
}

void ArpFrameSender::copyStrBuf(char * des,char * src,int len)
{
	for(int i=0;i<len;i++)
	{
		des[i]=src[i];
	}
}

bool ArpFrameSender::checkIP(char*s)
{
	int i,j,k;
	i=j=k=0;
	int m=(int)strlen(s);
	for(i=0;i<m;i++)//to check the format of ip addr.
	{
		if((s[i]<'0'||s[i]>'9')&&s[i]!='.')
			return 0;
		else 
		{
			if(s[i]!='.')
				j++;
			else
			{
				k++;
				if(j>3)
					return 0;
				else
					j=0;
				if(k>3)
					return 0;
			}
		}
	}
	return 1;
}

int ArpFrameSender::fillIP(char * s,unsigned char * ip)
{
	if(!checkIP(s))
		return 0;
	int j=0;
	for(int i=0;i<4;i++)
	{
		while(s[j]<'0'||s[j]>'9')
			j++;
		ip[i]=(unsigned char)atoi(s+j);//mod=256
		while(!(s[j]<'0'||s[j]>'9'))
			j++;
	}
	return 1;
}

bool ArpFrameSender::checkMac(char *s)
{
	int i,j,k;
	i=j=k=0;
	int m=(int)strlen(s);
	for(i=0;i<m;i++)//to check the format of mac addr.
	{
		if((s[i]<'0'||(s[i]>':'&&s[i]<'A')||(s[i]>'Z'&&s[i]<'a')||s[i]>'z'))
			return 0;
		else 
		{
			if(s[i]!=':')
				j++;
			else
			{
				k++;
				if(j>2)
					return 0;
				else
					j=0;
				if(k>5)
					return 0;
			}
		}
	}
	return 1;
}

int ArpFrameSender::fillMAC(char * s,unsigned char * mac)
{
	if(!checkMac(s))
		return 0;
	int j=0;
	for(int i=0;i<6;i++)
	{
		while(s[j]==':'||s[i]=='-')
			j++;
		if(s[j]>='0'&&s[j]<='9')
			mac[i]=(unsigned char)(s[j]-'0');
		if(s[j]>='a'&&s[j]<='z')
			mac[i]=(unsigned char)(s[j]-'a'+10);
		if(s[j]>='A'&&s[j]<='Z')
			mac[i]=(unsigned char)(s[j]-'A'+10);
		j++;
		mac[i]*=16;
		if(s[j]>='0'&&s[j]<='9')
			mac[i]+=(unsigned char)(s[j]-'0');
		if(s[j]>='a'&&s[j]<='z')
			mac[i]+=(unsigned char)(s[j]-'a'+10);
		if(s[j]>='A'&&s[j]<='Z')
			mac[i]+=(unsigned char)(s[j]-'A'+10);
		j++;
	}
	return 1;
}

int ArpFrameSender::openNIC()
{
	cout<<"Checking the NICs..."<<endl;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获得网卡的列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}

	/* 打印网卡信息 */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	printf("Enter the interface number (1-%d):",i);
	cin>>inum; //输入要选择打开的网卡号

	if(inum < 1 || inum > i) //判断号的合法性
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 0;
	}

	/* 找到要选择的网卡结构 */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* 打开选择的网卡 */
	if ( (adhandle= pcap_open_live(d->name, // 设备名称
		65536, // portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1, // 混杂模式
		1000, // 读超时为1秒
		errbuf // error buffer
		) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 0;
	}

	//printf("\nlistening on %s...\n", d->description);

	/* At this point, we don‘t need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	return 1;
}

bool ArpFrameSender::send(int num)
{
	//convert the packet to buffer
	unsigned char buf[60];
	//desMac 6
	copyStrBuf(&buf[0],arpFrame.etherHeader.desMAC,6);
	//srcMac 6
	copyStrBuf(&buf[6],arpFrame.etherHeader.srcMAC,6);
	//etherType 2
	buf[12]=(unsigned char)((arpFrame.etherHeader.etherType&0xff00)>>8);
	buf[13]=(unsigned char)(arpFrame.etherHeader.etherType&0x00ff);
	//hwType 2
	buf[14]=(unsigned char)((arpFrame.arp.hwType&0xff00)>>8);
	buf[15]=(unsigned char)(arpFrame.arp.hwType&0x00ff);
	//proType 2
	buf[16]=(unsigned char)((arpFrame.arp.protType&0xff00)>>8);
	buf[17]=(unsigned char)(arpFrame.arp.protType&0x00ff);
	//MacLen 1
	buf[18]=0x06;
	//IpLen
	buf[19]=0x04;
	//op 2
	buf[20]=(unsigned char)((arpFrame.arp.op&0xff00)>>8);
	buf[21]=(unsigned char)(arpFrame.arp.op&0x00ff);
	//sendMac 6
	copyStrBuf(&buf[22],arpFrame.arp.sendMacAddr,6);
	//sendIp 4
	copyStrBuf(&buf[28],arpFrame.arp.sendIpAddr,4);
	//desMac 
	copyStrBuf(&buf[32],arpFrame.arp.targMacAddr,6);
	//desIp
	copyStrBuf(&buf[38],arpFrame.arp.targIpAddr,4);
	//padding
	for(int i=42;i<60;i++)
	{
		buf[i]=(unsigned char)arpFrame.arp.padding[i-42];
	}

	int j=num;
	while(j)
	{
		if(pcap_sendpacket(adhandle,buf,60)!=0)
		{
			cout<<"Send failed !"<<endl;
			return false;
		}
		else
		{
			cout<<"Send ok !"<<endl;
		}
		j--;
	}
	return true;
}

void ArpFrameSender::closeNIC()
{
	pcap_close(this->adhandle);
}

void ArpFrameSender::run()
{
	cout<<"This is the program to send DIY ARP packets.Now let's make our packets......\n\n";
	cout<<"------------------------------------------------------------\n";
	if(this->openNIC()==0)//open the NIC
		return ;
	char desMac[18]="00:23:5a:6a:1b:e2";
	char srcMac[18]="00:23:54:21:49:7F";
	unsigned short opcode=2;
	char sendMac[18]="88:88:88:88:88:88";
	char sendIp[16]="172.19.44.34";
	char targetMac[18]="00:23:5a:6a:1b:e2";
	char targetIp[16]="172.19.44.136";

	int select=0;
	char buf1[16];
	char buf2[18];
AGAIN:
	while(true)
	{
		//show the info of the packet
		cout<<"------------------------------------------------------------\n";
		cout<<"This is the main info of your DIY arp packet :\n";
		cout<<"EtherDesMac="<<desMac<<" ; EtherSrcMac="<<srcMac<<endl<<"(";
		if(opcode==1)
			cout<<"request";
		else if(opcode==2)
			cout<<"reply";
		cout<<")\n";
		cout<<"ArpSenderMac="<<sendMac<<" ; ArpSenderIp="<<sendIp<<"\nArpTargetMac="<<targetMac<<" ; ArpTargetIp="<<targetIp<<endl;

		//ask for modification
		cout<<"------------------------------------------------------------\n";
		cout<<"Do you want to make any more change to the packet ?"<<endl;
		cout<<"0--no change ;\n1--desMac ;2--srcMac ;\n3--opcode ;4--sendMac ;5--sendIp ;6--targetMac ;7--targetIp\n"
			<<"Your select is :";
		cin>>select;
		if(select==0)
		{
			cout<<"DIY complete !"<<endl;
			break;
		}
		switch(select)
		{
		case 1:
			cout<<"EtherDesMac=";
			cin>>buf2;
			if(checkMac(buf2))
				copyStrBuf(desMac,buf2,18);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		case 2:
			cout<<"EtherSrcMac=";
			cin>>buf2;
			if(checkMac(buf2))
				copyStrBuf(srcMac,buf2,18);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		case 3:
			cout<<"ArpOpcode=";
			cin>>opcode;break;
		case 4:
			cout<<"ArpSendMac=";
			cin>>buf2;
			if(checkMac(buf2))
				copyStrBuf(sendMac,buf2,18);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		case 5:
			cout<<"ArpSendIp=";
			cin>>buf1;
			if(checkIP(buf1))
				copyStrBuf(sendIp,buf1,16);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		case 6:
			cout<<"ArpTargetMac=";
			cin>>buf2;
			if(checkMac(buf2))
				copyStrBuf(targetMac,buf2,18);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		case 7:
			cout<<"ArpTargetIp=";
			cin>>buf1;
			if(checkIP(buf1))
				copyStrBuf(targetIp,buf1,16);
			else
				cout<<"The format of your input is wrong !"<<endl;
			break;
		default:break;
		}
	}
	//fill the packet
	setEtherHeader(desMac,srcMac);
	setArp(opcode,sendMac,sendIp,targetMac,targetIp);
	//send the packet
	cout<<"------------------------------------------------------------\n"
		<<"How many arp packets would you like to send ?"<<endl<<"Packets' No.=";
	int num;
	cin>>num;
	send(num);
	cout<<"------------------------------------------------------------\n"
		<<"Would you like to send the ARP packet again ?(1--YES ;other--exit)"<<endl
		<<"Your choosen is :";
	char again='1';
	cin>>again;
	if(again=='1')
		goto AGAIN;
	closeNIC();
}