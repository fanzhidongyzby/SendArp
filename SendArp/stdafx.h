// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

#ifndef _WIN32_WINNT		// ����ʹ���ض��� Windows XP ����߰汾�Ĺ��ܡ�
#define _WIN32_WINNT 0x0501	// ����ֵ����Ϊ��Ӧ��ֵ���������� Windows �������汾��
#endif						

#include <stdio.h>
#include <tchar.h>




// TODO: �ڴ˴����ó�����Ҫ������ͷ�ļ�
#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"wpcap.lib")
#pragma comment (lib,"Packet.lib")

#include <pcap.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <conio.h>
#include <stdio.h>
#include "Packet32.h"
#include "Ntddndis.h"
using namespace std;