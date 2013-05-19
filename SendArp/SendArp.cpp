// SendArp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include "ArpFrameSender.h"

int _tmain(int argc, _TCHAR* argv[])
{
	ArpFrameSender arpFrameSender;
	arpFrameSender.run();
	return 0;
}
