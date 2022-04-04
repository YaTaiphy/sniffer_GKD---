#pragma once
#include <string>
#include <iostream>
#include <ws2tcpip.h>
#include <Windows.h>
#include <locale>         // std::wstring_convert
#include <codecvt>        // std::codecvt_utf8
/* write by Lai, 2021E8018682138, 2022.4.2*/
#include <psapi.h>//GetModuleFileNameEx
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <atlconv.h>

struct message {
    char time_sev[128] = "";
    char source[48] = "";
    char destiny[48] = "";
    char protocalType[16] = "";
	unsigned short sport = 0;
	unsigned short dport = 0;
    char analyse_infor[205535] = "";
    bool couldBeJudged = true;
};






//���´���Ϊ����port��׷�ٽ��̵ģ�����ʱ���Լ�BUG��ԭ����ʱ���á�
//DWORD GetIdOfOccupiedPortProcess(unsigned short port)
//{
//	ULONG ulSize = sizeof(MIB_TCPTABLE2);
//	PMIB_TCPTABLE2 pTcpTable = (PMIB_TCPTABLE2)malloc(ulSize);
//
//	if (pTcpTable == nullptr)
//		throw std::runtime_error("memory is not enough.");
//
//	//����GetTcpTable2�����ڴ治�������ͷţ�Ȼ��������
//	if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == ERROR_INSUFFICIENT_BUFFER)
//	{
//		free(pTcpTable);
//		pTcpTable = (PMIB_TCPTABLE2)malloc(ulSize);
//		if (pTcpTable == nullptr)
//			throw std::runtime_error("memory is not enough.");
//	}
//
//	if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == NO_ERROR)
//	{
//		for (int i = 0; i < pTcpTable->dwNumEntries; ++i)
//		{
//			//�õ��˿ں�
//			unsigned short localPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
//
//			//�õ�ռ�ö˿ڵĽ���pid
//			auto pid = pTcpTable->table[i].dwOwningPid;
//
//			//����Ŀ��˿ڣ�����pid
//			if (port == localPort)
//			{
//				free(pTcpTable);
//				return pid;
//			}
//		}
//	}
//
//	free(pTcpTable);
//	return 0;
//}
//
//std::string UTF8ToString(const std::string& utf8Data)
//{
//	std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
//	std::wstring wString = conv.from_bytes(utf8Data);    // utf-8 => wstring
//
//	std::wstring_convert<std::codecvt< wchar_t, char, std::mbstate_t>>
//		convert(new std::codecvt< wchar_t, char, std::mbstate_t>("CHS"));
//	std::string str = convert.to_bytes(wString);     // wstring => string
//
//	return str;
//}
//
//
//void getIDbyPort(unsigned short port) {
//	HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, GetIdOfOccupiedPortProcess(port));
//	TCHAR buf[MAX_PATH];
//	GetModuleFileNameEx(hProcess, 0, buf, MAX_PATH);
//	USES_CONVERSION;
//	char* IDBuffer = W2A(buf);
//	std::string str(IDBuffer);
//	std::cout << UTF8ToString(str) << endl;
//}
