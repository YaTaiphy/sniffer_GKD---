#include "MyThread.h"
#include <QThread>
#include <pcap.h>
#include <time.h>
#include "protocalHanldler.h"
#include "AllStructs.h"

MyThread::MyThread(QObject* parent)
{
}

MyThread::~MyThread()
{

}



//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
//{
//	struct tm* ltime;
//	char timestr[16];
//	ipv4_header* ih;
//	udp_header* uh;
//	u_int ip_len;
//	u_short sport, dport;
//	time_t local_tv_sec;
//	struct message m;
//
//	/*
//	 * unused parameter
//	 */
//	(VOID)(param);
//
//	/* convert the timestamp to readable format */
//	local_tv_sec = header->ts.tv_sec;
//	ltime = localtime(&local_tv_sec);
//	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//
//	char packetTime[64] = "";
//	sprintf(packetTime, "Time: %s.%.6d", timestr, header->ts.tv_usec);
//	//sprintf(packetTime, "Time: %s.%.6d length:len:%d\n", timestr, header->ts.tv_usec, header->len);
//	strcat(m.analyse_infor, packetTime);
//	strcat(m.time_sev, packetTime);
//	char packetLen[32] = "";
//	sprintf(packetLen, "length:len:%d\n", timestr, header->len);
//	strcat(m.analyse_infor, packetLen);
//	ethernet_protocol_packet_handle(header, pkt_data, m);
//
//}


void MyThread::run()
{
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	res = pcap_next_ex(adhandle, &header, &pkt_data);


	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (confirmStop == true)
			break;
		struct tm* ltime;
		char timestr[16];
		ipv4_header* ih;
		udp_header* uh;
		u_int ip_len;
		u_short sport, dport;
		time_t local_tv_sec;
		struct message m;

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		char packetTime[64] = "";
		sprintf(packetTime, "%s.%.6d", timestr, header->ts.tv_usec);
		//sprintf(packetTime, "Time: %s.%.6d length:len:%d\n", timestr, header->ts.tv_usec, header->len);
		strcat(m.analyse_infor, "Time");
		strcat(m.analyse_infor, packetTime);
		strcat(m.time_sev, packetTime);
		char packetLen[32] = "";
		sprintf(packetLen, "length:len:%d\n", timestr, header->len);
		strcat(m.analyse_infor, packetLen);
		ethernet_protocol_packet_handle(header, pkt_data, m);
		emit sendData(m);
	}

    //struct message m;
    //char* a = packet_filter;
    //for (int i = 0; i < 20; i++) {
    //    if (confirmStop == true)
    //        break;
    //    m.infor = "this is a test message" + std::to_string(i);
    //    msleep(500);
    //    emit sendData(m);
    //}
}
