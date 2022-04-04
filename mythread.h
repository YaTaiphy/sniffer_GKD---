#pragma once
#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QThread>
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include "allStructs.h"

class MyThread : public QThread
{
    Q_OBJECT
public:
    explicit MyThread(QObject* parent = 0);
    ~MyThread();

    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;

    int choose = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char *packet_filter;
    struct bpf_program fcode;

    bool confirmStop = false;
protected:
    void run();
signals:
    void sendData(struct message m);

public slots:
};
#endif // MYTHREAD_H

