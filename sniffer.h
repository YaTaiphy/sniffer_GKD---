#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_sniffer.h"
#include "mythread.h"
#include "allStructs.h"
#include <vector>
#include <QLabel>
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include "adapter_ui.h"


class sniffer : public QMainWindow
{
    Q_OBJECT

public:
    sniffer(QWidget *parent = Q_NULLPTR);
    ~sniffer();

    adapter_ui* au;

    int dev_num = -1;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[64] = "";
    struct bpf_program fcode;

    bool setting_changed = false;
    bool captureProcess();
    int mod = 1;
    void startProcess();
    void stopProcess();
    bool filterSet();
    void stopThread();
    void clearAllInfor();
    
private:
    Ui::snifferClass ui;

    MyThread myT;
    
    
private slots:

    void clearAllInformation();
    void selectAdapter();
    void getDevice(int num, int mod);
    void captureStart();
    void changeTxt();
    void showTest();
    void getFilterTxt();
    void showInformation(int row, int col);
    void quitThread();

    void sendMessageData(struct message m);
};
