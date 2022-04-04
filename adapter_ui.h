#pragma once

#include <QWidget>
#include "ui_adapter_ui.h"

#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>

class adapter_ui : public QWidget
{
    Q_OBJECT

public:
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int* choose;
    int seletItem = -1;
    adapter_ui(QWidget *parent = Q_NULLPTR);
    ~adapter_ui();

    void showListofAlldevs();
    
private:
    Ui::adapter_ui ui;

private slots:
    void chooseItem();
signals:
    void sendDevice(int num, int mod);
};
