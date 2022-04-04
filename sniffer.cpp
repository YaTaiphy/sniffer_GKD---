#include "sniffer.h"
#include <QtWidgets/QMainWindow>
#include <QTextEdit>
#include <QStandardItemModel>
#include <vector>
#include <QMessageBox>
#include <pcap.h>
#include <time.h>
#include "mythread.h"

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

std::vector<message> allPacketsStore;
unsigned long long int packetListIndex = 0;

sniffer::sniffer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    ui.showPacketList->setColumnCount(4);
    ui.showPacketList->setHorizontalHeaderLabels(QStringList() << "Time" << "source" << "destiny" << "protocol");
    myT.setObjectName("dataCapture");
    QObject::connect(&myT, &MyThread::sendData, this, &sniffer::sendMessageData);
    //当按窗口右上角x时，触发destroyed信号
    QObject::connect(this, &sniffer::destroyed, this, &sniffer::quitThread);
    //QApplication::setQuitOnLastWindowClosed(true);

#ifdef _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif
}

sniffer::~sniffer()
{
    myT.confirmStop = true;
    myT.quit();
    myT.wait();

}

bool sniffer::captureProcess()
{
    if ((adhandle = pcap_open_live(d->name,	// name of the device
        65536,			// portion of the packet to capture. 
                       // 65536 grants that the whole packet will be captured on all the MACs.
        mod,				// promiscuous mode (nonzero means promiscuous)
        1000,			// read timeout
        errbuf			// error buffer
    )) == NULL)
    {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Unable to open the adapter");
        return false;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "This program works only on Ethernet networks.");
        return false;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;

    return true;
}

void sniffer::startProcess()
{
    myT.d = d;
    myT.adhandle = adhandle;
    myT.packet_filter = packet_filter;
    myT.confirmStop = false;
    myT.start();
    if (myT.isRunning() == true)
        ui.status->setText("status: listening on.......");
    ui.CpatureButton->setText("Stop");
}

void sniffer::stopProcess()
{
}

bool sniffer::filterSet()
{
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Unable to compile the packet filter. Check the syntax.");
        return false;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Error setting the filter.");
        return false;
    }
    return true;
}


void sniffer::stopThread()
{
    myT.confirmStop = true;
    myT.quit();
    myT.wait();
}

void sniffer::clearAllInfor()
{
    ui.showData->clear();
    int row_count = ui.showPacketList->rowCount();
    for (int i = 0; i < row_count; i++) {
        ui.showPacketList->removeRow(0);
    }
    packetListIndex = 0;

    allPacketsStore.clear();
}


void sniffer::selectAdapter()
{
    if (myT.isRunning() == true) {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Please stop capturing then click");
        return;
    }
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", QString(QLatin1String(errbuf)));
        return;
    }
    
    au = new adapter_ui(nullptr);
    //QObject::connect(au, SIGNAL(au->sendDevice(int num)), this, SLOT(getDevice(int num)));
    QObject::connect(au, &adapter_ui::sendDevice, this, &sniffer::getDevice);

    au->alldevs = alldevs;
    au->showListofAlldevs();
    au->show();
}

void sniffer::getDevice(int num, int mod)
{
    this->mod = mod;
    if (myT.isRunning() == true) {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "stop capturing then select");
    }
    int i = 0;
    for (d = alldevs, i = 0; i < num; d = d->next, i++);
    dev_num = i;
    std::string name = d->name;
    std::string description;
    if (d->description)
        description = d->description;
    else
        description = "No description";
    std::string infor = "selected adapter: " + name + ": " + description;
    ui.adapterName->setText(QString::fromStdString(infor));
    QString status = QString::fromLocal8Bit("status:");
    ui.status->setText(status);
    status = QString::fromLocal8Bit("change adapter");
    ui.selectAdapter->setText(status);
    setting_changed = true;
}

void sniffer::changeTxt() {

}

void sniffer::showTest() {
    
}

void sniffer::getFilterTxt()
{
    if (dev_num < 0) {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "please choose adapter!");
        return;
    }
    if (captureProcess() == false) {
        return;
    }
    QString fi = ui.filterInput->text();
    fi = fi.simplified();
    QByteArray ba = fi.toLatin1();
    const char* temp;
    temp = ba.data();
    if (strlen(temp) > 63) {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "filter expression is too long");
        return;
    }
    strcpy(packet_filter, temp);
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Unable to compile the packet filter. Check the syntax.");
        return;
    }
    if (myT.isRunning() == true) {
        myT.confirmStop = true;

        //set the filter
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "Error setting the filter.");
            return;
        }

        stopThread();
        clearAllInfor();
        setting_changed = false;
        myT.d = d;
        myT.adhandle = adhandle;
        myT.packet_filter = packet_filter;
        myT.confirmStop = false;
        myT.start();
    }
    setting_changed = true;
}

void sniffer::captureStart()
{
    if (myT.isRunning() == true) {
        myT.confirmStop = true;
        stopThread();
        if (myT.isRunning() == false) {
            ui.CpatureButton->setText("Capture");
            ui.status->setText("status: stopped");
        }
        return;
    }
    else {
        if (dev_num < 0) {
            QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "please choose adapter!");
            return;
        }
        if (captureProcess() == false) {
            return;
        }
        if (filterSet() == false) {
            return;
        }
        if (setting_changed == true) {
            clearAllInfor();
            setting_changed = false;
        }
        startProcess();
    }
}

void sniffer::showInformation(int row = -1, int col = -1) {
    QString inf(allPacketsStore[row].analyse_infor);
    //ui.showData->setPlainText(QString::fromStdString(allPacketsStore[row].infor));
    ui.showData->setPlainText(inf);
}

void sniffer::clearAllInformation() {
    clearAllInfor();
}


void sniffer::sendMessageData(struct message m)
{
    ui.showPacketList->insertRow(ui.showPacketList->rowCount());
    QString tm(m.time_sev);
    ui.showPacketList->setItem(packetListIndex, 0, new QTableWidgetItem(tm));
    QString s(m.source);
    ui.showPacketList->setItem(packetListIndex, 1, new QTableWidgetItem(s));
    QString d(m.destiny);
    ui.showPacketList->setItem(packetListIndex, 2, new QTableWidgetItem(d));
    QString pt(m.protocalType);
    ui.showPacketList->setItem(packetListIndex, 3, new QTableWidgetItem(pt));
    allPacketsStore.push_back(m);
    packetListIndex++;
}

void sniffer::quitThread()
{
    myT.confirmStop = true;
    myT.quit();
    myT.wait();
}

