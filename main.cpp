#include "sniffer.h"
#include <QtWidgets/QApplication>
#include <QPushButton>



int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    sniffer w;
    w.show();
    //w.setWindowTitle(QString::fromLocal8Bit("ÄãºÃ "));
    return a.exec();
}
