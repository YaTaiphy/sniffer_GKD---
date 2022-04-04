#include "adapter_ui.h"
#include <QMessageBox>

adapter_ui::adapter_ui(QWidget *parent)
    : QWidget(parent)
{
    ui.setupUi(this);
}

adapter_ui::~adapter_ui()
{
}

void adapter_ui::showListofAlldevs()
{
    int i = 0;
    for (d = alldevs; d; d = d->next)
    {
        i++;
        std::string name = d->name;
        std::string description;
        if (d->description)
            description = d->description;
        else
            description = "No description";
        std::string infor = name + ": " + description;
        ui.listAdapter->addItem(QString::fromStdString(infor));
    }
    if (i == 0) {
        QMessageBox::StandardButton result = QMessageBox::critical(this, "Error", "No interfaces found! Make sure Npcap is installed.");
        this->close();
        this->destroy();
    }
}

void adapter_ui::chooseItem()
{
    int chooseRow = ui.listAdapter->currentRow();
    int mod = 1;
    emit sendDevice(chooseRow, mod);
    this->close();
    this->destroy();
}
