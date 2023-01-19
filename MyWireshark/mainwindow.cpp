#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include "sniffthreaed.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
    sniffThreaed* cpt = new sniffThreaed;
    static bool isBegin = false;
    connect(ui->actionrun, &QAction::triggered, this, [=](){
        isBegin = !isBegin;
        if(isBegin){
            int t = capture();
            if(t > 0 && in){
                cpt->setIn(in);
                cpt->setFlag();
                cpt->start();
                ui->comboBox->setEnabled(false);
                ui->actionrun->setIcon(QIcon(":/stop.png"));
            }
        }else{
            cpt->resetFlag();
            cpt->quit();
            cpt->wait();
            ui->comboBox->setEnabled(true);
            ui->actionrun->setIcon(QIcon(":/start.png"));
            pcap_close(in);
            in = nullptr;
        }
    });
    connect(cpt, &sniffThreaed::sendInfo, this, &MainWindow::recvAndHandleMsg);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkCard(){
    int n = pcap_findalldevs(&allDevices, errbuf);
    ui->comboBox->addItem("error:" + QString(errbuf));
    if(n == -1){
        ui->comboBox->addItem("error:" + QString(errbuf));
    }else{
        ui->comboBox->clear();
        ui->comboBox->addItem("choose nics");
        for(now = allDevices; now != nullptr; now = now->next){
            QString name = now->name;
            name.replace("\\Device\\NPF_","");
            QString description = now->description;
            QString msg = name + description;
            ui->comboBox->addItem(msg);
        }
   }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int idx = 0;
    if(index != 0){
        for(now = allDevices; idx < index - 1; now = now -> next){
            idx++;
        }
    }
}

int MainWindow::capture(){
   if(now != nullptr){
       in = pcap_open_live(now->name, 65536, 1, 1000, errbuf);
   } else{
       return -1;
   }
   if(in == nullptr){
       pcap_freealldevs(allDevices);
       now = nullptr;
       return -1;
   }
   if(pcap_datalink(in) != DLT_EN10MB){
       pcap_close(in);
       pcap_freealldevs(allDevices);
       now = nullptr;
       in = nullptr;
       return -1;
   }
//   statusBar()->showMessage(now->name);
   return 10;
}

void MainWindow::recvAndHandleMsg(packet data){
    qDebug()<<data.getTimeStmp()<<" "<<data.getInfo();
}
