#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>

#include <stdio.h>
#include "pcap/pcap.h"
#include "winsock2.h"
#include "packet.h"
#include <QDebug>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
public slots:
    void recvAndHandleMsg(packet data);

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    pcap_if_t *allDevices;
    pcap_if_t *now;
    pcap_t *in;
    char errbuf[PCAP_ERRBUF_SIZE];
};
#endif // MAINWINDOW_H
