#ifndef SNIFFTHREAED_H
#define SNIFFTHREAED_H
#include <QThread>
#include "packet.h"
#include "pcap.h"


class sniffThreaed:public QThread
{
    Q_OBJECT
signals:
    void sendInfo(packet data);
public:
    sniffThreaed();
    void run() override;
    QString toString(u_char *s, int sz);
    bool setIn(pcap_t *in);
    bool setFlag();
    bool resetFlag();
    int HandlePkg(const u_char *content, QString &info); //ether
    int HandleIpPkg(const u_char *content, int &ipInfo); //ip
    int HandleTcpPkg(const u_char *content, QString &info, int &ipInfo);
    int HandleUdpPkg(const u_char *content, QString &info);
    QString HandleArpPkg(const u_char *content);
private:
    pcap_t *in;
    struct pcap_pkthdr *head;
    const u_char *pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char time[20];
    bool isEnd;
};

#endif // SNIFFTHREAED_H
