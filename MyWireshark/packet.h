#ifndef PACKET_H
#define PACKET_H
#include "PDU.h"
#include <QString>

class packet
{
private:
    int data_Len;
    int pkg_Type;
    QString info;
    QString time_Stmp;
protected:
    const char *content;
public:
    packet();
    QString toString(char *s, int sz);
    void setDataLen(unsigned int length);
    void setTimeStmp(QString timeStmp);
    void setPkgType(int type);
    void setPkgContent(const char *pkt_content,int sz);
    void setPkgInfo(QString info);

    QString getDataLen();
    QString getTimeStmp();
    QString getPkgType();
    QString getInfo();
    QString getSrc();
    QString getDes();
};

#endif // PACKET_H
