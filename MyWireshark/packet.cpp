#include "packet.h"
#include <QMetaType>

packet::packet()
{
    qRegisterMetaType<packet>("packet");
    this->time_Stmp = "";
    this->data_Len = 0;
    this->pkg_Type = 0;
}

void packet::setDataLen(unsigned int len){
    this->data_Len = len;
}

void packet::setTimeStmp(QString timeStmp){
    this->time_Stmp = timeStmp;
}

void packet::setPkgInfo(QString info){
    this->info = info;
}

void packet::setPkgContent(const char *content, int sz){
    this->content = content;
    memcpy((char*)(this->content), content, sz);
}

QString packet::getDataLen(){
    return QString::number(this->data_Len);
}

QString packet::getTimeStmp(){
    return this->time_Stmp;
}

QString packet::getPkgType(){
    switch (this->pkg_Type) {
        case 1:return "ARP";
        case 2:return "ICMP";
        case 3:return "TCP";
        case 4:return "UDP";
        case 5:return "DNS";
        case 6:return "TLS";
        case 7:return "SSL";
        default: return "";
    }
}

QString packet::getInfo(){
    return this->info;
}

QString packet::toString(char *s, int sz){
    QString res = "";
    for(int i = 0;i < sz;i++){
        char one = s[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = s[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

