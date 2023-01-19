#include "sniffthreaed.h"
#include "PDU.h"
#include <QDebug>

sniffThreaed::sniffThreaed()
{
    this->isEnd = true;
}

bool sniffThreaed::setIn(pcap_t *in){
    this->in = in;
    if(in == nullptr) return false;
    return true;
}

bool sniffThreaed::setFlag(){
    this->isEnd = false;
    return true;
}

bool sniffThreaed::resetFlag(){
    this->isEnd = true;
    return true;
}

void sniffThreaed::run(){
    bool f = true;
    while(f){
        if(!isEnd){
            int cnt = pcap_next_ex(in, &head, &pkt_data);
            if(cnt == 0) continue;
            local_time_sec = head->ts.tv_sec;
            localtime_s(&local_time, &local_time_sec);
            strftime(time, sizeof (time), "%H:%M:%S", &local_time);
            QString info = "";
            int type = HandlePkg(pkt_data, info);
            if(type == 1){
                packet pkg;
                int len = head->len;
                pkg.setPkgInfo(info);
                pkg.setDataLen(len);
                pkg.setTimeStmp(time);
                emit sendInfo(pkg);
            }
        }else{
            f = false;
        }
    }
}

int sniffThreaed::HandlePkg(const u_char *content, QString &info){
    Ether_Header *eth;
    short type;
    eth = (Ether_Header*)content;
    type = ntohs(eth->type);
    switch (type) {
    case 0x0800:{
        int ipInfo = 0;
        int ipType = HandleIpPkg(content, ipInfo);
        if(ipType == 1){
            //icmp
            info = "icmp";
            return 2;
        }else if(ipType == 6){
            //tcp
            return HandleTcpPkg(content, info, ipInfo);
        }else if(ipType == 17){
            //udp
            return HandleUdpPkg(content, info);
        }
        break;
    }
    case 0x0806:{
        info = HandleArpPkg(content);
        return 1;
    }
    default:{
        break;
    }
    }
    return 0;
}

int sniffThreaed::HandleIpPkg(const u_char *content, int &ipInfo){
    Ip_Header *ip;
    ip = (Ip_Header*)(content + 14); //6 + 6 + 2;
    int protocol = ip->protocol;
    ipInfo = (ip->total_length - ((ip->version_len) & 0x0F) * 4);
    return protocol;
}

int sniffThreaed::HandleTcpPkg(const u_char *content, QString &info, int &ipInfo){
    Tcp_Header *tcp;
    tcp = (Tcp_Header*)(content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short dst = ntohs(tcp->des_port);
    QString Send = "", Recv = "";
    int type = 3;
    int lag = (tcp->header_length >> 4) * 4;
    int tcpLoader = ipInfo - lag;
    if(src == 443 || dst == 443){
        if(src == 443){
            Send = "(https)";
        }else{
            Recv = "(https)";
        }
    }else{
        info += QString::number(src) + Send + "-->" + QString::number(dst) + Recv;
    }
    QString flag = "";
    if(tcp->flags & 0x08) flag += "PSH,";
    if(tcp->flags & 0x10) flag += "ACK,";
    if(tcp->flags & 0x02) flag += "SYN,";
    if(tcp->flags & 0x20) flag += "URG,";
    if(tcp->flags & 0x01) flag += "FIN,";
    if(tcp->flags & 0x04) flag += "RDT,";
    if(flag != ""){
        flag = flag.left(flag.length() - 1);
        info += "[" + flag +"]";
    }
    u_int seq = ntohl(tcp->sequence);
    u_int ack = ntohl(tcp->ack);
    u_int win = ntohl(tcp->window_size);
    info += " SEQ=" + QString::number(seq);
    info += "ACK=" + QString::number(ack);
    info += "WIN=" + QString::number(win);
    info += "LEN=" + QString::number(tcpLoader);
    return type;
}

int sniffThreaed::HandleUdpPkg(const u_char *content, QString &info){
    Udp_Header *udp;
    udp = (Udp_Header*)(content + 14 + 20);
    u_short src = ntohs(udp->src_port);
    u_short dst = ntohs(udp->des_port);
    if(src == 53 || dst == 53){
        return 5;
    }else{
        info += QString::number(src) + "-->" + QString::number(dst);
        u_short len = ntohs(udp->data_length);
        info += " LEN=" + QString::number(len);
        return 4;
    }
}
QString sniffThreaed::toString(u_char *s, int sz){
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
QString sniffThreaed::HandleArpPkg(const u_char *content){
    Arp_Header *arp;
    arp = (Arp_Header*)(content + 14);
    QString res = "";
    short op = ntohs(arp->op_code);
    u_char *addr = arp->des_ip_addr;

    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    u_char* srcEthTemp = arp->src_eth_addr;
    QString srcEth = toString(srcEthTemp,1) + ":"
            + toString((srcEthTemp+1),1) + ":"
            + toString((srcEthTemp+2),1) + ":"
            + toString((srcEthTemp+3),1) + ":"
            + toString((srcEthTemp+4),1) + ":"
            + toString((srcEthTemp+5),1);

    switch (op){
    case 1:{
        res  = "Who is " + desIp + "? Plese Tell " + srcIp;
        break;
    }
    case 2:{
        res = srcIp + " is at the" + srcEth;
        break;
    }
    default:break;
    }
    return res;
}
