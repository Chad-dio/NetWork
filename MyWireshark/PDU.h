#ifndef PDU_H
#define PDU_H

typedef unsigned char u_char;     // 1
typedef unsigned short u_short;   // 2
typedef unsigned int u_int;       // 4
typedef unsigned long u_long;     // 4

typedef struct ether_header{
    u_char eth_des_host[6];
    u_char eth_src_host[6];
    u_short type;
} Ether_Header;

typedef struct ip_header{
    u_char version_len;
    u_char TOS;
    u_short total_length;
    u_short identification;
    u_short flag_offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int des_addr;
} Ip_Header;

typedef struct tcp_header{
    u_short src_port;
    u_short des_port;
    u_int sequence;
    u_int ack;
    u_char header_length;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent;
}Tcp_Header;

typedef struct udp_header{
    u_short src_port;
    u_short des_port;
    u_short data_length;
    u_short checksum;
}Udp_Header;

typedef struct icmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
}Icmp_Header;
typedef struct arp_header{
    u_short hardware_type;
    u_short protocol_type;
    u_char mac_length;
    u_char ip_length;
    u_short op_code;
    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char des_eth_addr[6];
    u_char des_ip_addr[4];
}Arp_Header;

#endif // PDU_H
