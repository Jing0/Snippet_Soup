/*
 * File:   sniffer.h
 * Author: Jackie Kuo(http://jackiekuo.com), j.kuo2012@gmail.com
 * Date:   2015-07-16
 *
 *
 */
#define _RESPONSE       1
#define _QUERY          0
#define _REQUEST        0

#define _DNS           53
#define _HTTP          80

#define SIZE_ETHERNET  14 /* Ethernet headers are 14 bytes */
#define SIZE_IPv4      20 /* Internet protocol version 4 headers are 20 bytes */
#define SIZE_IPv6      40 /* Internet protocol version 6 headers are 40 bytes */
#define SIZE_UDP        8 /* User datagram protocol headers are 8 bytes */
#define SIZE_DNS       12 /* DNS headers are 12 bytes */
#define ETHER_ADDR_LEN  6 /* Ethernet addresses are 6 bytes */
#define IP_ADDR_LEN     4 /* IPv4 addresses are 4 bytes */
#define IP6_ADDR_LEN   16 /* IPv 6 addresses are 16 bytes */

#define _A             1
#define _NS            2
#define _MD            3
#define _MF            4
#define _CNAME         5
#define _SOA           6
#define _MB            7
#define _MG            8
#define _MR            9
#define _NULL         10
#define _WKS          11
#define _PTR          12
#define _TXT          16

struct header_ethernet {
    u_char dest[ETHER_ADDR_LEN]; /* Destination address */
    u_char sour[ETHER_ADDR_LEN]; /* Source address */
    u_short type;
};

struct header_ipv4 {
    u_char vhl;                   /* Version and Internet header length */
    u_char tos;                   /* Type of service */
    u_short len;                  /* Total length */
    u_short id;                   /* Identification */
    u_short ffo;                  /* Flags and Fragment Offset */
    u_char ttl;                   /* Time to live */
    u_char pro;                   /* Protocol */
    u_short checksum;             /* Header checksum */
    u_char sourAddr[IP_ADDR_LEN]; /* Source address */
    u_char destAddr[IP_ADDR_LEN]; /* Destination address */
};

struct header_ipv6 {
    u_int vtcfl;                   /* Version, traffic class, flow label */
    u_short paylen;                /* Payload length */
    u_char nexthdr;                /* Next header */
    u_char hoplmt;                 /* Hop limit */
    u_char sourAddr[IP6_ADDR_LEN]; /* Source address */
    u_char destAddr[IP6_ADDR_LEN]; /* Destination address */
};

struct header_arp {
    u_short hrd;                /* Hardware type */
    u_short pro;                /* Protocol type */
    u_char hlen;                /* Byte length of each hardware address */
    u_char plen;                /* Byte length of each protocol address */
    u_short op;                 /* Opcode */
    u_char sha[ETHER_ADDR_LEN]; /* Hardware address of sender of this packet */
    u_char spa[IP_ADDR_LEN];    /* Protocol address of sender of this packet */
    u_char tha[ETHER_ADDR_LEN]; /* Hardware address of target of this packet */
    u_char tpa[IP_ADDR_LEN];    /* Protocol address of target of this packet */
};

/* RARP uses the same packet format that is used by ARP */
struct header_rarp {
    u_short hrd;                /* Hardware type */
    u_short pro;                /* Protocol type */
    u_char hlen;                /* Byte length of each hardware address */
    u_char plen;                /* Byte length of each protocol address */
    u_short op;                 /* Opcode */
    u_char sha[ETHER_ADDR_LEN]; /* Hardware address of sender of this packet */
    u_char spa[IP_ADDR_LEN];    /* Protocol address of sender of this packet */
    u_char tha[ETHER_ADDR_LEN]; /* Hardware address of target of this packet */
    u_char tpa[IP_ADDR_LEN];    /* Protocol address of target of this packet */
};

struct header_tcp {
    u_short sport;    /* Source port number */
    u_short dport;    /* Destination port number */
    u_int seqnum;     /* Sequence number of the first data octet in this segment */
    u_int acknum;     /* If the ACK control bit is set this field contains the value
    of the next sequence number */
    u_short dorcb;    /* Data offset, reserved and control bits */
    u_short window;   /* Number of data octets beginning with the one indicated
    in the acknowledgment field which the sender of this segment is willing to accept */
    u_short checksum; /* Checksum */
    u_short urp;      /* Urgent pointer */
    u_int options;    /* Options */
};

struct header_udp {
    u_short sport;    /* Source port number */
    u_short dport;    /* Destination port number */
    u_short len;      /* Length in octets of this user datagram including this
    header and the data(This means the minimum value of the length is eight) */
    u_short checksum; /* Checksum */
};

struct header_icmp {
    u_char type;      /* Type */
    u_char code;      /* Code */
    u_short checksum; /* Checksum */
    u_int unused;     /* Unused */
};

struct header_icmpv6 {
    u_char type;      /* Type */
    u_char code;      /* Code */
    u_short checksum; /* Checksum */
    u_int unused;     /* Unused */
};

struct header_dns {
    u_short tid;     /* Transaction ID */
    u_short flags;   /* Flags -- 
    qr:1, opcode:4, aa:1, tc:1, rd:1, ra:1, z(reserved,0):3, rcode:4 */
    u_short qdcount; /* Question */
    u_short ancount; /* Answer */
    u_short nscount; /* Authority */
    u_short arcount; /* Additional */
};

/* Destination and Source IP, use version to differ IPv4 from IPv6 */
struct dsip {
    u_char version;
    u_char sourAddr[IP6_ADDR_LEN]; /* Source address */
    u_char destAddr[IP6_ADDR_LEN]; /* Destination address */
};

/* Destination and Source port */
struct dsport {
    u_short sport;    /* Source port */
    u_short dport;    /* Destination port */
};

/* additional records */
struct addRec {
    u_char name;
    u_short type;
    u_short dnsclass;
    u_char exrcode; /* Higher bits in extended RCODE */
    u_char version;
    u_short z;
    u_char dlen;
    u_short opcode; /* Option code */
    u_short oplen; /* Option length */
    #define OPDATA_LEN 8
    u_char opdata[OPDATA_LEN]; /* 8 bytes */
};

/*
void printProtocol(const int protocolNum);
void printICMPv6Type(const u_int type);
void printDNSOpcode(const u_char opcode);
void printDNSRcode(const u_char rcode);
void printDNSType(const u_short dnstype);
void printDNSClass(const u_short dnsclass);
void printSeperatedLine(const char symbol);
void printIpAddr(const u_char *ipAddr);
void printIpv6Addr(const u_char *ipAddr);
void printMacAddr(const u_char *macAddr);
int nlpNameId(const int ethernetValue);
void processTCP(const struct header_tcp *tcp, const u_int pktLen,
    const u_int offset, struct dsport *port);
void processUDP(const struct header_udp *udp, struct dsport *port);
void processICMP(const struct header_icmp *icmp);
void processICMPv6(const struct header_icmpv6 *icmp);
int processIPv6(const struct header_ipv6 *ip, struct dsip *ipAddr);
void processARP(const struct header_arp *arp);
void processRARP(const struct header_rarp *rarp);
int processEtherHeader(const struct header_ethernet *ethernet);
void processALP(const struct dsport *port, const struct dsip *ipAddr, 
    const u_char *packet);
void processPacket(
    u_char *arg, const struct pcap_pkthdr *header, const u_char *packet);
void printUsage(void);
*/