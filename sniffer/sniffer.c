/*
 * File:   sniffer.c
 * Author: Jackie Kuo(http://jackiekuo.com), j.kuo2012@gmail.com
 * Date:   2015-07-16
 *
 ********************************************************
 *
 * Compile in gcc:
 *     gcc sniffer.c -o sniffer -lpcap
 *
 ********************************************************
 *
 * Usage:
 *      ./sniffer [-d device] [-f filter expression] [-n number of packets]
 * Note:
 *      parameters in [] is optional
 * Examples:
 *      ./sniffer -f arp -d en1 -n 100
 *      ./sniffer
 *      ./sniffer -f arp
 *
 ********************************************************
 * v0.1 (2015-07-16)
 *      support Ethernet, IPv4, IPv6, ARP, RARP, UDP, TCP, ICMP, ICMPv6
 * v0.2 (2015-07-19)
 *      support DNS
 *
 ********************************************************
 * TODO:
 *      ICMP->Checksum calculation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include "sniffer.h"

#define MAXBYTES2CAPTURE 2048

#define _ICMP    1
#define _TCP     6
#define _UDP    17
#define _ICMPv6 58

#define IPv4_EV  0x0800 /* Ethernet value of IPv4 */
#define IPv6_EV  0x86dd /* Ethernet value of IPv6 */
#define ARP_EV   0x0806 /* Ethernet value of ARP */
#define RARP_EV  0x8035 /* Ethernet value of RARP */

#define _IPv4    0
#define _IPv6    1
#define _ARP     2
#define _RARP    3

#define NLPNUM   4 /* Number of defined Network Layer Protocol values */

u_short NLPvals[NLPNUM] = {IPv4_EV, IPv6_EV, ARP_EV, RARP_EV};
/* Names of Network Layer Protocols */
char NLPnames[][10] = {"IPv4", "IPv6", "ARP", "RARP"};

#define ISSET(flag) ((flag) ? "Set" : "Not set")

void printUsage(void) {
    printf("Usage: ./sniffer %s",
        "[-d device] [-f filter_expression] [-n number_of_packets]\n");
}

void printProtocol(const int protocolNum) {
    switch (protocolNum) {
        case 1  : printf("ICMP");break;
        case 3  : printf("Gateway-to-Gateway");break;
        case 4  : printf("CMCC Gateway Monitoring Message\n");break;
        case 5  : printf("ST");break;
        case 6  : printf("TCP");break;
        case 7  : printf("UCL");break;
        case 9  : printf("Secure");break;
        case 11 : printf("NVP");break;
        case 12 : printf("PUP");break;
        case 13 : printf("Pluribus");break;
        case 14 : printf("Telenet");break;
        case 15 : printf("XNET");break;
        case 16 : printf("Chaos");break;
        case 17 : printf("User Datagram/UDP");break;
        case 18 : printf("Multiplexing");break;
        case 19 : printf("DCN");break;
        case 20 : printf("TAC Monitoring");break;
        case 58 : printf("ICMPv6");break;
        case 63 : printf("any local network");break;
        case 64 : printf("SATNET and Backroom EXPAK");break;
        case 65 : printf("MIT Subnet Support");break;
        case 69 : printf("SATNET Monitoring");break;
        case 71 : printf("Internet Packet Core Utility");break;
        case 76 : printf("Backroom SATNET Monitoring");break;
        case 78 : printf("WIDEBAND Monitoring");break;
        case 79 : printf("WIDEBAND EXPAK");break;
        default : printf("error");
    }
}

void printICMPv6Type(const u_int type) {
    switch (type) {
        case 0   : printf("Reserved"); break;
        case 1   : printf("Destination Unreachable"); break;
        case 2   : printf("Packet Too Big"); break;
        case 3   : printf("Time Exceeded"); break;
        case 4   : printf("Parameter Problem"); break;
        case 128 : printf("Echo Request"); break;
        case 129 : printf("Echo Reply"); break;
        case 130 : printf("Multicast Listener Query"); break;
        case 131 : printf("Multicast Listener Report"); break;
        case 132 : printf("Multicast Listener Done"); break;
        case 133 : printf("Router Solicitation"); break;
        case 134 : printf("Router Advertisement"); break;
        case 135 : printf("Neighbor Solicitation"); break;
        case 136 : printf("Neighbor Advertisement"); break;
        case 137 : printf("Redirect Message"); break;
        case 138 : printf("Router Renumbering"); break;
        case 139 : printf("ICMP Node Information Query"); break;
        case 140 : printf("ICMP Node Information Response"); break;
        case 141 : printf("Inverse Neighbor Discovery"); break;
        case 142 : printf("Inverse Neighbor Discovery"); break;
        case 144 : printf("Home Agent Address Discovery"); break;
        case 145 : printf("Home Agent Address Discovery"); break;
        case 146 : printf("Mobile Prefix Solicitation"); break;
        case 147 : printf("Mobile Prefix Advertisement"); break;
        default  : printf("error");
    }
}

void printDNSOpcode(const u_char opcode) {
    switch (opcode) {
        case 0 : printf("Standard query (QUERY)");break;
        case 1 : printf("Inverse query (IQUERY)");break;
        case 2 : printf("Server status request (STATUS)");break;
        default: printf("error");
    }
}

void printDNSRcode(const u_char rcode) {
    switch (rcode) {
        case 0 : printf("No error (%d)", 0);break;
        case 1 : printf("Format error (%d)", 1);break;
        case 2 : printf("Server failure (%d)", 2);break;
        case 3 : printf("Name Error (%d)", 3);break;
        case 4 : printf("Not Implemented (%d)", 4);break;
        case 5 : printf("Refused (%d)", 5);break;
        default: printf("error");
    }
}

void printDNSType(const u_short dnstype) {
    switch (dnstype) {
        case 1 : printf("A (Host Address)");break;
        case 2 : printf("NS (Authoritative Name Server)");break;
        case 3 : printf("MD (Mail Destination)");break; /* (Obsolete - use MX) */
        case 4 : printf("MF (Mail Forwarder)");break; /* (Obsolete - use MX) */
        case 5 : printf("CNAME (Canonical Name for An Alias)");break;
        case 6 : printf("SOA (Marks the Start of A Zone of Authority)");break;
        case 7 : printf("MB (Mailbox Domain Name)");break; /* (EXPERIMENTAL) */
        case 8 : printf("MG (Mail Group Member)");break; /* (EXPERIMENTAL) */
        case 9 : printf("MR (Mail Rename Domain Name)");break; /* (EXPERIMENTAL) */
        case 10 : printf("NULL (Null RR)");break; /* (EXPERIMENTAL) */
        case 11 : printf("WKS (Well Known Service Description)");break;
        case 12 : printf("PTR (Domain Name Pointer)");break;
        case 13 : printf("HINFO (Host Information)");break;
        case 14 : printf("MINFO (Mailbox or Mail List Information)");break;
        case 15 : printf("MX (Mail Exchange)");break;
        case 16 : printf("TXT (Text Strings)");break;
        case 41 : printf("OPT (Option)");break;
        case 252: printf("AXFR (Transfer of An Entire Zone)");break;
        case 253: printf("MAILB (Mailbox-related Records)");break; /* (MB, MG or MR) */
        case 254: printf("MAILA (Mail Agent RRs)");break; /* (Obsolete - see MX) */
        case 255: printf("* (All Records)");break;
        default : printf("error");
    }
}

void printDNSClass(const u_short dnsclass) {
    switch (dnsclass) {
        case 1 : printf("IN");break;
        case 2 : printf("CS");break;
        case 3 : printf("CH");break;
        case 4 : printf("HS");break;
        case 255: printf("*");break;
        default : printf("error\n");
    }
}

int printDNSName(const u_char *packet, const u_int offset, u_char *count) {
    int i = 0, j;
    while (packet[offset+i] != '\0' && packet[offset+i] != 0xc0) {
        printf("%s", i ? "." : "");
        for (j = 1; j <= packet[offset+i]; ++j) {
            printf("%c", packet[offset+i+j]);
        }
        if (count != NULL) {
            ++(*count);
        }
        i += packet[offset+i]+1;
    }
    if (packet[offset + i] == 0xc0) {
        ++i;
        printf(".");
        printDNSName(packet, packet[offset+i], NULL);
    }
    return i; /* Return name length (bytes) in packets */
}

void printSeperatedLine(const char symbol) {
    int i;
    if (symbol == '-') {
        for (i = 0; i < 20; ++i) {
            printf("-- ");
        }
    } else if (symbol == '*') {
        for (i = 0; i < 30; ++i) {
            printf("**");
        }
    }
    printf("\n");
}

void printIpAddr(const u_char *ipAddr) {
    printf("%u.%u.%u.%u", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
}

void printIpv6Addr(const u_char *ipAddr) {
    printf("%02x%02x::%02x%02x::%02x%02x::%02x%02x::%02x%02x",
        ipAddr[0], ipAddr[1], ipAddr[8], ipAddr[9], ipAddr[10],
        ipAddr[11], ipAddr[12], ipAddr[13], ipAddr[14], ipAddr[15]);
}

void printMacAddr(const u_char *macAddr) {
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        printf("%02x%s", macAddr[i], (i==ETHER_ADDR_LEN-1) ? "" : ":");
    }
}

int nlpNameId(const int ethernetValue) {
    int i;
    for (i = 0; i < NLPNUM; ++i) {
        if (ethernetValue == NLPvals[i]) {
            return i;
        }
    }
    return -1;
}

u_short processTCP(const struct header_tcp *tcp,
    const u_int pktLen, const u_int offset, struct dsport *port) {
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    u_short dorcb = ntohs(tcp->dorcb);
    u_short len = (dorcb>>12)<<2;
    u_short window = ntohs(tcp->window);
    u_short checksum = ntohs(tcp->checksum);
    u_short urp = ntohs(tcp->urp);
    u_char flagNS  = (dorcb&0x100)>>8; /* ECN-nonce concealment protection */
    u_char flagCWR = (dorcb&0x080)>>7; /* Congestion Window Reduced */
    u_char flagECE = (dorcb&0x040)>>6; /* ECN-Echo */
    u_char flagURG = (dorcb&0x020)>>5;
    u_char flagACK = (dorcb&0x010)>>4;
    u_char flagPSH = (dorcb&0x008)>>3;
    u_char flagRST = (dorcb&0x004)>>2;
    u_char flagSYN = (dorcb&0x002)>>1;
    u_char flagFIN = (dorcb&0x001);
    static u_char preFlagPSH;
    static u_int seqnum;
    static u_int acknum;
    static u_int nextSeqnum;
    u_int segdata = pktLen - offset - len; /* Segment data */
    port->sport = sport;
    port->dport = dport;

    printf("Transmission Control Protocol -- TCP");
    printf("\n   |- Source Port:      %-5u (%#04x)", sport, sport);
    printf("\n   |- Destination Port: %-5u (%#04x)", dport, dport);
    if (flagPSH && !flagSYN) {
        if (preFlagPSH) {
            seqnum = nextSeqnum;
        } else {
            acknum = nextSeqnum;
        }
    }
    printf("\n   |- Sequence number:        ");
    if (flagSYN) {
        seqnum = ntohl(tcp->seqnum);
        preFlagPSH = 0;
    }
    printf("%-10u (%#08x)", seqnum, seqnum);
    if (flagPSH) {
        nextSeqnum = seqnum + segdata;
        printf("\n   |- [ Next sequence number: %u ]", nextSeqnum);
        preFlagPSH = 1;
    } else {
        preFlagPSH = 0;
    }
    printf("\n   |- Acknowledgment number:  ");
    if (flagRST) {
        acknum = 0;
    } else if (flagACK) {
        acknum = ntohl(tcp->acknum);
    }
    printf("%-10u (%#08x)", acknum, acknum);

    printf("\n   |- Header Length:    %u bytes", len);
    printf("\n   |- .... 000%u %u%u%u%u %u%u%u%u = Flags: %#03x",
        flagNS, flagCWR, flagECE, flagURG, flagACK,
        flagPSH, flagRST, flagSYN, flagFIN, dorcb&0x0fff);
    printf("\n           000. .... .... = Reversed: Not set");
    printf("\n           ...%u .... .... = NS : %s", flagNS, ISSET(flagNS));
    printf("\n           .... %u... .... = CWR: %s", flagCWR, ISSET(flagCWR));
    printf("\n           .... .%u.. .... = ECE: %s", flagECE, ISSET(flagECE));
    printf("\n           .... ..%u. .... = URG: %s", flagURG, ISSET(flagURG));
    printf("\n           .... ...%u .... = ACK: %s", flagACK, ISSET(flagACK));
    printf("\n           .... .... %u... = PSH: %s", flagPSH, ISSET(flagPSH));
    printf("\n           .... .... .%u.. = RST: %s", flagRST, ISSET(flagRST));
    printf("\n           .... .... ..%u. = SYN: %s", flagSYN, ISSET(flagSYN));
    printf("\n           .... .... ...%u = FIN: %s", flagFIN, ISSET(flagFIN));
    printf("\n   |- Window size value: %u", window);
    printf("\n   |- Checksum:          %#04x", checksum);
    printf("\n   |- Urgent pointer:    %u", urp);
    printf("\n   |- Options:           %u bytes", len-20);
    printf("\n   |- TCP segment data:  %u bytes\n", segdata);
    printSeperatedLine('-');
    return len;
}

void processUDP(const struct header_udp *udp, struct dsport *port) {
    u_short sport = ntohs(udp->sport);
    u_short dport = ntohs(udp->dport);
    u_short len = ntohs(udp->len);
    u_short checksum = ntohs(udp->checksum);
    port->sport = sport;
    port->dport = dport;

    printf("User Datagram Protocol -- UDP");
    printf("\n   |- Source Port:      %-5u (%#04x)", sport, sport);
    printf("\n   |- Destination Port: %-5u (%#04x)", dport, dport);
    printf("\n   |- Length:           %u", len);
    printf("\n   |- Checksum:         %#04x\n", checksum);
    printSeperatedLine('-');
}

void processICMP(const struct header_icmp *icmp) {
    printf("Internet Control Message Protocol -- ICMP");
    printf("\n   |- Type:     %u", icmp->type);
    printf("\n   |- Code:     %u", icmp->code);
    printf("\n   |- Checksum: %#04x", icmp->checksum);
    printf("\n   |- Unused:   %08x\n", icmp->unused);
    printSeperatedLine('-');
}

void processICMPv6(const struct header_icmpv6 *icmp) {
    u_char type = icmp->type; /* Type */

    printf("Internet Control Message Protocol version 6 -- ICMPv6");
    printf("\n   |- Type:     ");
    printICMPv6Type(type);
    printf(" (%u)", type);
    printf("\n   |- Code:     %u", icmp->code);
    printf("\n   |- Checksum: %#04x", icmp->checksum);
    printf("\n   |- Unused:   %08x\n", icmp->unused);
    printSeperatedLine('-');
}

int processIPv4(const struct header_ipv4 *ip, struct dsip *ipAddr) {
    u_char tos = ip->tos;
    u_short len = ntohs(ip->len);
    u_short id = ntohs(ip->id);
    u_short ffo = ntohs(ip->ffo); /* Flags and Fragment Offset */
    u_short flags = ffo>>13;
    u_short protoVal = ip->pro;
    u_short checksum = ntohs(ip->checksum);

    ipAddr->version = 4;
    strcpy((char *)ipAddr->sourAddr, (char *)ip->sourAddr);
    strcpy((char *)ipAddr->destAddr, (char *)ip->destAddr);

    printf("Internet Protocol Version 4 -- IPv4");
    printf("\n   |- Version: %u", (ip->vhl)>>4);
    printf("\n   |- Header Length:   %u bytes", ((ip->vhl)&0x0f)<<2);
    printf("\n   |- Differentiated Services Field: %#04x", tos);
    printf("\n\t%u%u%u%u %u%u.. = Differentiated Services Codepoint: %s (%#02x)",
        (tos&0x080)>>7, (tos&0x040)>>6, (tos&0x020)>>5, (tos&0x010)>>4,
        (tos&0x008)>>3, (tos&0x004)>>2, (tos>>2) ? "Unknown" : "Default", tos>>2);
    printf("\n\t.... ..%u%u = Explicit Congestion Notificaton: (%#02x)",
        (tos&0x002)>>1, tos&0x001, tos&0x003);
    printf("\n   |- Total Length:    %u bytes", len);
    printf("\n   |- Identification:  %#04x (%u)", id, id);
    printf("\n   |- Flags: %#02x", flags);
    printf("\n\t0.. = Reversed bit:   Not set");
    printf("\n\t.%u. = Don't fragment: %s", flags&0x002 ? 1 : 0, ISSET(flags&0x002));
    printf("\n\t..%u = More fragment:  %s", flags&0x001 ? 1 : 0, ISSET(flags&0x001));
    printf("\n   |- Fragment offset: %u", ffo&0x1FFF);
    printf("\n   |- Time to live:    %u", ip->ttl);
    printf("\n   |- Protocol:        ");
    printProtocol(protoVal);
    printf(" (%u)", protoVal);
    printf("\n   |- Header checksum: %#04x", checksum);
    printf("\n   |- Source:          ");
    printIpAddr(ip->sourAddr);
    printf("\n   |- Destination:     ");
    printIpAddr(ip->destAddr);
    printf("\n");
    printSeperatedLine('-');
    return protoVal;
}

int processIPv6(const struct header_ipv6 *ip, struct dsip *ipAddr) {
    u_int vtcfl = ntohl(ip->vtcfl); /* Version, Traffic Class, Flow Label */
    u_char version = vtcfl>>28; /* Version */
    u_short traClass = (vtcfl>>20)&0x0ff; /* Traffic Class */
    u_int flowLbl = vtcfl&0x000fffff; /* Flow Label */
    u_short payLen = ntohs(ip->paylen); /* Payload Length */
    u_char protoVal = ip->nexthdr; /* Protocol */

    ipAddr->version = 6;
    strcpy((char *)ipAddr->sourAddr, (char *)ip->sourAddr);
    strcpy((char *)ipAddr->destAddr, (char *)ip->destAddr);

    printf("Internet Protocol Version 6 -- IPv6");
    printf("\n   |- Version: %u", version);
    printf("\n   |- Traffic Class:  %#08x", traClass);
    printf("\n   |- Flow Label:     %#08x", flowLbl);
    printf("\n   |- Payload length: %u", payLen);
    printf("\n   |- Next header:    ");
    printProtocol(protoVal);
    printf(" (%u)", protoVal);
    printf("\n   |- Hop limit:      %u", ip->hoplmt);
    printf("\n   |- Source:         ");
    printIpv6Addr(ip->sourAddr);
    printf("\n   |- Destination:    ");
    printIpv6Addr(ip->destAddr);
    printf("\n");
    printSeperatedLine('-');
    return protoVal;
}

void processARP(const struct header_arp *arp) {
    u_short hrd = ntohs(arp->hrd);
    u_short protoVal = ntohs(arp->pro);
    u_short op = ntohs(arp->op);

    printf("Address Resolution Protocol -- ARP");
    printf("\n   |- Hardware type: %s (%u)", hrd==1 ? "Ethernet" : "Unknown", hrd);
    printf("\n   |- Protocol type: ");
    int nlpVal = nlpNameId(protoVal);
    if (nlpVal != -1) {
        printf("%s (%#04x)", NLPnames[nlpVal], protoVal);
    } else {
        printf("Type not found");
    }
    printf("\n   |- Hardware size: %u", arp->hlen);
    printf("\n   |- Protocol size: %u", arp->plen);
    printf("\n   |- Opcode:        %s (%u)",
        op==1 ? "REQUEST":(op==2 ? "REPLY" : "ERROR"), op);
    printf("\n   |- Sender MAC address: ");
    printMacAddr(arp->sha);
    printf("\n   |- Sender IP address:  ");
    printIpAddr(arp->spa);
    printf("\n   |- Target MAC address: ");
    printMacAddr(arp->tha);
    printf("\n   |- Target IP address:  ");
    printIpAddr(arp->tpa);
    printf("\n");
    printSeperatedLine('-');
}

void processRARP(const struct header_rarp *rarp) {
    u_short hrd = ntohs(rarp->hrd);
    u_short protoVal = ntohs(rarp->pro);
    u_short op = ntohs(rarp->op);

    printf("Reverse Address Resolution Protocol -- RARP");
    printf("\n   |- Hardware type: %s (%u)", hrd==1 ? "Ethernet" : "Unknown", hrd);
    printf("\n   |- Protocol type: ");
    int nlpVal = nlpNameId(protoVal);
    if (nlpVal != -1) {
        printf("%s (%#04x)", NLPnames[nlpVal], protoVal);
    } else {
        printf("Type not found");
    }
    printf("\n   |- Hardware size: %u", rarp->hlen);
    printf("\n   |- Protocol size: %u", rarp->plen);
    printf("\n   |- Opcode:        %s (%u)",
        op==3 ? "REQUEST REVERSE" : (op==4 ? "REPLY REVERSE" : "ERROR"), op);
    if (op == 3) {
        printf("\n   |- Sender MAC address: ");
        printMacAddr(rarp->sha);
        printf("\n   |- Sender IP address:  ");
        printIpAddr(rarp->spa);
        printf("\n   |- Target MAC address: ");
        printMacAddr(rarp->tha);
        printf("\n   |- Target IP address:  ");
        printIpAddr(rarp->tpa);
    } else if (op == 4) {
        printf("\n   |- Responder MAC address: ");
        printMacAddr(rarp->sha);
        printf("\n   |- Responder IP address: ");
        printIpAddr(rarp->spa);
        printf("\n   |- Target MAC address:  ");
        printMacAddr(rarp->tha);
        printf("\n   |- Target IP address:   ");
        printIpAddr(rarp->tpa);
    }
    printf("\n");
    printSeperatedLine('-');
}

int processEtherHeader(const struct header_ethernet *ethernet) {
    printf("Ethernet II");
    printf("\n   |- Destination: ");
    printMacAddr(ethernet->dest);
    printf("\n   |- Source:      ");
    printMacAddr(ethernet->sour);
    printf("\n   |- Type:        ");
    u_short ethernetValue = ntohs(ethernet->type);
    int nlpVal = nlpNameId(ethernetValue);
    if (nlpVal != -1) {
        printf("%s (%#04x)\n", NLPnames[nlpVal], ethernetValue);
    } else {
        printf("Type not found\n");
    }
    return nlpVal;
    printSeperatedLine('-');
}

void processDNS(const u_char *packet) {
    struct header_dns *dnshdr = (struct header_dns *)packet;
    u_short flags = ntohs(dnshdr->flags);
    u_char qr = flags>>15; /* query(0) or response(1) */
    u_char opcode = (flags>>11)&0x00f; /* Opcode */
    u_char aa = (flags>>10)&0x001; /* Authoritative Answer */
    u_char tc = (flags>>9)&0x001; /* TrunCation */
    u_char rd = (flags>>8)&0x001; /* Recursion desired */
    u_char ra = (flags>>7)&0x001; /* Recursion available */
    u_char an = (flags>>5)&0x001; /* Answer authenticated */
    u_char nd = (flags>>4)&0x001; /* Non-authenticated data */
    u_char rcode = flags&0x00f; /* Reply code */
    u_short qdcount = ntohs(dnshdr->qdcount);
    u_short ancount = ntohs(dnshdr->ancount);
    u_short nscount = ntohs(dnshdr->nscount);
    u_short arcount = ntohs(dnshdr->arcount);
    int offset = 0;

    printf("Domain Name System -- DNS");
    printf("\n   |- Transaction ID: %#04x", ntohs(dnshdr->tid));
    printf("\n   |- Flags: %#04x", flags);
    printf("\n      %u... .... .... .... = Response: Message is a %s",
        qr, qr ? "response" : "query");
    printf("\n      .%u%u%u %u... .... .... = Opcode: ",
        (flags>>14)&0x001, (flags>>13)&0x001, (flags>>12)&0x001, (flags>>11)&0x001);
    printDNSOpcode(opcode);
    if (qr == _RESPONSE) {
        printf("\n      .... .%u.. .... .... = Authoritative: ", aa);
        printf("Server is %san authority for domain", aa ? "" : "not ");
    }
    printf("\n      .... ..%u. .... .... = Truncated: Message is %struncated",
        tc, tc ? "" : "not ");
    printf("\n      .... ...%u .... .... = Recursion desired: ", rd);
    printf("Do query %srecursively", rd ? "" : "not ");
    printf("\n      .... .... %u... .... = Recursion available: ", ra);
    printf("Server can %sdo recursive queries", ra ? "" : "not ");
    printf("\n      .... .... .0.. .... = Z: reserved (0)");
    if (qr == _RESPONSE) {
        printf("\n      .... .... ..%u. .... = Answer authenticated: ", an);
        printf("Answer/authority portion was %sauthenticated by the server",
            an ? "" : "not ");
    }
    printf("\n      .... .... ...%u .... = Non-authenticated data: %s",
        nd, nd ? "Acceptable" : "Unacceptable");
    if (qr == _RESPONSE) {
        printf("\n      .... .... .... %u%u%u%u = Reply code: ",
            rcode>>3, (rcode>>2)&0x001, (rcode>>1)&0x001, rcode&0x001);
        printDNSRcode(rcode);
    }
    printf("\n   |- Questions: %d", qdcount);
    printf("\n   |- Answer RRs: %d", ancount);
    printf("\n   |- Authority RRs: %d", nscount);
    printf("\n   |- Additional RRs: %d", arcount);
    offset += SIZE_DNS;
    if (qdcount) {
        char *qname;
        u_char qnameLen;
        u_char lblCount;
        u_short *qtype;
        u_short *qclass;

        printf("\n   |- Queries");
        int i;
        for (i = 0; i < qdcount; ++i) {
            qname = (char *)(packet+offset);
            qnameLen = strlen(qname) - 1;
            offset += qnameLen + 2;
            qtype = (u_short *)(packet+offset);
            offset += 2;
            qclass = (u_short *)(packet+offset);
            offset += 2;
            *qtype = ntohs(*qtype);
            *qclass = ntohs(*qclass);
            printf("\n        Name:  ");
            lblCount = 0;
            printDNSName((u_char *)packet, (int)qname-(int)packet, &lblCount);
            printf("\n        [ Name Length: %u ]", qnameLen);
            printf("\n        [ Label Count: %u ]", lblCount);
            printf("\n        Type:  ");
            printDNSType(*qtype);
            printf(" (%d)", *qtype);
            printf("\n        Class: ");
            printDNSClass(*qclass);
            printf(" (%#04x)", *qclass);
            printf("\n");
        }
    }
    if (ancount) {
        char *aname;
        u_short *anameOff;
        u_short *atype;
        u_short *aclass;
        u_int *ttl;
        u_short *dlen; /* Data length */

        printf("\n   |- Answers");
        int i;
        for (i = 0; i < ancount; ++i) {
            printf("\n        Name:  ");
            anameOff = (u_short *)(packet + offset);
            *anameOff = ntohs(*anameOff);
            *anameOff = (*anameOff)&0x0fff;
            aname = (char *)(packet + *anameOff);
            offset += 2;
            printDNSName((u_char *)packet, (int)aname-(int)packet, NULL);
            atype = (u_short *)(packet + offset);
            *atype = ntohs(*atype);
            offset += 2;
            printf("\n        Type:  ");
            printDNSType(*atype);
            printf(" (%d)", *atype);
            aclass = (u_short *)(packet + offset);
            *aclass = ntohs(*aclass);
            offset += 2;
            printf("\n        Class: ");
            printDNSClass(*aclass);
            printf(" (%#04x)", *aclass);
            ttl = (u_int *)(packet + offset);
            *ttl = ntohl(*ttl);
            offset += 4;
            printf("\n        Time to live: %u", *ttl);
            dlen = (u_short *)(packet + offset);
            *dlen = ntohs(*dlen);
            offset += 2;
            printf("\n        Data length:  %u", *dlen);
            switch (*atype) {
                case _A:
                    printf("\n        Address: ");
                    printIpAddr((u_char *)(packet + offset));
                    offset += 4;
                    break;
                case _CNAME:
                    printf("\n        CNAME: ");
                    offset += 1 + printDNSName((u_char *)(packet), offset, NULL);
                    break;
            }
            printf("\n");
        }
    }
    if (arcount) {
        struct addRec *addRec;
        u_char cacheFlush;
        u_short udpPayload;

        printf("\n   |- Additional Records");
        int i;
        for (i = 0; i < arcount; ++i) {
            addRec = (struct addRec *)(packet + offset);
            cacheFlush = (addRec->dnsclass)>>15;
            udpPayload = (addRec->dnsclass)&0x7fff;
            offset += sizeof(addRec);
            printf("\n        Name: %s", addRec->name ? "error" : "<Root>");
            printf("\n        Type: ");
            printDNSType(addRec->type);
            printf(" (%u)", addRec->type);
            printf("\n          %u... .... .... .... = Cache flush: %s",
                cacheFlush, cacheFlush ? "True" : "False");
            printf("\n          .%u%u%u %u%u%u%u %u%u%u%u %u%u%u%u = UDP payload size: %#04x",
                udpPayload>>14, (udpPayload>>13)&0x001, (udpPayload>>12)&0x001,
                (udpPayload>>11)&0x001, (udpPayload>>10)&0x001, (udpPayload>>9)&0x001,
                (udpPayload>>8)&0x001, (udpPayload>>7)&0x001, (udpPayload>>6)&0x001,
                (udpPayload>>5)&0x001, (udpPayload>>4)&0x001, (udpPayload>>3)&0x001,
                (udpPayload>>2)&0x001, (udpPayload>>1)&0x001, udpPayload&0x001,
                udpPayload);
            printf("\n        Higher bits in extended RCODE: %#04x", addRec->exrcode);
            printf("\n        EDNS0 version: %d", addRec->version);
            printf("\n        Z: %#04x", addRec->z);
            printf("\n        Data length: %u", addRec->dlen);
            printf("\n        Option:");
            printf("\n           Option Code:   %s (%u)",
                addRec->opcode==4 ? "Owner" : "Unknown", addRec->opcode);
            printf("\n           Option Length: %u", addRec->oplen);
            printf("\n           Option Data:   %s", addRec->opdata);
            printf("\n");
        }
    }
    printf("\n");
    printSeperatedLine('-');
}

void processHTTP(const u_char *packet, const u_int pktLen) {
    char *version = strstr((char *)packet, "HTTP/");
    if (version == NULL) {
        return;
    }
    int messageType = ((int)packet == (int)version) ? _RESPONSE : _REQUEST;
    int i;
    printf("Hypertext Transfer Protocol -- HTTP");
    if (messageType == _RESPONSE) {
        printf("\n           Request Version: ");
        for (i = 0; i < 8; ++i) {
            printf("%c", *(version + i));
        }
        printf("\n           Status Code:     ");
        for (i = 9; i < 12; ++i) {
            printf("%c", *(version + i));
        }
        printf("\n           Response Phrase: ");
        for (i = 13; *(version + i) != 0x0d; ++i) {
            printf("%c", *(version + i));
        }
    } else {
        printf("\n           Request Method:  ");
        for (i = 0; *(packet + i) != 0x20; ++i) {
            printf("%c", *(packet + i));
        }
        printf("\n           Request Version: ");
        for (i = 0; i < 8; ++i) {
            printf("%c", *(version + i));
        }
    }
    printf("\n   |- ");
    for (i = 0; i < pktLen; ++i) {
        printf("%c", packet[i]);
        if (packet[i] == 0x0a) {
            printf("   |- ");
        }
        if (packet[i] == 0x0d && packet[i+1] == 0x0a
            && packet[i+2] == 0x0d && packet[i+3] == 0x0a) {
            break;
        }
    }
    printf("\n");
    printSeperatedLine('-');
    printf("\n");
}

void processALP(const struct dsport *port, const struct dsip *ipAddr,
    const u_char *packet, const u_int pktLen) {
    switch (port->sport) {
        case _DNS:  processDNS(packet);return;
        case _HTTP: processHTTP(packet, pktLen);return;
    }
    switch (port->dport) {
        case _DNS:  processDNS(packet);return;
        case _HTTP: processHTTP(packet, pktLen);return;
    }
}

void processPacket(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet) {
    u_int *counter = (u_int *)arg;
    u_int pktLen = header->len;
    int nlpVal; /* Network Layer Protocol values */
    int tlpVal = -1; /* Transport Layer Protocol values */
    int alpVal = -1; /* Application Layer Protocol values */
    struct dsport port; /* Port get from Transport Layer */
    struct dsip ip; /* IP get from Network Layer */
    u_int pktOff = 0; /* Packet Offset */

    printf("Packet Count: %u\n", ++(*counter));
    printf("Packet Size:  %u bytes (%u bits)\n", pktLen, pktLen<<3);
    /* Deal with Data Link Layer */
    printSeperatedLine('-');
    nlpVal = processEtherHeader((struct header_ethernet *)packet);
    pktOff += SIZE_ETHERNET;
    /* Deal with Network Layer */
    switch (nlpVal) {
        case _IPv4 :
            tlpVal = processIPv4((struct header_ipv4 *)(packet + pktOff), &ip);
            pktOff += SIZE_IPv4;
            break;
        case _IPv6 :
            tlpVal = processIPv6((struct header_ipv6 *)(packet + pktOff), &ip);
            pktOff += SIZE_IPv6;
            break;
        case _ARP  : processARP((struct header_arp *)(packet + pktOff));break;
        case _RARP : processRARP((struct header_rarp *)(packet + pktOff));break;
        default    : printf("Protocol not supported\n");
    }
    /* Deal with Transport Layer */
    switch (tlpVal) {
        case _ICMP :
            processICMP((struct header_icmp *)(packet + pktOff));
            break;
        case _TCP :
            pktOff += processTCP((struct header_tcp *)(packet + pktOff), pktLen, pktOff, &port);
            if (pktOff == pktLen) {
                break;
            }
            processALP(&port, &ip, (u_char *)(packet + pktOff), pktLen - pktOff);
            break;
        case _UDP :
            processUDP((struct header_udp *)(packet + pktOff), &port);
            pktOff += SIZE_UDP;
            processALP(&port, &ip, (u_char *)(packet + pktOff), pktLen - pktOff);
            break;
        case _ICMPv6 :
            processICMPv6((struct header_icmpv6 *)(packet + pktOff));
            break;
        default : printf("Protocol not supported\n");
    }
    /* Deal with Application Layer */
    ;

    int i, j;
    /* Print packet bytes */
    for (i = 0; i < pktLen; i += 0x010) {
        printf("%04x\t", i);
        for (j = 0; j < 0x010; ++j) {
            printf("%02x%s ", packet[i+j], j==7 ? " " : "");
        }
        printf("\t");
        for (j = 0; j < 0x010; ++j) {
            printf("%c", isprint(packet[i+j]) ? packet[i+j] : '.');
        }
        printf("\n");
    }
    printf("\n");
    printSeperatedLine('*');
    printf("\n");
}

int main(int argc, char const *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    pcap_t *handle;                /* Session handle */
    struct bpf_program filter;     /* Compiled filter expression */
    bpf_u_int32 mask;              /* Netmask of our sniffing device */
    bpf_u_int32 net;               /* IP of our sniffing device */
    const u_char *packet;          /* Packet */
    const char *device;            /* Device to sniff on */
    const char *filter_exp = "";   /* Filter expression, defalut: none */
    int packets_num = -1;          /* Number of packets, default: infinite */
    u_int counter = 0;             /* Packet Counter */
    /* Define the device */
    device = pcap_lookupdev(errbuf);

    if (argc > 1) {
        int i;
        for (i = 1; i < argc; i += 2) {
            if (argv[i][0] != '-' || !(argc & 1)) {
                printUsage();
                return 2;
            }
            switch (argv[i][1]) {
                case 'd' :
                    device = argv[i+1];break;
                case 'f' :
                    filter_exp = argv[i+1];break;
                case 'n' :
                    packets_num = atoi(argv[i+1]);break;
                default :
                    printUsage();
                    return 2;
            }
        }
    }

    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Device: %s\n", device);
    printSeperatedLine('*');
    /* Find the properties for the device */
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 2;
    }
    /* Compile the filter */
    if (pcap_compile(handle, &filter, filter_exp, 1, mask) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    /* Apply the filter */
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, packets_num, &processPacket, (u_char *)&counter);
    /* Close the session */
    pcap_freecode(&filter);
    pcap_close(handle);
    return 0;
}