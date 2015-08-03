/*
 * File:   nslookup.c
 * Author: Jackie Kuo(http://jackiekuo.com), j.kuo2012@gmail.com
 * Date:   2015-07-20
 *
 ********************************************************
 *
 * Compile in gcc:
 *     gcc nslookup.c -o nslookup -lpcap
 *
 ********************************************************
 *
 * Usage:
 *      ./nslookup [-d device] [-n number of packets]
 * Note:
 *      parameters in [] is optional
 * Examples:
 *      ./nslookup -d en1 -n 100
 *      ./nslookup
 *
 ********************************************************
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "sniffer.h"

#define MAXBYTES2CAPTURE 2048

void printUsage(void) {
    printf("Usage: ./nslookup %s",
        "[-d device] [-n number_of_packets]\n");
}

void printIpAddr(const u_char *ipAddr) {
    printf("%u.%u.%u.%u", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
}

void processIPv4(const struct header_ipv4 *ip, struct dsip *ipAddr) {
    strcpy((char *)(ipAddr->sourAddr), (char *)(ip->sourAddr));
    strcpy((char *)(ipAddr->destAddr), (char *)(ip->destAddr));
}

void processUDP(const struct header_udp *udp, struct dsport *port) {
    port->sport = ntohs(udp->sport);
    port->dport = ntohs(udp->dport);
}

int printDNSName(const u_char *packet, const u_int offset) {
    int i, j;
    for (i = 0; packet[offset+i] != '\0' && packet[offset+i] != 0xc0; i += packet[offset+i]+1) {
        printf("%s", i?".":"");
        for (j=1; j <= packet[offset+i]; ++j) {
            printf("%c", packet[offset+i+j]);
        }
    }
    if (packet[offset + i] == 0xc0) {
        ++i;
        printf(".");
        printDNSName(packet, packet[offset+i]);
    }
    return i;
}

void processDNS(const u_char *packet, const struct dsip *ipAddr, const struct dsport *port) {
    struct header_dns *dnshdr = (struct header_dns *)packet;
    u_short flags = ntohs(dnshdr->flags);
    u_char qr = flags>>15; /* query(0) or response(1) */
    u_char aa = (flags>>10)&0x001; /* Authoritative Answer */
    u_short qdcount = ntohs(dnshdr->qdcount);
    u_short ancount = ntohs(dnshdr->ancount);
    int offset = 0;
    if (!ancount || qr != _RESPONSE) {
        return;
    }
    if (port->sport == _DNS) {
        printf("Server:   ");
        printIpAddr(ipAddr->sourAddr);
        printf("\nAddress:  ");
        printIpAddr(ipAddr->sourAddr);
    } else if (port->dport == _DNS) {
        printf("Server:   ");
        printIpAddr(ipAddr->destAddr);
        printf("\nAddress:  ");
        printIpAddr(ipAddr->destAddr);
    }
    printf("#%d\n", _DNS);
    printf("\n   |- Questions:  %d", qdcount);
    printf("\n   |- Answer RRs: %d", ancount);

    offset += SIZE_DNS;
    if (qdcount) {
        printf("\n   |- Queries");
        char *qname;
        int i;
        for (i = 0; i < qdcount; ++i) {
            qname = (char *)(packet+offset);
            offset += strlen(qname) + 5;
            printf("\n        Name:    ");
            printDNSName((u_char *)packet, (int)qname-(int)packet);
            printf("\n");
        }
    }
    if (ancount) {
        printf("\n   |- Answers  (%suthoritative answer)", aa?"A":"Non-a");
        u_short *anameOff;
        char *aname;
        u_short *atype;
        int i;
        for (i = 0; i < ancount; ++i) {
            anameOff = (u_short *)(packet + offset);
            *anameOff = ntohs(*anameOff)&0x0fff;
            aname = (char *)(packet + *anameOff);
            offset += 2;
            atype = (u_short *)(packet + offset);
            *atype = ntohs(*atype);
            offset += 10;
            switch (*atype) {
                case _A:
                    printf("\n        Name:    ");
                    printDNSName((u_char *)packet, (int)aname-(int)packet);
                    printf("\n        Address: ");
                    printIpAddr((u_char *)(packet + offset));
                    offset += 4;
                    break;
                case _CNAME:
                    printf("\n        ");
                    printDNSName((u_char *)packet, (int)aname-(int)packet);
                    printf("   canonical name =  "); 
                    offset += 1 + printDNSName((u_char *)(packet), offset);
                    break;
            }
        }
    }
    printf("\n************************************************************\n");
}

void processPacket(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet) {
    struct dsport port; /* Port get from Transport Layer */
    struct dsip ip; /* IP get from Network Layer */
    u_int pktOff = 0; /* Packet Offset */
    /* Deal with Data Link Layer */
    pktOff += SIZE_ETHERNET;
    /* Deal with Network Layer */
    processIPv4((struct header_ipv4 *)(packet + pktOff), &ip);
    pktOff += SIZE_IPv4;
    /* Deal with Transport Layer */
    processUDP((struct header_udp *)(packet + pktOff), &port);
    pktOff += SIZE_UDP;
    processDNS((u_char *)(packet+pktOff), &ip, &port);
}

int main(int argc, char const *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    pcap_t *handle;                /* Session handle */
    struct bpf_program filter;     /* Compiled filter expression */
    bpf_u_int32 mask;              /* Netmask of our sniffing device */
    bpf_u_int32 net;               /* IP of our sniffing device */
    const u_char *packet;          /* Packet */
    const char *device;            /* Device to sniff on */
    const char *filter_exp = "port 53";   /* Filter expression, defalut: none */
    int packets_num = -1;          /* Number of packets, default: infinite */
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

    pcap_loop(handle, packets_num, &processPacket, (u_char *)NULL);
    /* Close the session */
    pcap_freecode(&filter);
    pcap_close(handle);
    return 0;
}