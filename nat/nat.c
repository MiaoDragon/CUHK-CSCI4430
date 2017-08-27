// usage: ./nat <public ip> <internal ip> <subnet mask>
#define OFFSET 10000    // beginning of available port numbers
#include "checksum.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  //uint*_t
#include <asm/types.h>  //__int*
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// entry of lookup table (tran port -> (original ip, origianl port, state))
// original ip, original port, state
static struct
{
    __u32 oaddr;
    __u16 oport;  // network order
    __u8  state;  // denote in use, FIN state
} table[2001];
//static struct in_addr in;    Do we need this? I'm not sure.
//in_addr_t paddr_struct;
//in_addr_t iaddr_struct;
static __u32 paddr; // public ip
static __u32 iaddr; // internal network ip
static __u32 mask;
static int next = 0;  // next entry in table to add
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *data);
static void printTable();
int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int len;
    char buf[4096];
    // Skeleton of nfq
    // Open library handle
    if (!(h = nfq_open()))
    {
        fprintf(stderr, "Error: nfq_open()\n");
        exit(-1);
    }
    // Unbind existing nfq handler
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error: nfq_unbind_pf()\n");
        exit(1);
    }
    // Bind nfnetlink_queue as nf_queue handler of AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error: nfq_bind_pf()\n");
        exit(1);
    }
    // Bind socket and install a callback on queue 0
    if (!(qh = nfq_create_queue(h, 0, &Callback, NULL)))
    {
        fprintf(stderr, "Error: nfq_create_queue()\n");
        exit(1);
    }
    // Setting packet copy mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "Could not set packet copy mode\n");
        exit(1);
    }
    fd = nfq_fd(h);
    memset(table, 0, sizeof(table));
    inet_aton(argv[1], (struct in_addr*)&paddr);    // network order
    mask = 0xffffffff << (32 - atoi(argv[3]));
    inet_aton(argv[2], (struct in_addr*)&iaddr);
    paddr = ntohl(paddr);
    iaddr = ntohl(iaddr);
    iaddr = iaddr & mask;
    while ((len = recv(fd, buf, sizeof(buf), 0)) && len > 0)
        nfq_handle_packet(h, buf, len);
    // Unbinding from queue 0
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *data)
{
/**
Criteria:  TCP
Inbound:  (src != network)
    port in table?
        T:  IP, TCP header change
            {
                destination IP<-table ip;
                destination port<-table port;
                checksum update; (first TCP (inner), then IP)
            }
        F: drop
Outbound:  (src == network)
    port in table?
        N:  if SYN, then create new entry
            else, drop
    IP, TCP header change
Table delete:
    if the end of 4-way handshake:  delete the FIN-2 entry
    if RST:  delete the entry
Table struct:
    original ip, original port, tran port, state
    * state = 0:  entry not in use
    *         1:  in use, no FIN received
    *         2:  first FIN
    *         3:  second FIN (if ACK received, then delete)
Output:
    when table update, output:
        original ip, original port, tran ip (public ip), tran port
*/
    // get id
    struct nfqnl_msg_packet_hdr *header;   // meta header
    header = nfq_get_msg_packet_hdr(pkt);
    u_int32_t id = ntohl(header->packet_id);
    // get payload
    unsigned char* payload;
    int data_len = nfq_get_payload(pkt, (char**)&payload);
    // payload is network order or host order?
    struct iphdr *iph = (struct iphdr*) payload;
    // check protocol
    if (iph->protocol != IPPROTO_TCP)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    struct tcphdr *tcph = (struct tcphdr*) (((char*)iph)+(iph->ihl << 2));
    int i;  // index of the entry
    // Check inbound, outbound
    char source_addr[50];
    inet_ntop(AF_INET, &iph->saddr, source_addr, sizeof(source_addr));
    __u32 source_ad = ntohl(iph->saddr);
    source_ad &= mask;
    source_ad = htonl(source_ad);
    inet_ntop(AF_INET, &source_ad, source_addr, sizeof(source_addr));
    if ((ntohl(iph->saddr) & mask) != iaddr)
    {
        // Inbound
        // check destination port (is translated port)
        i = ntohs(tcph->dest)-OFFSET;
        if (!table[i].state)   // not in table
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        // modify tcp, ip header
        tcph->dest = table[i].oport;
        iph->daddr = table[i].oaddr;
    }
    else
    {
        //outbound
        //check source port (is original port)
        char linux_addr[50];
        inet_ntop(AF_INET, &iph->daddr, linux_addr, sizeof(linux_addr));
        for (i = 0; i < 2001; i++)
            if (table[i].state && table[i].oport == tcph->source)   break;
        if (i == 2001)  // not in table
        {
            if (!tcph->syn) // not syn
            {
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
                // create new entry
            table[next].state = 1;  table[next].oaddr = iph->saddr;
            table[next].oport = tcph->source;
            i = next;   // the entry in table
            int j;
            // find the next availale place
            for (j = next; j < 2001; j++)
                if (!table[j].state)  break;
            next = j;
            printTable();   //print
        }
        // i now is the entry in the table
        tcph->source = htons(i + OFFSET);
        iph->saddr = htonl(paddr);
    }
    // compute checksum
    tcph->check = tcp_checksum(payload);
    iph->check = ip_checksum(payload);
    // check if can delete table
    if (tcph->rst)
    {
        table[i].state = 0;
        if (i < next)   next = i;   //smaller available place
        printTable();
    }
    else if (tcph->fin)
    {
        table[i].state++;
    }
    else if (tcph->ack && table[i].state == 3)
    {
        table[i].state = 0;
        if (i < next)  next = i;
        printTable();
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, payload);
}

static void printTable()
{
    int i;
    char str_oaddr[20], str_paddr[20];
    printf("|  original address  |   original  port   | translated address |  translated  port  |\n");
    for (i = 0; i < 2001; i++)
        if (table[i].state)
        {
            inet_ntop(AF_INET, &table[i].oaddr, str_oaddr, sizeof(str_oaddr));
            __u32 tmp = htonl(paddr);
            inet_ntop(AF_INET, &tmp, str_paddr, sizeof(str_paddr));
            printf("|%-20s|%-20d|%-20s|%-20d|\n", str_oaddr, ntohs(table[i].oport), str_paddr, i+OFFSET);
        }
}
