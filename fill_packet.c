#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#define TTL 1

void 
fill_iphdr ( struct ip* ip_hdr , const char* dst_ip)
{
    struct in_addr dst,src;
	inet_pton(AF_INET,dst_ip,&dst);
    ip_hdr->ip_dst = dst;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5; //*4
    ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct icmp)+ 18; //not sure
    ip_hdr->ip_id = htons(321);
    ip_hdr->ip_off = htons(0);
    ip_hdr->ip_ttl = (unsigned char)TTL;
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_sum = 0;
    //inet_pton(AF_INET,"10.0.2.15",&src);
    //ip_hdr->ip_src = src;
}

void
fill_icmphdr (struct icmp* icmp_hdr,int seq)
{
	icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = 0;
    icmp_hdr->icmp_seq = seq;
}

u16
fill_cksum(unsigned short *hdr,int len)
{
	int nleft = len;
    int sum = 0;
    unsigned short *w = (unsigned short *)hdr;
    unsigned short result = 0;

    while(nleft>1){
        sum += *w++;
        nleft-=2;
    }

    if(nleft == 1){
        *(unsigned *)(&result) = *(unsigned char *)w;
        sum+=result;
    }
    sum =(sum >> 16)+(sum & 0xffff);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}