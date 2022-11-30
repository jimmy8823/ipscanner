#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <time.h>

#include "fill_packet.h"
#include "pcap.h"

#define IP_HDR_LEN 20
pid_t pid;


int main(int argc, char* argv[])
{
	struct in_addr inaddr;
	int sockfd;
	char src_ip[15]={'\0'};
	int on = 1;
	clock_t send_time,recv_time;
	double spend_time;
	pid = getpid();
	struct sockaddr_in dst;
	char packet[PACKET_SIZE];
	struct ip *ip_hdr;
	struct icmp *icmp_hdr;
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	char *data;
	struct pcap_t *p;
	int n;
	char dst_ip[16],host[4];
	char *net_addr = "10.0.2.";
	if(argc!=5){
		printf("usage : ./ipscanner -i devicename -t timeout\n");
		return -1;
	}

	if(strcmp(argv[1],"-i")!=0 || strcmp(argv[3],"-t")!=0){
		printf("usage : ./ipscanner -i devicename -t timeout\n");
		return -1;
	}
	if(atoi(argv[4])==0 ||atoi(argv[4])==INTMAX_MAX){
		printf("please type valid time out value ex:10000\n");
		return -1;
	}
	/* 
	 * in pcap.c, initialize the pcap
	 */
	//pcap_init( target_ip , timeout);
	p = pcap_init_s( timeout , argv[2]);
	timeout = atoi(argv[4]);
	//time.tv_usec = atoi(argv[4]);
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */
	dst.sin_family = AF_INET;
	for(int i=1;i<255;i++){
		strcpy(dst_ip,net_addr);
		sprintf(host,"%d",i);
		strcat(dst_ip,host);
		dst.sin_addr.s_addr = inet_addr(dst_ip);
		memset(packet,'\0',sizeof(packet));
		ip_hdr = (struct ip*)packet;
		icmp_hdr = (struct icmp*)(packet + IP_HDR_LEN);
		fill_iphdr(ip_hdr,dst_ip);
		ip_hdr->ip_sum = ((unsigned short *)packet,ip_hdr->ip_hl);
		fill_icmphdr(icmp_hdr,i);
		memcpy(&packet[28],"M113040113",10);
		icmp_hdr->icmp_cksum = fill_cksum((unsigned short *)icmp_hdr,sizeof(packet)-sizeof(struct icmp));
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
			perror("sendto");
			exit(1);
		}
		printf("PING %s (data size = 10, id = 0x%x, seq = %d, timeout = %d ms)\n",dst_ip,pid,i,timeout);
		pcap_get_reply(timeout);
	}
	
	return 0;
}

