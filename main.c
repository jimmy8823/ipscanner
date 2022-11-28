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
	struct timeval time;
	int sockfd,recvsock;
	char src_ip[15]={'\0'};
	int on = 1;
	clock_t send_time,recv_time;
	double spend_time;
	pid = getpid();
	struct sockaddr_in dst,from;
	char packet[PACKET_SIZE],recv_buffer[1024];
	struct ip *ip_hdr;
	struct icmp *icmp_hdr;
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	socklen_t addr_len = sizeof(from);
	char *data;
	int n;
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
	pcap_init_s( timeout , argv[2]);
	timeout = atoi(argv[4]);
	time.tv_sec = 10;
	time.tv_usec = 0;
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

	if((recvsock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){
		perror("recv socket");
		exit(1);
	}

	if(setsockopt(recvsock, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(struct timeval)) < 0)
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
	dst.sin_addr.s_addr = inet_addr("10.0.2.2");
	memset(packet,'\0',sizeof(packet));
	ip_hdr = (struct ip*)packet;
	icmp_hdr = (struct icmp*)(packet + IP_HDR_LEN);
	fill_iphdr(ip_hdr,"10.0.2.2");
	ip_hdr->ip_sum = ((unsigned short *)packet,ip_hdr->ip_hl);
	fill_icmphdr(icmp_hdr,1);
	icmp_hdr->icmp_cksum = fill_cksum((unsigned short *)icmp_hdr,sizeof(packet)-sizeof(struct icmp));
	if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
	{
		perror("sendto");
		exit(1);
	}
	printf("PING 10.0.2.2 (data size = 10, id = %d, seq = 1, timeout = %d ms)\n",pid,timeout);
	send_time = clock();
	while(1){
		/*memset(recv_buffer,'\0',sizeof(recv_buffer));
		n =recvfrom(recvsock,recv_buffer,sizeof(recv_buffer),0,(struct sockaddr *)&from,&addr_len);
		ip_hdr = (struct ip*)recv_buffer;
		inaddr = ip_hdr->ip_src;
		inet_ntop(AF_INET,&inaddr,&src_ip,INET_ADDRSTRLEN);
		if(n>0 && strcmp(src_ip,"10.0.2.15")!=0){
			recv_time = clock();
			spend_time = (double)(recv_time - send_time)/CLOCKS_PER_SEC;
			icmp_hdr = (struct icmp*)recv_buffer + IP_HDR_LEN;
			data = recv_buffer + IP_HDR_LEN + sizeof(struct icmp);
			printf("    reply from %s time : %f ms\n",src_ip,spend_time*1000.0);
			printf("get %d byte data\n",n);
			for(int i=0;i<n;i++){
				printf("%02x ",recv_buffer[i]);
			}
			break;
		}else{
			printf("timeout\n");
			break;
		}*/
		pcap_get_reply();
	}
	return 0;
}

