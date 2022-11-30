#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define ETHER_HDR_LEN 14
#define IP_HDR_LEN 20
extern pid_t pid;
extern u16 icmp_req;

static char* dev = "enp0s3";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr *hdr;
static const u_char *content;

/* This function is almost completed.
 * But you still need to edit the filter string.
 */
int pcap_init_s(unsigned int timeout , const char* devicename)
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;
	
	//strcpy(dev,devicename);
	ret = pcap_lookupnet(devicename, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	p = pcap_create(devicename,errbuf);
	//p = pcap_open_live(devicename, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	strcpy(filter_string,"icmp");

	if(pcap_set_timeout(p,timeout)==-1){
		pcap_perror(p,"pcap_settimeout");
		exit(1);
	}
	pcap_set_promisc(p,1);
	pcap_set_snaplen(p,8000);
	//pcap_set_immediate_mode(p,1);
	pcap_setnonblock(p,1,errbuf);
	pcap_activate(p);
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
		
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
	
	
	return 0;
}

int pcap_get_reply(int timeout)
{
	const u_char *ptr;
	int ret;
	clock_t start,current;
	double spend_time;
	struct ip *ip_hdr;
	struct icmp *icmp_hdr;
	char src_ip[16]; 
	struct in_addr inaddr;
	/*ptr = pcap_next(p,&hdr);
	printf("%s\n",ptr);
	for(int i=0;i<hdr.len;i++){
		printf("%02x ",ptr[i]);
	}f
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 
	if(ptr==NULL){
		printf("NULL\n");
	}*/
	start = clock();
	memset(src_ip,'\0',INET_ADDRSTRLEN);
	while(1){
		ret = pcap_next_ex(p,&hdr,&content);
		current = clock();
		if(ret==1){
			/*for(int i=0;i<hdr->caplen;i++){
				printf("%02x ",content[i]);
			}*/
			
			ip_hdr = (struct ip*)(content + ETHER_HDR_LEN);
			icmp_hdr = (struct icmp*)(content + ETHER_HDR_LEN + IP_HDR_LEN);
			inaddr = ip_hdr->ip_src;
			inet_ntop(AF_INET,&inaddr,src_ip,INET_ADDRSTRLEN);
			if(strcmp(src_ip,"10.0.2.15")!=0){
				spend_time = (current - start)/1000000.0;
				printf("    reply from : %s , time : %f ms",src_ip,spend_time);
				printf("\n");
				break;
			}
		}else if(ret==0){
			spend_time = (current - start)/1000;
			if(spend_time>timeout){
				printf("    Destination Unreachable\n");
				break;
			}
		}else if(ret == -2){
			printf("-2\n");
		}
	}
	
	return 0;
}
