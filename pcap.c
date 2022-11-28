#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern pid_t pid;
extern u16 icmp_req;

static char* dev = "enp0s3";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

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
	pcap_set_immediate_mode(p,1);
	pcap_activate(p);
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	strcpy(filter_string,"icmp");

	if(pcap_set_timeout(p,timeout)==-1){
		pcap_perror(p,"pcap_settimeout");
		exit(1);
	}
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


int pcap_get_reply( void )
{
	const u_char *ptr;
	ptr = pcap_next(p,&hdr);
	for(int i=0;i<hdr.len;i++){
		printf("%02x ",ptr[i]);
	}
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
	if(ptr==NULL){
		printf("NULL\n");
	}
	return 0;
}