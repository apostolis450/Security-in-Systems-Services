/* 
 * HRY414: Assignment 6	--	Network traffic monitoring using the Packet Capture library
 * Author: Apostolos Zacharopoulos
 * Date:   16/12/2020
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>
#include <signal.h>


typedef struct flows_records fl;

void usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./nwmonitor \n"
		"Options:\n"
		"-i <Network interface name> [e.g. eth0]\n"
		"-r <pcap filename> [e.g. test.pcap] \n"
		"-h, Help message\n\n");
	exit(1);
}

typedef struct flows_records
{
	char *sIP;
	char *dIP;
	u_int16_t sPort;
	u_int16_t dPort;
	char protocol[3];
	fl *next;
}fl;


/*Global*/
int nump=0; //number of packets
int total_tcp_packets=0;
int total_udp_packets=0;
ulong total_tcp_bytes=0;
ulong total_udp_bytes=0;
fl *head;

void
print_flows_list(){
	fl *node = head;
	int total_flows=0;
	int total_tcp_flows=0;
	int total_udp_flows=0;
	
	/*flows counting..*/
	while( node != NULL ){
		if(strcmp(node->protocol,"TCP")==0){
			total_tcp_flows++;
		}
		else if(strcmp(node->protocol,"UDP")==0)
		{
			total_udp_flows++;
		}
		total_flows++;
		node=node->next;
	}

	printf("\nStatistics from packets captured:\n");
	printf("-------------------------------------\n");
	printf("Total number of network flows captured: %d\n",total_flows);
	printf("Number of TCP network flows captured: %d\n",total_tcp_flows);
	printf("Number of UDP network flows captured: %d\n",total_udp_flows);
	printf("Total number of packets received: %d\n",nump);
	printf("Total number of TCP packets received: %d\n",total_tcp_packets);
	printf("Total number of UDP packets received: %d\n",total_udp_packets);
	printf("Total number of TCP bytes received: %lu\n",total_tcp_bytes);
	printf("Total number of UDP bytes received: %lu\n",total_udp_bytes);
	printf("-------------------------------------\n");

	return;
}

void 
signal_handler(int signal) {
    
	switch (signal) {
    case SIGINT:
        printf("\nCtrl+C - asked termination\n");
		print_flows_list();
        exit(0);
    default:
        printf("\nUnexpected termination!!!!\n");
        exit(1);
    }
}

void 
flow_rec(char *sip,char *dip, u_int16_t sport, u_int16_t dport, char *prot){
	
	fl *node = head;
	
	while (node != NULL)
	{
		/*if node is empty program has nothing to compare*/
		if(node->sIP == NULL){
			node->sIP = (char *)malloc(strlen(sip)*sizeof(char));
			node->dIP = (char *)malloc(strlen(dip)*sizeof(char));
			strcpy(node->protocol,prot);
			strcpy(node->sIP,sip);
			strcpy(node->dIP,dip);
			node->sPort = sport;
			node->dPort = dport;
			// /*pre create the 2nd node*/
			// fl *newnode = (fl*)malloc(sizeof(fl));
			// node->next = newnode;
			return;
		}
		if (strcmp(sip,node->sIP) == 0 && strcmp(dip,node->dIP) == 0 
			&& (sport == node->sPort) && (dport == node->dPort) && 
			strcmp(prot,node->protocol) == 0)
		{
			return; /*Flow exists so no extra record*/
		}
		else if(node->next == NULL) 
		{
			/*reached last node and current flow doesn't exist -> record it*/
			fl *newnode = (fl*)malloc(sizeof(fl));
			newnode->sIP = (char *)malloc(strlen(sip)*sizeof(char));
			newnode->dIP = (char *)malloc(strlen(dip)*sizeof(char));
			strcpy(newnode->protocol,prot);
			strcpy(newnode->sIP,sip);
			strcpy(newnode->dIP,dip);
			newnode->sPort = sport;
			newnode->dPort = dport;
			newnode->next = NULL;
			node->next = newnode;
			return;
		}
		node = node->next;
	}
	return;
}

u_int16_t
handle_ethernet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ether_header *ehdr;
	/* ethernet header */
	ehdr = (struct ether_header *)packet;

	if (ntohs(ehdr->ether_type) == ETHERTYPE_IP
		|| ntohs(ehdr->ether_type) == ETHERTYPE_IPV6)
	{
		nump++; //counting packets received over ethernet type ipv6/ipv4.
		return ehdr->ether_type;
	}
	else
	{
		return 0;
	}

}

void
handle_IPv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip6_hdr *ip6;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	u_int udphdr_length=8; //udp header fixed 8 bytes
	
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	u_int ip6hdr_len = 40;	//fixed length
	
	ip6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
	int nxthdr = ip6->ip6_nxt; // next header -> holds protocol
	/* check version */
	if (((ip6->ip6_vfc) & 0xf0) >> 4 != 6)	//vfc holds version and traffic class
	{
		printf("Unknown version: %d\n", ip6->ip6_vfc);
		return ;
	}
	
	printf("--packet:\n");
	printf("  IPv6 | ");

	inet_ntop(AF_INET6,&(ip6->ip6_src),src,INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6,&(ip6->ip6_dst),dst,INET6_ADDRSTRLEN);
	
	if (nxthdr == IPPROTO_TCP)
	{
		total_tcp_packets++;
		tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip6hdr_len);
		printf("(src) %s:%d -> ",src,ntohs(tcp->th_sport));
		printf("(dst) %s:%d ",dst,ntohs(tcp->th_dport));		
		printf("| TCP ");
		printf("| hdrlen: %d",tcp->th_off*4);
		printf("| pldlen: %d\n",ntohs(ip6->ip6_plen)-tcp->th_off*4); //pld len - tcphdr len
		total_tcp_bytes+=(ulong)(ntohs(ip6->ip6_plen));
		flow_rec(src,dst,ntohs(tcp->th_sport),ntohs(tcp->th_dport),"TCP");
	}else if (nxthdr == IPPROTO_UDP)
	{
		total_udp_packets++;
		udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip6hdr_len);
		printf("(src) %s: -> ",src);
		printf("(dst) %s: ",dst);
		printf("| UDP ");
		printf("| hdrlen: %d",udphdr_length);
		printf("| pldlen: %d\n",ntohs(udp->uh_ulen)-udphdr_length); //udp len - udphdr len
		total_udp_bytes+=(ulong)(ntohs(udp->uh_ulen)); //header included
		flow_rec(src,dst,ntohs(udp->uh_sport),ntohs(udp->uh_dport),"UDP");
	}else 
	{
		return;
	}
	
	printf("\n");
	return;
}

void
handle_IP(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	const struct ip *ip;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	u_int iphdr_length, udphdr_length=8; //udp header fixed 8 bytes
	u_int version;
	
	/* ip hdr is after the ethernet header */
	ip = (struct ip *)(packet + sizeof(struct ether_header));
	iphdr_length = ip->ip_hl*4;	//in bytes
	
	/* check to see we have a packet of valid length */
	if (iphdr_length < 20)
	{
		printf("invalid ip header length: %d", iphdr_length);
		return ;
	}

	version = ip->ip_v; /* ip version */

	/* check version */
	if (version != IPVERSION)	
	{
		printf("Unknown version: %d\n", version);
		return ;
	}
	
	printf("--packet:\n");
	printf("  IPv4 | ");
	
	inet_ntop(AF_INET, &ip->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, dst, INET_ADDRSTRLEN);
	
	if (ip->ip_p == IPPROTO_TCP)
	{
		total_tcp_packets++;
		/*pass over ether hdr and ip hdr to reach tcp hdr and then payload, same for udp */
		tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + iphdr_length);
	
		printf("(src) %s:%d -> ",inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
		//strcpy(sip,inet_ntoa(ip->ip_src));
		printf("(dst) %s:%d ",inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));	
		//strcpy(dip,inet_ntoa(ip->ip_dst));
		printf("| TCP ");
		printf("| hdrlen: %d",tcp->th_off*4);
		printf("| pldlen: %d \n",ntohs(ip->ip_len)-iphdr_length-tcp->th_off*4);
		total_tcp_bytes+=(ulong)(ntohs(ip->ip_len)-iphdr_length); //header included
		flow_rec(src,dst,ntohs(tcp->th_sport),ntohs(tcp->th_dport),"TCP");
	}
	else if (ip->ip_p == IPPROTO_UDP)
	{
		total_udp_packets++;
		udp = (struct udphdr *)(packet + sizeof(struct ether_header) + iphdr_length);

		printf("(src) %s:%d -> ", inet_ntoa(ip->ip_src),ntohs(udp->uh_sport));
		printf("(dst) %s:%d ",inet_ntoa(ip->ip_dst),ntohs(udp->uh_dport));
		printf("| UDP ");
		printf("| hdrlen: %d",udphdr_length);
		printf("| pldlen: %d\n",ntohs(udp->uh_ulen)-udphdr_length); //UDP length - udp header length
		total_udp_bytes+=(ulong)(ntohs(udp->uh_ulen)); //header included
		flow_rec(src,dst,ntohs(udp->uh_sport),ntohs(udp->uh_dport),"UDP");
	}
	else{
		return ; /*skip non TCP/UDP*/
	}
	
	return ;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	u_int16_t type = handle_ethernet(args, header, packet);

	if (ntohs(type) == ETHERTYPE_IP )
	{ 
		handle_IP(args, header, packet);
	}
	else if(ntohs(type) == ETHERTYPE_IPV6){
		handle_IPv6(args, header, packet);	
	}

	return;
}

int monitor_device(char *device)
{

	char error_buf[PCAP_ERRBUF_SIZE];
	head = (fl*)malloc(sizeof(fl));	//init list for recording flows; head is global
	head->next=NULL;

	signal(SIGINT,signal_handler);//handle keyboard interrupt stop.

	pcap_t *open_dev = open_dev = pcap_open_live(device, BUFSIZ, 1, -1, error_buf);
	if (open_dev == NULL)
	{
		printf("Device opening error: %s\n", error_buf);
		exit(1);
	}

	/* calling callback function for each packet caption */
	/* loop continuously until an interrupt */
	pcap_loop(open_dev,0,callback,NULL);
	
	pcap_close(open_dev);
	return 0;
}

int monitor_file(char *file)
{

	char error_buf[PCAP_ERRBUF_SIZE];
	
	head = (fl*)malloc(sizeof(fl));	//init list for recording flows; head is global
	head->next=NULL;

	signal(SIGINT,signal_handler);//handle keyboard interrupt stop.



	pcap_t *open_file = pcap_open_offline(file, error_buf);

	if (open_file == NULL)
	{
		printf("File pcap opening error: %s\n", error_buf);
		exit(1);
	}
	/* calling callback function for each packet caption */
	/* loop continuously until a keyboard interrupt */
	pcap_loop(open_file,0,callback,NULL);
	print_flows_list();
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int ch;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "hi:r:")) != -1)
	{
		switch (ch)
		{
		case 'i':
			monitor_device(optarg);
			break;
		case 'r':
			monitor_file(optarg);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	return 0;
}
