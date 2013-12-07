/*
   Implementation of Packet Sniffer 
   using PCAP library. 

	Ashok Kumar 
	Tapan Bohra
	Utkarsh Patange 

   To run the sniffer use the command:
   $gcc sniffer.c -o sniffer -lpcap
   $sudo ./sniffer

   Press Ctrl+C to stop the sniffer
 */

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <map>
#include <vector>
#include <utility>
#include <algorithm>
#include <string>
#include <stdlib.h>

#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <pcap.h>

#define ETHERNET_HEADER_SIZE 14


using namespace std;

map <string,int > top_10_ip;
map <string, int > ip_data;

int packet_size_stats[5];

int tcp_count=0,udp_count=0,icmp_count=0,other_count = 0;




//ip-header structure
struct ip_header {
	u_char ip_vs_hl;				//version<<4 | header length >> 2
	u_char ip_tos;					//type of service
	u_char ip_hr_len;				//header length
	u_char ip_id;					//identification
	u_char ip_off;					//fragment offset
#define IP_RF 0x8000			//reserved fraagment
#define IP_DF 0x4000			//don't fragment
#define IP_MF 0x2000			//more fragments
#define IP_OFFMASK 0x1fff		//mask for fragmenting bits
	u_char ip_ttl;					//time to live
	u_char ip_p;					//protocol
	u_char ip_checksum;				//checksum
	struct in_addr ip_src, ip_dst;	//source and destination addresses
};



//filter for packets
struct filter {
	char *ip;
	int protocol;
};

struct filter filter_exp;



FILE *ip_list;
FILE *packet_types;
FILE *speed;
FILE *packet_list;
int total_bytes_used;



int print_ip_header(const u_char *packet, u_char *protocol,int size_of_packet)
{
	total_bytes_used   += size_of_packet;
	if(size_of_packet> 1000)
		packet_size_stats[4]++;
	else
		packet_size_stats[size_of_packet/250]++;



	struct ip_header *iphdr;
	int ip_hdr_size;

	//extracts the ip heaeder from the packet
	iphdr=(struct ip_header *)(packet+ETHERNET_HEADER_SIZE);




	if(top_10_ip.find(inet_ntoa(iphdr->ip_dst))==top_10_ip.end()) {
		top_10_ip[inet_ntoa(iphdr->ip_dst)] = 1;
		ip_data[inet_ntoa(iphdr->ip_dst)] = size_of_packet;
	}
	else {
		top_10_ip[inet_ntoa(iphdr->ip_dst)]++;
		ip_data[inet_ntoa(iphdr->ip_dst)] += size_of_packet;
	}
	if(top_10_ip.find(inet_ntoa(iphdr->ip_src))==top_10_ip.end()) {
		top_10_ip[inet_ntoa(iphdr->ip_src)] = 1;
		ip_data[inet_ntoa(iphdr->ip_src)] = size_of_packet;
	}
	else {
		top_10_ip[inet_ntoa(iphdr->ip_src)]++;
		ip_data[inet_ntoa(iphdr->ip_src)] += size_of_packet;
	}


	*protocol=iphdr->ip_p;

	ip_hdr_size=(iphdr->ip_vs_hl & 0x0f)*4;



	//printing tcp header according to filter
	if(*protocol==IPPROTO_TCP)
		tcp_count++;
	else if(*protocol==IPPROTO_UDP)
		udp_count++;	
	else if(*protocol==IPPROTO_ICMP)
		icmp_count++;
	else 
		other_count++;


	return (iphdr->ip_vs_hl & 0x0f)*4;
}




void packet_receive(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct in_addr source, destination;
	u_char protocol;
	int proto_hdr_size;

	int ip_hdr_size=print_ip_header(packet, &protocol,header->len);


}


int main(int argc, char *argv[])
{
	char *device=NULL;
	char error_buffer[PCAP_ERRBUF_SIZE], devices_array[100][100];
	struct in_addr address;
	pcap_if_t *all_devices, *device_t;
	int count=1, n;
	memset(packet_size_stats,0,sizeof(packet_size_stats));

	//find all available devices
	
	if( pcap_findalldevs( &all_devices , error_buffer) )
	{
		printf("Error finding devices : %s" , error_buffer);
		exit(1);
	}
	

	//Print the available devices
	
	for(device_t = all_devices ; device_t != NULL ; device_t = device_t->next)
	{
		
		if(device_t->name != NULL)
		{
			strcpy(devices_array[count] , device_t->name);
		}
		count++;
	}

	
	if (argc > 1) n = atoi(argv[1]);
	else n=1;
	device=devices_array[n];

	//network number
	bpf_u_int32 net_num;
	//subnet mask number
	bpf_u_int32 subnet_mask;

	//looks up the device for network number and subnet mask
	pcap_lookupnet(device, &net_num, &subnet_mask, error_buffer);
	address.s_addr=net_num;
	//printf("Net Number: %s\n", inet_ntoa(address));
	address.s_addr=subnet_mask;
//	printf("Subnet mask: %s\n", inet_ntoa(address));

	//creates a pcap_t handle descriptor
	pcap_t *descriptor;
	//open a lifve device and binds it to the handle descriptor
	descriptor=pcap_open_live(device,BUFSIZ, 1, 0, error_buffer);

	if(descriptor==NULL)
	{
		printf("Couldn't open device %s\n", device);
		return 0;
	}

	ip_list = fopen("ip_list.txt","w");
	packet_types = fopen("packet_types.txt","w");
	packet_list = fopen("packet_list.txt","w");
	speed = fopen("speed.txt","w");

	char ip[13];
	struct bpf_program fp;
	char ch;
	int i=0;

	ch='\n';
	int p;
	//printf("Enter the ip of node to sniff. Press enter if you don't want. \n");
	ch='\n';
	while((ch)!='\n')
	{
		ip[i]=ch;
		i++;
	}
	ip[i]='\0';
	filter_exp.ip=ip;

	//printf("Enter the protocol:\n0:ignore\n1:TCP \n2:UDP \n3:ICMP \n");
	//scanf("%d", &p);
	if (argc > 2) p = atoi(argv[2]);
	else p=0;
	

	if(p==1) filter_exp.protocol=IPPROTO_TCP;
	else if(p==2) filter_exp.protocol=IPPROTO_UDP;
	else if(p==3) filter_exp.protocol=IPPROTO_ICMP;	

	//go in an infinte loop and execute packet_receive function for sniffing
	struct timeval tim;
	gettimeofday(&tim, NULL);
	double t1=tim.tv_sec+(tim.tv_usec/1000000.0);

	pcap_loop(descriptor, 500, packet_receive, NULL);

	gettimeofday(&tim, NULL);
	double t2=tim.tv_sec+(tim.tv_usec/1000000.0);
	fprintf(speed,"%d\t%.6lf\n",total_bytes_used, t2-t1);

	vector < pair < int,string > > ip_results;
	for (map<string,int>::iterator it=top_10_ip.begin(); it!=top_10_ip.end(); ++it) {
		ip_results.push_back(make_pair(it->second,it->first));
	}
	sort(ip_results.begin(),ip_results.end());
	reverse(ip_results.begin(),ip_results.end());
	int k = 0;

	if(ip_results.size() > 10)
		ip_results.erase (ip_results.begin() + 5,ip_results.end());
	random_shuffle(ip_results.begin(),ip_results.end());

	for(int i=0;i<4; i++)
		fprintf(packet_list, "%d-%d\t%d\n",250*i,250*(i+1),packet_size_stats[i]);
	fprintf(packet_list, "above 1000\t%d\n",packet_size_stats[4]);


	for (int i=0; i<ip_results.size()&& k<5 ; i++,k++) {
		fprintf(ip_list,"%s\t%d\n",ip_results[i].second.c_str(),ip_data[ip_results[i].second.c_str()]);
	}

	//  printf("\ntcp = %d , udp = %d, icmp = %d\n",IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP);
	fprintf(packet_types,"%d\n%d\n%d\n%d",tcp_count,udp_count,icmp_count,other_count);
	printf("\nTCP:%d UDP:%d ICMP:%d\n",tcp_count,udp_count,icmp_count);

}



