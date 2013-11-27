/*
Implementation of Packet Sniffer 
using PCAP library. 



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

int tcp_count=0,udp_count=0,icmp_count=0;


//ethernet header structure
struct	ethernet_header {
	u_char	ethernet_dhost[ETHER_ADDR_LEN];		//destination host address
	u_char	ethernet_shost[ETHER_ADDR_LEN];		//source host address
	u_short	ethernet_type;						//type of packet
};

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

//tcp-header structure
struct tcp_header {
	u_short tcp_src_port;			//Source Port
	u_short tcp_dst_port;			//Destination Port
	u_int tcp_seq_no;				//Sequence Number
	u_int tcp_ack_no;				//Acknowledgement number
	u_char offset;					//data offset, reserved bits
	u_char tcp_flags;				//tcp control bits and ecn options
	#define TCP_FIN  0x01
    #define TCP_SYN  0x02
    #define TCP_RST  0x04
    #define TCP_PUSH 0x08
    #define TCP_ACK  0x10
    #define TCP_URG  0x20
    #define TCP_ECE  0x40
    #define TCP_CWR  0x80
    #define TCP_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)	
	u_short tcp_win;				//window size
	u_short tcp_sum;				//checksum
	u_short tcp_urptr;				//urgent pointer
};

//icmp-header structure
struct icmp_header {
	u_char icmp_type;				//icmp type
	u_char icmp_code;				//icmp code 
	u_short icmp_sum;				//icmp checksum
	u_int icmp_data;				//other data
};

//udp-header structure
struct udp_header {
	u_short udp_src_port;			//source port
	u_short udp_dst_port;			//destination port
	u_short udp_length;				//header length
	u_short udp_sum;				//check sum
};

//filter for packets
struct filter {
	char *ip;
	int protocol;
};

struct filter filter_exp;



FILE *logfile;
FILE *ip_list;
FILE *packet_types;
FILE *packet_list;
void print_ethernet_header(const u_char *packet)
{
	struct ethernet_header *etherhdr;
	//extracts the ethernet header from the packet
	etherhdr = (struct ethernet_header *) packet;
    
	fprintf(logfile,"\n		ETHERNET HEADER		\n");
    
	//prints the ethernet type
    if (ntohs (etherhdr->ethernet_type) == ETHERTYPE_IP)
    {
        fprintf(logfile, "Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(etherhdr->ethernet_type),
                ntohs(etherhdr->ethernet_type));
    }else  if (ntohs (etherhdr->ethernet_type) == ETHERTYPE_ARP)
    {
        fprintf(logfile,"Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(etherhdr->ethernet_type),
                ntohs(etherhdr->ethernet_type));
    }else {
        fprintf(logfile,"Ethernet type %x not IP\n", ntohs(etherhdr->ethernet_type));
    }
	
	int i;
	u_char *ptr;
    
	//extracting destinantion host address and printing
    ptr = etherhdr->ethernet_dhost;
    i = ETHER_ADDR_LEN;
    fprintf(logfile,"Destination Ethernet Address:  ");
    do{
        fprintf(logfile, "%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    fprintf(logfile,"\n");
    
	//extracting source host address and printing
    ptr = etherhdr->ethernet_shost;
    i = ETHER_ADDR_LEN;
    fprintf(logfile,"Source Ethernet Address:  ");
    do{
        fprintf(logfile,"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    fprintf(logfile,"\n");
	//printing the protocol field of ethernet
	fprintf(logfile,"Protocol : %x\n", ntohs(etherhdr->ethernet_type));
}

int print_ip_header(const u_char *packet, u_char *protocol,int size_of_packet)
{
	if(size_of_packet> 1000)
		packet_size_stats[4]++;
	else
		packet_size_stats[size_of_packet/250]++;

	fprintf(logfile,"\n			IP HEADER			\n");
    
	struct ip_header *iphdr;
	int ip_hdr_size;
    
	//extracts the ip heaeder from the packet
	iphdr=(struct ip_header *)(packet+ETHERNET_HEADER_SIZE);
	
	//printing the ip header fields
	fprintf(logfile,"Version : %d\n", iphdr->ip_vs_hl>>4);
	fprintf(logfile,"Header length : %d\n", (iphdr->ip_vs_hl & 0x0f)*4);
    
    
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
    
    
	fprintf(logfile,"Source ip: %s\n", inet_ntoa(iphdr->ip_src));
	fprintf(logfile,"Destination ip: %s\n", inet_ntoa(iphdr->ip_dst));
	fprintf(logfile,"Type of service: %u\n", iphdr->ip_tos);
	fprintf(logfile,"Time to live: %d\n",iphdr->ip_ttl);
	fprintf(logfile,"Ip protocol: %u\n", iphdr->ip_p);
	fprintf(logfile,"Checksum : %d\n", iphdr->ip_checksum);
	*protocol=iphdr->ip_p;
    
	ip_hdr_size=(iphdr->ip_vs_hl & 0x0f)*4;
    
	if(filter_exp.protocol==0 && filter_exp.ip[0]==0)
		goto done;
    
	//printing the filtered header
	if((*protocol==filter_exp.protocol || filter_exp.protocol==0) && (!strcmp(inet_ntoa(iphdr->ip_dst),filter_exp.ip) || !strcmp(inet_ntoa(iphdr->ip_src),filter_exp.ip) || filter_exp.ip[0]==0))
	{
		printf("\n		IP HEADER		\n");
		printf("Version : %d\n", iphdr->ip_vs_hl>>4);
		printf("Header length : %d\n", (iphdr->ip_vs_hl & 0x0f)*4);
		printf("Source ip: %s\n", inet_ntoa(iphdr->ip_src));
		printf("Destination ip: %s\n", inet_ntoa(iphdr->ip_dst));
		printf("Type of service: %u\n", iphdr->ip_tos);
		printf("Time to live: %d\n",iphdr->ip_ttl);
		printf("Ip protocol: %u\n", iphdr->ip_p);
		printf("Checksum : %d\n", iphdr->ip_checksum);
        
		//printing tcp header according to filter
		if(*protocol==IPPROTO_TCP)
		{
            tcp_count++;
			struct tcp_header *tcphdr;
			printf("\n		TCP HEADER		\n");
            
			//extracts tcp header
			tcphdr=(struct tcp_header *)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
            
			//printing the tcp header fields
			printf("Source Port: %u\n", ntohs(tcphdr->tcp_src_port));
			printf("Destination Port: %u\n", ntohs(tcphdr->tcp_dst_port));
			printf("Sequence Number: %u\n", ntohl(tcphdr->tcp_seq_no));
			printf("Acknowledgement: %u\n", ntohl(tcphdr->tcp_ack_no));
			printf("Header length: %d\n", (tcphdr->offset & 0xf0)*4);
			printf("Flags: %u\n", tcphdr->tcp_flags);
			printf("Window: %d\n", ntohs(tcphdr->tcp_win));
			printf("Checksum %d\n", ntohs(tcphdr->tcp_sum));
			printf("Urgent pointer: %d\n", ntohs(tcphdr->tcp_urptr));
		}
		
		//printing udp header according to filter
		else if(*protocol==IPPROTO_UDP)
		{
            udp_count++;
			struct udp_header *udphdr;
            
			//extracts udp header
			udphdr=(struct udp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
            
			//printing the udp header fields
			printf("\n			UDP HEADER			\n");
			printf("UDP Source Port: %d\n", ntohs(udphdr->udp_src_port));
			printf("UDP Destination Port: %d\n", ntohs(udphdr->udp_dst_port));
			printf("UDP Length %d\n",ntohs(udphdr->udp_length));
			printf("UDP CheckSum: %d\n", ntohs(udphdr->udp_sum));
		}
        
		//printing icmp header according to filter
		else if(*protocol==IPPROTO_ICMP)
		{
            icmp_count++;
			struct icmp_header *icmphdr;
			printf("\n		ICMP HEADER			\n");
            
			//extracts icmp header
			icmphdr=(struct icmp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
            
			//printing the icmp header fields
			printf("\n			ICMP HEADER			\n");
			printf("ICMP Type: %u\n", icmphdr->icmp_type);
			printf("ICMP Code: %u\n", icmphdr->icmp_code);
			printf("ICMP CheckSum: %d\n", ntohs(icmphdr->icmp_sum));
			printf("ICMP Data: %d\n", icmphdr->icmp_data);
		}
	}
    
done:
	return (iphdr->ip_vs_hl & 0x0f)*4;
}

int print_tcp_header(const u_char *packet, int ip_hdr_size)
{
	fprintf(logfile,"\n			TCP HEADER			\n");
    
	struct tcp_header *tcphdr;
	int tcp_hdr_size;
    
	//extracts tcp header
	tcphdr=(struct tcp_header *)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
    
	//printing the tcp header fields
	fprintf(logfile,"Source Port: %u\n", ntohs(tcphdr->tcp_src_port));
	fprintf(logfile,"Destination Port: %u\n", ntohs(tcphdr->tcp_dst_port));
	fprintf(logfile,"Sequence Number: %u\n", ntohl(tcphdr->tcp_seq_no));
	fprintf(logfile,"Acknowledgement: %u\n", ntohl(tcphdr->tcp_ack_no));
	fprintf(logfile,"Header length: %d\n", (tcphdr->offset & 0xf0)*4);
	fprintf(logfile,"Flags: %u\n", tcphdr->tcp_flags);
	fprintf(logfile,"Window: %d\n", ntohs(tcphdr->tcp_win));
	fprintf(logfile,"Checksum %d\n", ntohs(tcphdr->tcp_sum));
	fprintf(logfile,"Urgent pointer: %d\n", ntohs(tcphdr->tcp_urptr));
	tcp_hdr_size=(tcphdr->offset & 0xf0)*4;
	return tcp_hdr_size;
}

int print_icmp_header(const u_char *packet, int ip_hdr_size)
{
	struct icmp_header *icmphdr;
	int icmp_hdr_size=8;
    
	//extracts icmp header
	icmphdr=(struct icmp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
    
	//printing the icmp header fields
	fprintf(logfile,"\n			ICMP HEADER			\n");
	fprintf(logfile,"ICMP Type: %u\n", icmphdr->icmp_type);
	fprintf(logfile,"ICMP Code: %u\n", icmphdr->icmp_code);
	fprintf(logfile,"ICMP CheckSum: %d\n", ntohs(icmphdr->icmp_sum));
	fprintf(logfile,"ICMP Data: %d\n", icmphdr->icmp_data);
	return icmp_hdr_size;
}

int print_udp_header(const u_char *packet, int ip_hdr_size)
{
    
	struct udp_header *udphdr;
	int udp_hdr_size=8;
    
	//extracts udp header
	udphdr=(struct udp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);
    
	//printing the udp header fields
	fprintf(logfile,"\n			UDP HEADER			\n");
	fprintf(logfile,"UDP Source Port: %d\n", ntohs(udphdr->udp_src_port));
	fprintf(logfile,"UDP Destination Port: %d\n", ntohs(udphdr->udp_dst_port));
	fprintf(logfile,"UDP Length %d\n",ntohs(udphdr->udp_length));
	fprintf(logfile,"UDP CheckSum: %d\n", ntohs(udphdr->udp_sum));
	return udp_hdr_size;
    
}



void packet_receive(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct in_addr source, destination;
	u_char protocol;
	int proto_hdr_size;
    
	fprintf(logfile,"\nLENGTH of packet: %d\n", header->len);
    
	//print the ethernet header
	print_ethernet_header(packet);
    
	//return the ip header size and pass the protocol in the argument, printing ip header
	int ip_hdr_size=print_ip_header(packet, &protocol,header->len);
	
	//print the appropriate protocol header  and return the header size
	if(protocol==IPPROTO_TCP){
        proto_hdr_size=print_tcp_header(packet,ip_hdr_size);}
    
	if (protocol==IPPROTO_ICMP){
        proto_hdr_size=print_icmp_header(packet,ip_hdr_size);}
    
	if (protocol==IPPROTO_UDP) {
        proto_hdr_size=print_udp_header(packet, ip_hdr_size);}
    
	//print the data payload removing the ethernet and ip header
	//print_data(packet+ETHERNET_HEADER_SIZE+ip_hdr_size, header->len-(ETHERNET_HEADER_SIZE+ip_hdr_size));
    
	fprintf(logfile, "\n\n-----------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}


int main()
{
	char *device=NULL;
	char error_buffer[PCAP_ERRBUF_SIZE], devices_array[100][100];
	struct in_addr address;
	pcap_if_t *all_devices, *device_t;
	int count=1, n;
	memset(packet_size_stats,0,sizeof(packet_size_stats));

	//find all available devices
	printf("Finding available devices ... ");
    if( pcap_findalldevs( &all_devices , error_buffer) )
    {
        printf("Error finding devices : %s" , error_buffer);
        exit(1);
    }
    printf("Done");
     
   //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device_t = all_devices ; device_t != NULL ; device_t = device_t->next)
    {
        printf("%d. %s - %s\n" , count , device_t->name , device_t->description);
        if(device_t->name != NULL)
        {
            strcpy(devices_array[count] , device_t->name);
        }
        count++;
    }
     
    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
	device=devices_array[n];

	//network number
	bpf_u_int32 net_num;
	//subnet mask number
	bpf_u_int32 subnet_mask;

	//looks up the device for network number and subnet mask
	pcap_lookupnet(device, &net_num, &subnet_mask, error_buffer);
	address.s_addr=net_num;
	printf("Net Number: %s\n", inet_ntoa(address));
	address.s_addr=subnet_mask;
	printf("Subnet mask: %s\n", inet_ntoa(address));

	//creates a pcap_t handle descriptor
	pcap_t *descriptor;
	//open a lifve device and binds it to the handle descriptor
	descriptor=pcap_open_live(device,BUFSIZ, 1, 0, error_buffer);

	if(descriptor==NULL)
	{
		printf("Couldn't open device %s\n", device);
		return 0;
	}

	//open a file to store the sniffing result
	logfile=fopen("log.txt", "w");
    ip_list = fopen("ip_list.txt","w");
    packet_types = fopen("packet_types.txt","w");
    packet_list = fopen("packet_list.txt","w");

	char ip[13];
	struct bpf_program fp;
	char ch;
	int i=0;
	
	ch=getchar();
	int p;
	printf("Enter the ip of node to sniff. Press enter if you don't want. \n");
	while((ch=getchar())!='\n')
	{
		ip[i]=ch;
		i++;
	}
	ip[i]='\0';
	filter_exp.ip=ip;

	printf("Enter the protocol:\n0:ignore\n1:TCP \n2:UDP \n3:ICMP \n");
	scanf("%d", &p);

	printf("For all packets , take a look at log.txt\n");

	if(p==1) filter_exp.protocol=IPPROTO_TCP;
	else if(p==2) filter_exp.protocol=IPPROTO_UDP;
	else if(p==3) filter_exp.protocol=IPPROTO_ICMP;	
	printf("%d",filter_exp.protocol);
	//go in an infinte loop and execute packet_receive function for sniffing
	pcap_loop(descriptor, 1000, packet_receive, NULL);
    
    vector < pair < int,string > > ip_results;
    for (map<string,int>::iterator it=top_10_ip.begin(); it!=top_10_ip.end(); ++it) {
        ip_results.push_back(make_pair(it->second,it->first));
    }
    sort(ip_results.begin(),ip_results.end());
    reverse(ip_results.begin(),ip_results.end());
    int k = 0;
    printf("my results\n");
    if(ip_results.size() > 10)
    ip_results.erase (ip_results.begin() + 10 ,ip_results.end());
	random_shuffle(ip_results.begin(),ip_results.end());
	
	for(int i=0;i<4; i++)
		fprintf(packet_list, "%d-%d\t%d\n",250*i,250*(i+1),packet_size_stats[i]);
	fprintf(packet_list, "above 1000\t%d\n",packet_size_stats[4]);


    for (int i=0; i<ip_results.size()&& k<10 ; i++,k++) {
        fprintf(ip_list,"%s\t%d\n",ip_results[i].second.c_str(),ip_data[ip_results[i].second.c_str()]);
    }
    
  //  printf("\ntcp = %d , udp = %d, icmp = %d\n",IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP);
    fprintf(packet_types,"%d\n%d\n%d",tcp_count,udp_count,icmp_count);
    printf("\nTCP:%d UDP:%d ICMP:%d\n",tcp_count,udp_count,icmp_count);
    
}



