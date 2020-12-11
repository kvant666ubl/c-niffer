#include<getopt.h>  // for cli
#include<pcap.h>    // lib fo sniff

#include<stdio.h>	// for in/out
#include<stdlib.h>  // for exit()
#include<string.h>  // for memset
#include<getopt.h>  // fot cli

#include<sys/socket.h>    // socket lib for commun
#include<arpa/inet.h>     // for inet_ntoa()
#include<net/ethernet.h>  // for eth0 debice

#include<netinet/udp.h>	  // udp header
#include<netinet/tcp.h>	  // tcp header

#include"func.h"

FILE *logfile;
struct sockaddr_in source, dest;
int tcp=0, udp=0, others=0, total=0, i, j; 

static int verbose_flag;
int packets = 0;

int main (int argc, char **argv) 
{  
	pcap_if_t *alldevsp , *device;     // Devices array, one device to sniff (interface like eth0 e.g.)
	pcap_t *handle; 				   // Handle of the device that shall be sniffed
	char errbuf[100] , *devname , devs[100][100];
	int count = 1, n;

	if(pcap_findalldevs( &alldevsp , errbuf))
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}

	for(device = alldevsp ; device != NULL ; device = device->next) {
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	count = 1;
	int c;
	int action = 0;
	while (1)
    {
    	static struct option long_options[] =
    	{
          {"verbose", no_argument		, &verbose_flag, 1},
          {"brief",   no_argument		, &verbose_flag, 0},
          {"start"  , no_argument       , 0, 's'}, 			// s-start
          {"stop"   , no_argument       , 0, 'p'}, 			// p-pause
          {"show"   , required_argument , 0, 'v'}, 			// v-view
          {"select" , required_argument , 0, 'c'}, 			// c-choose 
          {"stat"   , required_argument , 0, 'i'}, 			// i-info 
          {"help"   , no_argument       , 0, 'h'}, 			// h-help
		  {"mode"   , required_argument , 0, 'm'},          // m-mo	de
          {0		, 0					, 0	  ,   0}  		// NULL
        };

    	int option_index = 0;
    	c = getopt_long (argc, argv, "sphv:c:i:m:",
                    long_options, &option_index);

    	if (c == -1) break;

    	switch (c)
        {
        case 0:
        	if (long_options[option_index].flag != 0)
        		break;
        	printf ("option %s", long_options[option_index].name);
        	if (optarg) printf (" with arg %s", optarg);
        	printf ("\n");
        	break;

        case 's':
			devname = devs[4];	// Default eth0 (ethN), see dev-tab: sudo cniff -h
			
			printf("[SNIFFING FROM DEFAULT %s INTERFACE] \n" , devname);
	    	handle = pcap_open_live(devname , 65536 , 1 , 0  , errbuf);
			
			if (handle == NULL)  
			{
	      		fprintf(stderr, "[ERROR] Couldn't open device %s : %s\n" , devname , errbuf);
				exit(1);
		  	}
			action = 1;
          	break;

        case 'p':
			printf("[SOON] Packets are not sniffed from now.");
        	break;

		case 'h':
			reference();

		 	printf("%s[MY AVAILABLE DEVICES]\n", KYEL); printf("%s", KNRM);
		 	for(device = alldevsp ; device != NULL ; device = device->next) {
		 		printf("%d. %s - %s\n" , count , device->name , device->description);
		 		if(device->name != NULL)
				{
					strcpy(devs[count] , device->name);
				}
				count++;
		 	}
			action = 0;
        	break;

        case 'v':
			printf("[SOON] Print number of packets received from ip address");
        	// printf ("Option -v with value `%s'\n", optarg);
        	break;

        case 'c':
			devname = devs[atoi(optarg)];
			printf("[SNIFFING FROM  %s INTERFACE] \n" , devname);
	    	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf); // for a 64bit Linux: 65535 bytes + 1
			if (handle == NULL)  
			{
	      		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
				exit(1);
		  	}
			action = 1;
        	break;

        case 'i':
			printf("[SOON] Collected statistics for particular interface.");
        	// printf ("Option -i with value `%s'\n", optarg);
        	break;

		case 'm':
			
			if (*optarg == 'P')    // show packets
				packets = 1;
			
			break;

        case '?': break;

        default: abort ();
        }
    }

	// if (verbose_flag) puts ("verbose flag is set\n");

	if (optind < argc)
    {
    	printf ("non-option ARGV-elements: \n");
    	while (optind < argc) printf ("%s ", argv[optind++]);
    	putchar ('\n');
    }

	if (action == 1) {  
    	logfile = fopen("log.txt","w");
		
		if(logfile == NULL) 
		{
			printf("[ERROR] Unable to create file.\n");
		}
		pcap_set_timeout(handle, 1000);
		pcap_loop(handle , -1 , process_packet , NULL);
	}
    exit (0);
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol)
	{
		
		case 6:  	// TCP 
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: 	// UDP 
			++udp;
			print_udp_packet(buffer , size);
		
			break;
		
		default: 	// Other,  like ARP etc.
			++others;
			break;
	}
	if (packets == 1)
	printf("TCP : %d   UDP : %d   Others : %d   Total : %d\r", tcp , udp , others , total);
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size);
		
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	print_data(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	print_data(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile , "Data Payload\n");	
	print_data(Buffer + header_size , Size - header_size );
						
	fprintf(logfile , "\n###########################################################");
}


void print_udp_packet(const u_char *Buffer , int Size)
{	
	unsigned short iphdrlen;	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	
	print_ip_header(Buffer,Size);			
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	print_data(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	print_data(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	print_data(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}


void print_data (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); 
				else fprintf(logfile , ".");
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1) 
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); 
			}
			fprintf(logfile , "         ");
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			fprintf(logfile ,  "\n" );
		}
	}
}

void reference() {
	printf("\n");
	printf("%s[USAGE INFORMATION]\n", KYEL);
	printf("%sExamples: \n", KNRM);
	printf("%s  sudo ./cniff --help", KNRM);  		  printf("%s           | get usage information or your net-devices\n", KYEL);
	printf("%s  sudo ./cniff --start", KNRM); 		  printf("%s          | sniff packets from default interface (eth0)\n", KYEL);
	printf("%s  sudo ./cniff --select [iface]", KNRM); printf("%s | sniff packets using wireless interface (dev-tab)\n", KYEL);
	printf("%s  sudo ./cniff --stat [iface]", KNRM);   printf("%s   | show collected statistics for particular interface\n", KYEL);
	printf("%s  sudo ./cniff --show [ip]", KNRM);      printf("%s      | print number of packets received from [ip] address\n", KYEL);
	printf("%s  sudo ./cniff --stop", KNRM);			  printf("%s           | stop sniffing\n", KYEL);
	printf("\n"); printf("\n");
	printf("%s[DEVICES TABLE] (dev-tab)\n", KYEL); 
	printf("%sWhen using a '--select' or '-c' option value of option must be:\n", KNRM);
	printf("<1> - Networking wireless interface (e.g. wlan0,  wlp2s0..)\n");
	printf("<2> - Pseudo-device that captures on all interfaces\n");
	printf("<3> - Loopback interface (lo)\n");
	printf("<4> - Networking wired interface (e.g. eth0, eth1, enp1s0..)\n");
	printf("<5> - Bluetooth adapter  (e.g. bluetooth0)\n");
	printf("<6> - Linux netfilter log (NFLOG) interface (nflog)\n");
	printf("<7> - Linux netfilter queue (NFQUEUE) interface (nfqueue)\n");
	printf("<8> - USB bus number 1 (usbmon1)\n");
	printf("<9> - USB bus number 2 (usbmon2)\n");
	printf("\n");
}