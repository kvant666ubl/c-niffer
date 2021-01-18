#include<pcap.h>    // network analysis

#include <stdio.h>  // in/out
#include <stdlib.h> // exit()
#include <string.h> // memset
#include <getopt.h> // CLI
#include <unistd.h> 

#include <syslog.h>        // logging to /var/log/syslog
#include <sys/types.h>  
#include <sys/stat.h>
#include <sys/socket.h>    // socket lib for commun
#include <stdlib.h>

#include <arpa/inet.h>     // inet_ntoa()
#include <net/ethernet.h>  // eth0 device

#include <netinet/udp.h>   // udp header
#include <netinet/tcp.h>   // tcp header

#include <fcntl.h>
#include <errno.h> // errors

#include "func.h" // funstions and constants 

struct sockaddr_in source, dest;
int tcp=0, udp=0, others=0, total=0, i, j; 

static int verbose_flag;
int packets = 0;

int main (int argc, char **argv)  
{
	/* PCAP-part*/
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; 				  
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
	uint8_t action = 0;
    
    /* Our process ID and Session ID */
    pid_t pid, sid; 
    
	/* Fork off the parent process */
    pid = fork();
    printf("PID is: %d\n", pid);
    if (pid < 0) {
    	exit(EXIT_FAILURE);
    }   
    
    /* Parent Process */
    if (pid > 0) {
    	exit(EXIT_SUCCESS);
    }   
    
	/* Change the file mode mask */
    umask(0);   
    
    /* Writing in /var/log/syslog */   
    setlogmask (LOG_UPTO (LOG_NOTICE));
    openlog ("[C-NIFFER]", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1); 

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
    	/* Log the failure */
    	exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
    	/* Log the failure */
    	exit(EXIT_FAILURE);
    }
    
    /* The Big Loop */
    while (1) 
    {
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
        	    	if (long_options[option_index].flag != 0) break;
        	    	printf ("option %s", long_options[option_index].name);
        	    	if (optarg) printf (" with arg %s", optarg);
        	    	printf ("\n");
        	    	break;

        	    case 's':
        	    	devname = devs[4];
        	    	printf("[SNIFFING FROM DEFAULT %s INTERFACE] \n" , devname);
        	    	handle = pcap_open_live(devname , 65536 , 1 , 0  , errbuf);
        	    	if (handle == NULL)  
        	    	{
        	    			syslog(LOG_NOTICE, "[CNIFFER] | [ERROR] Couldn't open device %s : %s\n" , devname , errbuf);
        	    			exit(1);
        	    	}
        	    	action = 1;
        	    	break;

        	    case 'p':
        	    	syslog(LOG_NOTICE, "[CNIFFER] | [SOON] Packets are not sniffed from now.");
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
                	break;

                case 'm':
                	/*
                	// Fixing...
                	if (*optarg == 'P') 
                    	packets = 1;
                	*/
                	break;

                case '?': 
			    	break;

                default: 
			    	abort ();
            }
        }

        if (optind < argc)
        {
            printf ("non-option ARGV-elements: \n");
            while (optind < argc) printf ("%s ", argv[optind++]);
            putchar ('\n');
        }
        
        if (action == 1) 
	    {
    	    pcap_set_timeout(handle, 1000);
    	    pcap_loop(handle , -1 , process_packet , NULL);
        }
    
        else exit(EXIT_SUCCESS);
    }

    closelog();
    exit(EXIT_SUCCESS);
}



void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;

	switch (iph->protocol)
	{   
		case 6:     // TCP 
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
        
        case 17:    // UDP 
            ++udp;
            print_udp_packet(buffer , size);
        
            break;
        
        default:    // Other,  like ARP etc.
            ++others;
            break;
    }

    if (packets == 1)
    printf("TCP : %d   UDP : %d   Others : %d   Total : %d\r", tcp , udp , others , total);
}



void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    syslog(LOG_NOTICE, "[CNIFFER]\n");
    syslog(LOG_NOTICE, "Ethernet Header\n");
    syslog(LOG_NOTICE, "|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    syslog(LOG_NOTICE, "|-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    syslog(LOG_NOTICE, "|-Protocol            : %u \n",(unsigned short)eth->h_proto);
}



void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
    unsigned short iphdrlen;
        
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    syslog(LOG_NOTICE , "\n");
    syslog(LOG_NOTICE , "IP Header\n");
    syslog(LOG_NOTICE , "|-IP Version       : %d\n",(unsigned int)iph->version);
    syslog(LOG_NOTICE , "|-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    syslog(LOG_NOTICE , "|-Type Of Service  : %d\n",(unsigned int)iph->tos);
    syslog(LOG_NOTICE , "|-IP Total Length  : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    syslog(LOG_NOTICE , "|-Identification   : %d\n",ntohs(iph->id));
    syslog(LOG_NOTICE , "|-TTL              : %d\n",(unsigned int)iph->ttl);
    syslog(LOG_NOTICE , "|-Protocol         : %d\n",(unsigned int)iph->protocol);
    syslog(LOG_NOTICE , "|-Checksum         : %d\n",ntohs(iph->check));
    syslog(LOG_NOTICE , "|-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    syslog(LOG_NOTICE , "|-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}



void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
    syslog(LOG_NOTICE , "\n\n***********************TCP Packet*************************\n");             
    print_ip_header(Buffer,Size);
    syslog(LOG_NOTICE , "\n");
    syslog(LOG_NOTICE , "TCP Header\n");
    syslog(LOG_NOTICE , "|-Source Port          : %u\n",ntohs(tcph->source));
    syslog(LOG_NOTICE , "|-Destination Port     : %u\n",ntohs(tcph->dest));
    syslog(LOG_NOTICE , "|-Sequence Number      : %u\n",ntohl(tcph->seq));
    syslog(LOG_NOTICE , "|-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    syslog(LOG_NOTICE , "|-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    syslog(LOG_NOTICE , "|-Push Flag            : %d\n",(unsigned int)tcph->psh);
    syslog(LOG_NOTICE , "|-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    syslog(LOG_NOTICE , "|-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    syslog(LOG_NOTICE , "|-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    syslog(LOG_NOTICE , "|-Window               : %d\n",ntohs(tcph->window));
    syslog(LOG_NOTICE , "|-Checksum             : %d\n",ntohs(tcph->check));
    syslog(LOG_NOTICE , "|-Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
    syslog(LOG_NOTICE , "|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    syslog(LOG_NOTICE , "|-Urgent Pointer       : %d\n",tcph->urg_ptr);
    syslog(LOG_NOTICE , "\n");
    syslog(LOG_NOTICE , "                        HEX-DATA DUMP                     ");
    syslog(LOG_NOTICE , "\n");
    syslog(LOG_NOTICE, "IP Header\n");
    print_data(Buffer,iphdrlen);
    syslog(LOG_NOTICE, "TCP Header\n");
    print_data(Buffer+iphdrlen,tcph->doff*4);
    syslog(LOG_NOTICE, "Data Payload\n");
    print_data(Buffer + header_size , Size - header_size );
    syslog(LOG_NOTICE, "\n###########################################################");
}



void print_udp_packet(const u_char *Buffer , int Size)
{   
    unsigned short iphdrlen;    
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    
    syslog(LOG_NOTICE, "\n\n***********************UDP Packet*************************\n");
    print_ip_header(Buffer,Size);           
    syslog(LOG_NOTICE, "\nUDP Header\n");
    syslog(LOG_NOTICE,  "|-Source Port      : %d\n" , ntohs(udph->source));
    syslog(LOG_NOTICE,  "|-Destination Port : %d\n" , ntohs(udph->dest));
    syslog(LOG_NOTICE,  "|-UDP Length       : %d\n" , ntohs(udph->len));
    syslog(LOG_NOTICE,  "|-UDP Checksum     : %d\n" , ntohs(udph->check));
    
    syslog(LOG_NOTICE,  "\n");
    syslog(LOG_NOTICE, "IP Header\n");
    print_data(Buffer , iphdrlen);
    syslog(LOG_NOTICE,  "UDP Header\n");
    print_data(Buffer+iphdrlen , sizeof udph);
    syslog(LOG_NOTICE, "Data Payload\n");    
    print_data(Buffer + header_size , Size - header_size);
    syslog(LOG_NOTICE, "\n###########################################################");
}



void print_data (const u_char * data , int Size)
{
    int i , j;
    for(i = 0 ; i < Size ; i++)
    {
        if( i != 0 && i % 16 == 0)   
        {
            syslog(LOG_NOTICE, "         ");
            for(j = i-16; j < i; j++)
            {
                if(data[j]>=32 && data[j]<=128) syslog(LOG_NOTICE, "%c", (unsigned char)data[j]);
                else syslog(LOG_NOTICE, ".");
            }
            syslog(LOG_NOTICE, "\n");
        } 
        
        if(i%16==0) syslog(LOG_NOTICE, "   ");
            syslog(LOG_NOTICE, " %02X", (unsigned int)data[i]);
                
        if(i==Size-1) 
        {
            for(j=0;j<15-i%16;j++) 
            {
              syslog(LOG_NOTICE, "   "); 
            }
            syslog(LOG_NOTICE, "         ");
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  syslog(LOG_NOTICE, "%c",(unsigned char)data[j]);
                }
                else 
                {
                  syslog(LOG_NOTICE, ".");
                }
            }
            syslog(LOG_NOTICE,  "\n" );
        }
    }
}



void reference() {
    printf("\n");
    printf("%s[USAGE INFORMATION]\n", KYEL);
    printf("%s➤ Examples: \n", KNRM);
    printf("%-32s", "  sudo ./cniff --help"); 		printf("%s\n", " →  get usage information or your net-devices");
    printf("%-32s", "  sudo ./cniff --start");		printf("%s\n", " →  sniff packets from default interface (eth0)");
    printf("%-32s", "  sudo ./cniff --select [iface]"); printf("%s\n", " →  sniff packets using wireless interface (dev-tab)");
    printf("%-32s", "  sudo ./cniff --stat [iface]");   printf("%s\n", " →  show collected statistics for particular interface");
    printf("%-32s", "  sudo ./cniff --show [ip]");      printf("%s\n", " →  print number of packets received from [ip] address");
    printf("%-32s", "  sudo ./cniff --stop");           printf("%s\n", " →  stop sniffing");
    printf("\n");
    printf("%s[DEVICES TABLE] (dev-tab)\n", KYEL); 
    printf("%s➤ When using a '--select' or '-c' option value of option must be:\n", KNRM);
    printf("	<1> Networking wireless interface (e.g. wlan0,  wlp2s0..)\n");
    printf("	<2> Pseudo-device that captures on all interfaces\n");
    printf("	<3> Loopback interface (lo)\n");
    printf("	<4> Networking wired interface (e.g. eth0, eth1, enp1s0..)\n");
    printf("	<5> Bluetooth adapter  (e.g. bluetooth0)\n");
    printf("	<6> Linux netfilter log (NFLOG) interface (nflog)\n");
    printf("	<7> Linux netfilter queue (NFQUEUE) interface (nfqueue)\n");
    printf("	<8> USB bus number 1 (usbmon1)\n");
    printf("	<9> USB bus number 2 (usbmon2)\n");
    printf("\n");
}
