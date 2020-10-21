/*
 * Spades Firewall - A firewall for Aos
 * Author: Atom
*/

/* Libs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pthread.h>

/* Config */
#define	FIREWALL_VERSION 	"0.1" 	// Firewall version
#define RATELIMIT_SECONDS	(1)		// Time for clear packets count (Default: 5 seconds)
#define CLEAR_SECONDS	 	(60) 	// Time for clear the blocked list (Default: 1 minute)
#define MAX_PACKETS		 	(100)  	// MAX_PACKETS per RATELIMIT_SECONDS (Default: 50 packets per 1 seconds)
#define	STRUCT_NUMBER	 	(700) 	// Max size for register list and blocked list (Default: 700)

/* Defines */
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

typedef unsigned int uint;

void ProcessPackets(u_char*, const struct pcap_pkthdr*, const u_char*);
void ProcessUDPPacket(const u_char*, int);
void BlockIncomingAttack(char* host, u_short port, u_short dst_port);

void* rl_threadCheck(void* ptr);
void rl_threadReload();

void* bl_threadCheck(void* ptr);
void bl_threadReload();

void BlockAddress(char* host, u_short port, u_short dst_port);
int GetAddressIndex(char* host);
int IsAddressBlocked(char* host);
void ResetRules();

struct userPackets
{
	char host[30];
	long int TotalPackets;
};
struct userPackets ddosInfo[STRUCT_NUMBER];

struct blockPackets
{
	char host[30];
};
struct blockPackets blockedInfo[STRUCT_NUMBER];

struct sockaddr_in source, dest;

FILE* logfile;
time_t _rw;
struct tm *tm;

int main(int argc, char* argv[])
{
	// Thread for clear packets count
	rl_threadReload();
	pthread_t thread1;
	pthread_create(&thread1, NULL, rl_threadCheck, NULL);

	// Thread for clear the blocked list
	bl_threadReload();
	pthread_t thread2;
	pthread_create(&thread2, NULL, bl_threadCheck, NULL);
	
	pcap_if_t *alldevsp;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// Get interface
	char* iface;
	if (!argv[1])
	{
		FILE* f = fopen("/proc/net/route", "r");
		char line[100];
		while (fgets(line, 100, f))
		{
			char* p = strtok(line, " \t"); char* c = strtok(NULL, " \t");
			if ((p != NULL && c != NULL) && (strcmp(c, "00000000") == 0))
			{
				iface = p;
				break;
			}
		}
	}
	else iface = argv[1];
	
	// Started
	system("clear");
	
	printf(""RESET"███████╗██████╗  █████╗ ██████╗ ███████╗███████╗\n");
	printf("██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝\n");
	printf("███████╗██████╔╝███████║██║  ██║█████╗  ███████╗\n");
	printf("╚════██║██╔═══╝ ██╔══██║██║  ██║██╔══╝  ╚════██║\n");
	printf("███████║██║     ██║  ██║██████╔╝███████╗███████║\n");
	printf("╚══════╝╚═╝     ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝\n");
	printf("    Spades Firewall by Atom [v"FIREWALL_VERSION"] started.\n\n");

	if (argc < 2) printf("[!] Help: %s <iface>\n", argv[0]);

	if (!argv[1])
		printf("[!] Using default interface:"YEL" \"%s\""RESET".\n", iface);
	
	printf("[!] Finding available devices, please wait...");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("\n[!] Error finding devices: "RED"%s"RESET"\n", errbuf);
		exit(1);
	}
	printf(" "GRN"Done"RESET".\n");
	
	printf("[!] Opening device"YEL" \"%s\""RESET" for sniffing...", iface);
	handle = pcap_open_live(iface, 65536, 1, 0, errbuf);
	
	if (handle == NULL)
	{
		printf("\n[!] Couldn't open device \"%s\": "RED"%s"RESET"\n", iface, errbuf);
		exit(1);
	}
	printf(" "GRN"Done"RESET".\n");
	printf(RESET "\n");
	
	pcap_setdirection(handle, PCAP_D_IN);
	pcap_loop(handle, -1, ProcessPackets, NULL);
	return 0;
}

/* Process packets */
void ProcessPackets(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol)
	{
		case 17: // UDP Protocol
		{
			ProcessUDPPacket(buffer, header->len);
			break;
		}
		default: break;
	}
}

void ProcessUDPPacket(const u_char* buffer, int size)
{
	unsigned short iphdrlen;
	
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	struct udphdr* udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	
	BlockIncomingAttack(inet_ntoa(source.sin_addr), ntohs(udph->source), ntohs(udph->dest));
}

/* Mitigation */
void BlockIncomingAttack(char* host, u_short port, u_short dst_port)
{
	int blocked = IsAddressBlocked(host);
	if (!blocked)
	{
		int check = GetAddressIndex(host);
		if (check != -1) // If already exists in list
		{
			ddosInfo[check].TotalPackets ++;
			if (ddosInfo[check].TotalPackets > MAX_PACKETS) // Is flooding
				BlockAddress(ddosInfo[check].host, port, dst_port);
		}
		else // Register new address
		{
			int i = 0;
			for (i = 0; i < STRUCT_NUMBER; i++)
			{
				if (strcmp(ddosInfo[i].host, "127.0.0.1") == 0)
				{
					strcpy(ddosInfo[i].host, host);
					ddosInfo[i].TotalPackets += 1;
					break;
				}
			}
		}
	}
}

/* Utils */
void BlockAddress(char* host, u_short port, u_short dst_port)
{
	static char buffer[85];
	sprintf(buffer, "Incoming attack from %s:%d to port %d.\n", host, port, dst_port);
	printf("[*] %s", buffer);
	time(&_rw);
	tm = localtime(&_rw);
	if ((logfile = fopen("log.txt", "a")) == NULL)
		printf("[!] Unable to open log file.\n");

	fprintf(logfile, "[%02d/%02d/%02d - %02d:%02d:%02d] %s", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, buffer);
	fclose(logfile);

	char cmd[50];
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "iptables -A INPUT -s %s -j DROP", host);
	system(cmd);

	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		if (strlen(blockedInfo[i].host) < 4)
		{
			strcpy(blockedInfo[i].host, host);
			break;
		}
	}
}

void ResetRules()
{
	// Flush rules
	system("iptables -F");

	// Block ICMP
	system("iptables -t mangle -A PREROUTING -p icmp -j DROP");

	// Block private address
	system("iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP"); 
	system("iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP");
	system("iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP");
}

int GetAddressIndex(char* host)
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		if (strcmp(ddosInfo[i].host, host) == 0)
		return i;
	}
	return -1;
}

int IsAddressBlocked(char* host)
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		if (strcmp(blockedInfo[i].host, host) == 0)
		return 1;
	}
	return 0;
}

/* Ratelimit check */
void rl_threadReload()
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		strcpy(ddosInfo[i].host, "127.0.0.1");
		ddosInfo[i].TotalPackets = 0;
	}
}

void* rl_threadCheck(void* ptr)
{
	while (1)
	{
		sleep(RATELIMIT_SECONDS);
		rl_threadReload();
	}
}

/* Clear blacklist */
void bl_threadReload()
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		strcpy(blockedInfo[i].host, "");
	}

	ResetRules();
}

void* bl_threadCheck(void* ptr)
{
	while (1)
	{
		sleep(CLEAR_SECONDS);
		bl_threadReload();
	}
}