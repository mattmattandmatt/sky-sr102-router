/*

	Transfers the PPPoA IP to a Client LAN, simulates a Bridge Mode
	   this relies on 'dsldetails' to get 2 settings

	This also communicates with the built in Web Interface to
	   change it to a Normal Bridge Mode

	Matt Goring - July 2015, sorry for the compile warnings.

*/





#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>



#include "../../../gpl/apps/udhcp/dhcpd.h"
#include "../../../gpl/apps/udhcp/packet.h"
#define LEASE_TIME 60	// Seconds
#define ddebug 0
struct dhcpMessage packet;
char lease_mac_addr[6];	// Leased out WAN to this MAC
int  leased_time;		// Expiry time



#define BRIDGE_MODE_FILE "/etc/bridgemode"	// 0=None, 1=Normal Bridge, 2=Dhcp'd Bridge
int  bridge_mode_type;
char *httppass;
char *httpauth;
char sesskey[12];	// Numerical value as a string



struct sockaddr_in server;	// Local HTTP
int web_sock;		// IP sockets
struct ifreq ifrBR;	// br0 IP
int local_ip;		// private
int local_subnet;	// private
int wan_ip;			// public
int wan_ptp;		// public Point to Point
int wan_gw;			// faked +/-1 of public, local interface
int wan_subnet;		// computed smallest
int wan_dns1;
int wan_dns2;



// Base64 - copied from somewhere ?
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};



void change_to_normal_bridge_mode();
int  get_session_key(const char *main_page);
void logout_session();
void get_web_page(const char *web_url);
void change_to_dhcp_bridge_mode();
void find_another_ip_subnet();
void *thread_socket_udp_handler();



// This function is copied from the Net,  I think from StackOverflow
static void daemonise()
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
	}

    if (pid > 0) {
        exit(EXIT_SUCCESS);
	}

    /* On success: The child process becomes session leader */
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
	}
	
    /* Catch, ignore and handle signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0) {
        exit(EXIT_FAILURE);
	}

    /* Success: Let the parent terminate */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
	}

    /* Set new file permissions */
    umask(0666);

    /* Change the working directory */
    chdir("/etc");

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
    {
        close (x);
    }

}





// Base64 copied from = http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
char *base64_encode(const unsigned char *data, int input_length, int output_length)
{
	output_length = 4 * ((input_length + 2) / 3);
	int i, j;
	char *encoded_data = malloc(output_length);
	if (encoded_data == NULL) { return NULL; }

	for (i = 0, j = 0; i < input_length;)
	{
		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (i = 0; i < mod_table[input_length % 3]; i++)
	{
		encoded_data[output_length - 1 - i] = '=';
	}

	return encoded_data;
}

void build_decoding_table()
{
	int i;
    decoding_table = malloc(256);
    for (i = 0; i < 64; i++)
	{
        decoding_table[(unsigned char) encoding_table[i]] = i;
	}
}






int main(int argc, char *argv[])
{
	if (argc > 1)
	{
		if (strstr(argv[1], "help"))
		{
			printf("dhcpbridge, no arguments.\n"
					"This dhcp-bridge transfers the IP from PPPoA0 to a LAN dhcp client,\n"
					"when the interface is active\n");
			return EXIT_SUCCESS;
		}
	}
	
	
	
	FILE *bridgefd;
	char *line = NULL;
	size_t  lenf;
	ssize_t readcnt;
	httppass = (char*) malloc (65);
	
	
	
	//const char BRIDGE_MODE_FILE[] = "/etc/bridgemode";
	bridgefd = fopen(BRIDGE_MODE_FILE, "r");
	if (bridgefd == NULL)
	{
		// No Conf file, no bridge mode
		return 0;
	}
	else
	{
		//  Get Bridge Mode Type
		readcnt = getline (&line, &lenf, bridgefd);
		bridge_mode_type = atoi (line);
		readcnt = getline (&line, &lenf, bridgefd);
		strncpy ( httppass, line, readcnt -1 );
		
		free (line);
		fclose (bridgefd);
	}
	
	if (bridge_mode_type == 0)
	{
		return 0;
	}
	
	
	
	
	
#if ddebug
	// No Daemonise
#else
	daemonise();
#endif
	
	
	
	
	
	// Open Socket, keep open as much as possible
	if ( (web_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("ERROR opening socket\n");
		return 1;
	}
	
	
	
	
	
	
	// Get Local IP / Subnet
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0", 6);	// Bridge Interface
	
	
	// When booting, wait for the interface to be created, upto 25 seconds
	int retry_time;
	for (retry_time = 0; retry_time <= 60; retry_time++)
	{
		if (ioctl(web_sock, SIOCGIFADDR, &ifrBR) == -1)
		{
			sleep (1);
		}
		else
		{
			break;
		}
	}
	
	ioctl(web_sock, SIOCGIFADDR, &ifrBR);		// br0 IP
	local_ip     = ((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr;
	ioctl(web_sock, SIOCGIFNETMASK, &ifrBR);	// br0 NetMask
	local_subnet = ((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr;
#if ddebug
	printf("IP:  %s\n", inet_ntoa(local_ip));
	printf("Sub: %s\n", inet_ntoa(local_subnet));
#endif
	
	
	
	
	
	// Broadcom Web Interface Info
    server.sin_addr.s_addr = inet_addr("127.0.0.1\0\0\0\0\0\0");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
	
	
	
	// Base64 Auth String
	char *tmpauthin = (char*) malloc (255);
	int outlen = 0;
	httpauth = (char*) malloc (255);
	strcpy(tmpauthin, "admin:");
	strcat(tmpauthin, httppass);
	build_decoding_table();
	httpauth = base64_encode (tmpauthin, strlen (tmpauthin), outlen);
#if ddebug
    printf("Base64: %s %s\n", tmpauthin, httpauth);
#endif
	free (decoding_table);
	free (tmpauthin);
	
	
	
	
	
	
	
	
	
	if (bridge_mode_type == 2)
	{
		// Temporary Address until PPP connects
		wan_ip     = 0x0A000001;
		wan_gw     = 0x0A000002;
		wan_subnet = 0xFFFFFFFC;
		//memset (lease_mac_addr, 0xFF, 6);
		wan_dns1 = 0x08080808;	// Default Google DNS
		wan_dns2 = 0x08080404;
		
		// Closed existing dhcp server, 1st attempt
		system("pkill dhcpd");
		// Fork off the Listen Thread
		pthread_t sniffer_thread;
		pthread_create( &sniffer_thread, NULL, thread_socket_udp_handler, NULL );
	}	
	
	
	
	
	
	
	
	// Listen for an Interface Change
	// Mostly Copied from http://stackoverflow.com/questions/579783/how-to-detect-ip-address-change-programmatically-in-linux/2353441#2353441
	struct sockaddr_nl addr;
	int sock, len, i;
	char buffer[4096];
	struct nlmsghdr *nlh;
	struct stat st;
	time_t last_intf_read;


	if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
	{
		perror("err int: NETLINK_ROUTE socket");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR; // | RTMGRP_LINK;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
		perror("err int: bind");
		return 1;
	}



	nlh = (struct nlmsghdr *)buffer;
	while ((len = recv(sock, nlh, 4096, 0)) > 0)	// Wait/Blocking
	{
		// Calls appear to double tap
		if ((last_intf_read + 5) >= time(NULL))
		{
			continue;
		}
		last_intf_read = time(NULL);
		
		
		while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE))
		{
			if (nlh->nlmsg_type == RTM_NEWADDR)
			{
				struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
				struct rtattr *rth = IFA_RTA(ifa);
				int rtl = IFA_PAYLOAD(nlh);
				
				while (rtl && RTA_OK(rth, rtl))
				{
					if (rth->rta_type == IFA_LOCAL)
					{
						uint32_t ipaddr = htonl(*((uint32_t *)RTA_DATA(rth)));
						char name[IFNAMSIZ];
						if_indextoname(ifa->ifa_index, name);
#if ddebug
						printf("%s is now %d.%d.%d.%d   %x   %d\n",
							   name, (ipaddr >> 24) & 0xFF, (ipaddr >> 16) & 0xFF,
									 (ipaddr >>  8) & 0xFF,  ipaddr & 0xFF, ipaddr, ipaddr);
#endif
						
						
						if ( !strcmp (name, "pppoa0") )
						{
							sleep (4);	// Let most of the SSK finish, takes about 2.8 secs
#define DNSINFO_CONF  "/var/dnsinfo.conf"	// cms.h
							// Wait for the dns values to update
							//    or the web interface crashes.
							for (i=0; i<30; i++)
							{
								stat(DNSINFO_CONF, &st);
								if (st.st_size > 20)
								{
									break;
								}
								sleep (1);
							}
							
							switch (bridge_mode_type)
							{
								case 1:	// Normal
									change_to_normal_bridge_mode();
									break;
								case 2:	// DCHP'd
									change_to_dhcp_bridge_mode();
									break;
							}
						}
					
					
					}
					rth = RTA_NEXT(rth, rtl);
				}
			}
			nlh = NLMSG_NEXT(nlh, len);
		}
	}
	
	
	
	logout_session();
	return 0;
}





void change_to_normal_bridge_mode()	// Using the Web Interface
{
	//close (web_sock);
	//web_sock = socket(AF_INET, SOCK_STREAM, 0);
    //connect(web_sock, (struct sockaddr *)&server, sizeof(server));
	
	get_session_key ("/wancfg.cmd");
	get_web_page ("/wancfg.cmd?action=remove&rmLst=pppoa0");
	get_web_page ("/wancfg.cmd?action=remove&rmLst=eth0");
	get_web_page ("/wancfg.cmd?action=remove&rmLst=atm0");
	get_web_page ("/wancfg.cmd?action=remove&rmLst=atm0.1");
	
	get_session_key ("/dslatm.cmd");	// Try to Delete, if its still there
	get_web_page ("/dslatm.cmd?action=remove&rmLst=atm0");
	get_session_key ("/ethwan.cmd");
	get_web_page ("/ethwan.cmd?action=remove&rmLst=eth0");
	
	
	
	// Add ATM
	/*
		Add a ATM interface via the command line
		xtmctl operate conn --add 1.0.38 aal5 vcmux_pppoa 0 1 1
		xtmctl operate conn --createnetdev 1.0.38 atm2
		ifconfig atm2 up
	*/
	get_session_key ("/dslatm.cmd");
	get_web_page ("/dslatm.cmd?action=add&atmVpi=0&atmVci=38&portId=0&linkType=EoA&connMode=1&"
					"encapMode=0&atmServiceCategory=UBR&atmPeakCellRate=0&atmSustainedCellRate=0&"
					"atmMaxBurstSize=0&atmMinCellRate=-1&enblQos=1&grpPrec=8&grpAlg=WRR&grpWght=1&prec=8&"
					"alg=WRR&wght=1");
	
	
	// Add WAN/Bridge
	/*
		Can not reliably add a PPPoA interface via the command line.
		So using the Http instead.
		Tried variations on: pppd -c ppp2 -a atm2.0.0.38 -u username@isp -p PASSWORD -f 0
	*/
	get_session_key ("/wancfg.cmd");
	get_web_page ("/wanifc.cmd?serviceId=0");
	get_web_page ("/wansrvc.cmd?wanL2IfName=atm0/(0_0_38)");
	get_web_page ("/ntwksum2.cgi?enblEnetWan=0&ntwkPrtcl=3&enVlanMux=1&vlanMuxId=-1&vlanMuxPr=-1&serviceName=br_0_0_38");
	get_web_page ("/wancfg.cmd?action=add");
	
	sleep (2);
	logout_session();
}





int get_session_key(const char *main_page)
{
	int attempt = 0;
	TryAgain:;
	
	close (web_sock);
	if ( (web_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("ERROR opening socket\n");
		return 1;
	}
    if (connect(web_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		printf("ERROR opening connection\n");
		return 2;
	}
	
	
	
	
	
    char *buffer = (char*) malloc (4080);
	int n;
	int key_ses_pos;
	
#if ddebug
	printf("GETs %s\n", main_page);
#endif
	sprintf(buffer, "GET %s HTTP/1.1\r\nAuthorization: Basic %s\r\n\r\n", main_page, httpauth);
    n = write(web_sock, buffer, strlen(buffer));
	
	while (n)
	{
		n = read(web_sock, buffer, 4080);
#if ddebug
		printf(">%.99s<\n", buffer);
#endif
		if ( (key_ses_pos = strstr(buffer, "401 Unauthorized")) != NULL )
		{
			// Unauthorised, needs another attempt
			attempt += 1;
			if ( attempt == 3 )
			{
				free (buffer);
#if ddebug
				printf("Too many retries\n");
#endif
				return 4;
			}
			goto TryAgain;
		}
		else if ( (key_ses_pos = strstr(buffer, "This page is not supported")) != NULL )
		{
			// Another User logged in
			close (web_sock);
			system("pkill httpd");
			sync();
			goto TryAgain;
			break;
		}
		else if ( (key_ses_pos = strstr(buffer, "&sessionKey=")) != NULL )
		{
			n = strstr(key_ses_pos, "'");
			//printf("YYY:%d:%d:%d:\n", sesskey, key_ses_pos, buffer);
			strncpy (sesskey, key_ses_pos + 12, n - key_ses_pos - 12);
			sesskey[n - key_ses_pos - 12] = 0;
#if ddebug
			printf("KEYs %s\n", sesskey);
#endif
			while (n)
			{
				n = read(web_sock, buffer, 4080);
			}
			free (buffer);
			return 0;
			break;
		}
		else
		{
			// Error
			attempt += 1;
			if ( attempt == 3 )
			{
				free (buffer);
#if ddebug
				printf("Too many retries\n");
#endif
				return 4;
			}
			goto TryAgain;
		}
	}
	
	free (buffer);
	return 3;
}
	




void logout_session()
{
	// Logout
	/*
    char *buffer = (char*) malloc (4081);
	sprintf(buffer, "GET /sky_logout.html HTTP/1.1\r\nAuthorization: Basic %s\r\n\r\n", httpauth);
    write(web_sock, buffer, strlen(buffer));
	read(web_sock, buffer, 4080);
	
	close (web_sock);
	free (buffer);
	*/
	
	
	
	//close (web_sock);
	sync();
	system("pkill httpd");	// Easier !
}





void get_web_page(const char *web_url)
{
	int n, i, key_ses_pos;
    char *buffer = (char*) malloc (4080);
	
	close (web_sock);
	web_sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(web_sock, (struct sockaddr *)&server, sizeof(server));
	
#if ddebug
	printf("GETp %s\n", web_url);
#endif
	sprintf(buffer, "GET %s&sessionKey=%s HTTP/1.1\r\n"
					"Authorization: Basic %s\r\n\r\n", web_url, sesskey, httpauth);
    n = write(web_sock, buffer, strlen(buffer));
	while (n)
	{
		n = read(web_sock, buffer, 4080);	// Ignore Contents
#if ddebug
		printf(">%.99s<\n", buffer);
#endif
		// Check if the Session Key has changed
		if ( (key_ses_pos = strstr(buffer, "&sessionKey=")) != NULL )
		{
			i = strstr(key_ses_pos, "'");
			strncpy (sesskey, key_ses_pos + 12, i - key_ses_pos - 12);
			sesskey[i - key_ses_pos - 12] = 0;
#if ddebug
			printf("KEYp %s\n", sesskey);
#endif
		}
	}
	
	free (buffer);
}





void change_to_dhcp_bridge_mode()
{
	struct ifreq ifr;
	int temp_ip;
	int non_route_ip = inet_addr("192.0.2.1\0\0\0\0\0\0");
	
	system("pkill dhcpd");	// Just in case
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy (ifr.ifr_name, "pppoa0", 7);
	
	// Get WAN IP
	ioctl(web_sock, SIOCGIFADDR, &ifr);
	temp_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
#if ddebug
	printf("temp_ip: %s\n", inet_ntoa(temp_ip));
	printf("wan_ip:  %s\n", inet_ntoa(wan_ip));
#endif
	
	if ( (temp_ip == wan_ip) || (temp_ip == non_route_ip) )
	{
		return;
	}
	
	wan_ip = temp_ip;
	
	
	
	// Get WAN PtP IP
	ioctl(web_sock, SIOCGIFDSTADDR, &ifr);
	wan_ptp = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
#if ddebug
	printf("wan_ptp: %s\n", inet_ntoa(wan_ptp));
#endif
	
	
	
	find_another_ip_subnet();
	
	
	
	char *buf = (char*) malloc(4080);
	
	char *c_non_route_ip = strdup(inet_ntoa(non_route_ip));
	char *c_wan_ip       = strdup(inet_ntoa(wan_ip));
	char *c_wan_gw       = strdup(inet_ntoa(wan_gw));
	char *c_wan_ptp      = strdup(inet_ntoa(wan_ptp));
	char *c_local_ip     = strdup(inet_ntoa(local_ip));
	char *c_local_subnet = strdup(inet_ntoa(local_subnet));

#if ddebug
	printf("IPs: %s %s %s %s %s %s\n", c_non_route_ip, c_wan_ip, c_wan_gw, c_wan_ptp, c_local_ip, c_local_subnet);
#endif
	sprintf (buf, "ifconfig pppoa0 %s pointopoint %s", c_non_route_ip, c_wan_ptp);
	system(buf);
	sprintf (buf, "ifconfig br0 %s netmask 255.255.255.255 up", c_wan_gw);
	system(buf);
	sprintf (buf, "ifconfig br0:1 %s netmask %s up", c_local_ip, c_local_subnet);	// Move Local IP
	system(buf);
	system("ip route flush table main");
	sprintf (buf, "route add %s/32 dev pppoa0", c_wan_ptp);
	system(buf);
	sprintf (buf, "route add %s/32 dev br0", c_wan_ip);
	system(buf);
	sprintf (buf, "route add default gw %s pppoa0", c_wan_ptp);
	system(buf);
	system("route add -net 10.0.0.0/8 dev br0");
	system("route add -net 172.16.0.0/12 dev br0");
	system("route add -net 192.168.0.0/16 dev br0");

	system("iptables -F");
	system("iptables -t nat -F");
	system("iptables -t mangle -F");
	system("iptables -P INPUT ACCEPT");
	system("iptables -P FORWARD ACCEPT");
	system("iptables -P OUTPUT ACCEPT");
	system("iptables -I INPUT -d 10.0.0.0/255.0.0.0      -i pppoa0 -j DROP");
	system("iptables -I INPUT -d 172.16.0.0/255.240.0.0  -i pppoa0 -j DROP");
	system("iptables -I INPUT -d 192.168.0.0/255.255.0.0 -i pppoa0 -j DROP");
	system("iptables -I INPUT -d 192.0.2.0/255.255.255.0 -i pppoa0 -j DROP");



	// Get DNS Servers, from a delimited file
	char *line = NULL;
	FILE *file = fopen("/var/dnsinfo.conf", "r");
	if (file)
	{
		getline (&line, &temp_ip, file);
		fclose(file);
		strsep(&line, ";");	// Interface
		strsep(&line, ";");	// Local Subnet
		wan_dns1 = inet_addr(strsep(&line, ","));	// DNS 1
		wan_dns2 = inet_addr(strsep(&line, ","));	// DNS 2
#if ddebug
		printf("dns1=%x, dns2=%x\n", wan_dns1, wan_dns2);
#endif
	}

	free (buf);
}



void find_another_ip_subnet()
{
	// Using the WAN IP address, it adds / subtracts 1 and calculates the smallest subnet
	int i, zero, one;
	int temp_ip;
	int sub[3] = {0};
	
	for (temp_ip = wan_ip - 1; temp_ip <= wan_ip + 2; temp_ip++)
	{
		zero = 0;
		one = 0;
		for (i = 0; i <= 30; i++)
		{
			// Look for the first Zero && One
			if ( (temp_ip & (1 << i)) == 0 )
			{
				if ( (one > 0) && (zero > 0) ) { break; }
				if (one == 0) { one = 1; }
			}
			else
			{
				if ( (one > 0) && (zero > 0) ) { break; }
				if (zero == 0) { zero = 1; }
			}
		}
		
		// Save possible Subnet ending point
		if ( temp_ip == (wan_ip - 1) )
		{
			sub[0] = i;
		}
		else if ( temp_ip == (wan_ip + 0) )
		{
			sub[1] = i;
		}
		else if ( temp_ip == (wan_ip + 1) )
		{
			sub[2] = i;
		}
	}
	
	
	// Save the smaller of the 2, if its larger than the WANP_IP subnet
	if (sub[0] <= sub[2])
	{
		wan_gw = wan_ip - 1;
		wan_subnet = -1 << (sub[0] > sub[1] ? sub[0] : sub[1]);
	}
	else
	{
		wan_gw = wan_ip + 1;
		wan_subnet = -1 << (sub[2] > sub[1] ? sub[2] : sub[1]);
	}
	
#if ddebug
	printf("subs=%d, 2=%d, 3=%d\n", sub[0], sub[1], sub[2]);
	printf("ip=%x, 2=%x\n", wan_gw, wan_subnet);
#endif

}



// Mostly Copied from http://www.binarytides.com/programming-udp-sockets-c-linux/
void *thread_socket_udp_handler() // listen_to_dhcp_packets()
{
	struct sockaddr_in si_me, si_other;
	int sck, slen = sizeof(si_other), recv_len;
	char buf[550];



	// create a UDP socket
	if ((sck = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	{
		perror("err socket");
	}

	if (setsockopt(sck, SOL_SOCKET, SO_BINDTODEVICE, "br0", 6) == -1)
	{
		perror("err SO_BINDTODEVICE");
	}

	int broadcastEnable = 1;
	if (setsockopt(sck, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)))
	{
		perror("err SO_BROADCAST");
	}



	// zero out the structure
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(67);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);	// INADDR_ANY

	// bind socket to port
	if( bind(sck , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
	{
		perror("err bind");
	}



	// Keep listening for data
	while (1)
	{
		// Receive UDP data, Wait/Blocking call
		if ((recv_len = recvfrom(sck, buf, 550, 0, (struct sockaddr *) &si_other, &slen)) == -1)
		{
			perror("err recvfrom");
			continue;
		}
		
		time_t current_secs = time(NULL);
		memcpy(&packet, buf, 240); //recv_len);
		
#if ddebug
		printf("Time: %d\n", current_secs);
		printf("Received packet: %s:%d len(%d)\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), recv_len);
		printf("Packet info: %d:%d:%d:%d:%x:\n", packet.op, packet.htype, packet.hlen, packet.hops, packet.cookie);
		printf("MAC start: %x:%x:%x:%x:\n", packet.chaddr[0], packet.chaddr[1], packet.chaddr[2], packet.chaddr[3]);
#endif		

		// Check if its a Proper Packet, Renew or Timed Out
		if ( (packet.op == BOOTREQUEST) && (packet.htype == ETH_10MB) && (packet.cookie == DHCP_MAGIC) &&
				((memcmp(packet.chaddr, lease_mac_addr, 6) == 0) || (leased_time <= current_secs)) )
		{
			packet.op = BOOTREPLY;
			packet.hops = 0;
			packet.secs = 0;
			packet.yiaddr = wan_ip;
			memcpy (buf, &packet, 240);
			
			// Make a few Vendor Options
			buf[240] = 53;	// Message Type
			buf[241] = 1;	// Length
			if (buf[242] == DHCPDISCOVER)	// Hmmm, should not have cheated here, luckily option 53
			{								//	appears to always be the first option.
				buf[242] = DHCPOFFER;
			}
			else if (buf[242] == DHCPRELEASE)
			{
				buf[242] = DHCPACK;
				leased_time = 0;
			}
			else
			{
				buf[242] = DHCPACK;
				memcpy (lease_mac_addr, packet.chaddr, 6);
				leased_time = current_secs + LEASE_TIME + 2;	// Give 2 extra seconds for the same MAC addr,
																// When the WAN IP changes, it starts Discovery again.
			}
			
			buf[243] = 54;	// Server ID
			buf[244] = 4;
			memcpy (&buf[245], &wan_gw, 4);
			buf[249] = 51;	// IP Lease Time
			buf[250] = 4;
			buf[251] = (LEASE_TIME >> 24) & 0x7F;	buf[252] = (LEASE_TIME >> 16) & 0xFF;
			buf[253] = (LEASE_TIME >>  8) & 0xFF;	buf[254] = LEASE_TIME & 0xFF;
			buf[255] = 1;	// Subnet Mask
			buf[256] = 4;
			memcpy (&buf[257], &wan_subnet, 4);
			buf[261] = 3;	// Router
			buf[262] = 4;
			memcpy (&buf[263], &wan_gw, 4);
			buf[267] = 6;	// DNS
			buf[268] = 8;
			memcpy (&buf[269], &wan_dns1, 4);
			memcpy (&buf[273], &wan_dns2, 4);
			buf[277] = 255;	// End
			
			
			// Reply Packet
			si_me.sin_port = htons(68);
			if (si_me.sin_addr.s_addr == htonl(INADDR_ANY))		// Non Unicast Request   (Not Renew)
			{
				si_me.sin_addr.s_addr = htonl(INADDR_BROADCAST);
			}
			if (sendto(sck, buf, 278, 0, (struct sockaddr*) &si_me, slen) == -1)
			{
				perror("err sendto");
			}
			
		}
	}

	close(sck);
	return 0;
}
