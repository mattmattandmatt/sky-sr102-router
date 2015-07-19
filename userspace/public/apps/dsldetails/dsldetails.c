/*

	The initial socket connection code copied from http://www.linuxhowtos.org/C_C++/socket.htm
	The get IP addresses code copied from http://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
	The rest is hand written (mostly) - Matt Goring - Feb 2015, adjusted July 2015

	Basicly it opens port 8080 - for the addon web interface, only allowing the local br0 subnet to connect.

	This program also supplies 2 settings for 'dhcpbridge'

	When starting: If there is no internet, it checks every 10 seconds,
		after that it checks the IPTABLES every 10 minutes.



	Make command line:
	/opt/toolchains/uclibc-crosstools-gcc-4.4.2-1/usr/bin/mips-linux-uclibc-gcc dsldetails.c -o dsldetails -lpthread
		sorry for the compile warnings, but I'm lazy there.


	The libcms_core? program flushes and remakes the tables on every re/disconnect.
		I wish OpenWrt + ADSL worked on this router !

	iptables -D INPUT -p tcp --dport 30005 -i pppoa0 -j ACCEPT
	iptables -D INPUT -p icmp -i pppoa0 -j ACCEPT
	iptables -D INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT
	iptables -I INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT

*/





#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
//#include <ifaddrs.h>
#include <sys/ioctl.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <mtd/mtd-user.h>	// MEMUNLOCK
#include <signal.h>
//#include <linux/reboot.h>
#include <sys/reboot.h>
#define BRIDGE_MODE_FILE "/etc/bridgemode"	// 0=None, 1=Normal Bridge, 2=Dhcp'd Bridge

//#include <linux/ctype.h>  /* isdigit, isxdigit */





/*
	The following 2 typedefs are copied from the SKY Source at:
	#include "../../../../bcmdrivers/opensource/include/bcm963xx/board.h"
	"bcm_hwdefs.h" - has usefull stuff too
*/

#define BOARD_IOCTL_MAGIC			'B'
#define BOARD_IOCTL_FLASH_WRITE		_IOWR(BOARD_IOCTL_MAGIC, 0, BOARD_IOCTL_PARMS)
#define BOARD_IOCTL_FLASH_READ		_IOWR(BOARD_IOCTL_MAGIC, 1, BOARD_IOCTL_PARMS)
typedef enum 
{
    PERSISTENT,
    NVRAM,
    BCM_IMAGE_CFE,
    BCM_IMAGE_FS,
    BCM_IMAGE_KERNEL,
    BCM_IMAGE_WHOLE,
    SCRATCH_PAD,
    FLASH_SIZE,
    SET_CS_PARAM,
    BACKUP_PSI,
    SYSLOG,
    SERIALISATION,
    SERIALISATION_WP,
    SOFT_UNPROT,
    SOFT_WRITE_PROT,
	SECTOR_SIZE,
	PUBLIC_KEY,
    SKY_SECTOR_SET,
    SKY_AUXFS_SECTOR
} BOARD_IOCTL_ACTION;

typedef struct boardIoctParms
{
	char *string;
	char *buf;
	int strLen;
	int offset;
	BOARD_IOCTL_ACTION action;
	int result;
} BOARD_IOCTL_PARMS;

// xmon.c
#define isxdigit(c)	(('0' <= (c) && (c) <= '9') \
			 || ('a' <= (c) && (c) <= 'f') \
			 || ('A' <= (c) && (c) <= 'F'))
/*
#define _D	0x04	// digit
#define _X	0x40	// hex digit
extern unsigned char _ctype[];
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isxdigit(c)	((__ismask(c)&(_D|_X)) != 0)
*/





int main_sock, newsockfd;	// IP sockets
int keep_going = 1;
int stop_ping = 0;
struct ifreq ifrBR;			// br0 IP

void daemonise();
void error( const char *msg );
void *thread_socket_conn_handler();
void ProcessRequest( char *buff );	// from HTTP
void process_html_dsl();
void process_html_bridge();
void urldecode2( char *dst, const char *src );
void send_HTTP_dsl( const char *user, const char *pass, const char *mac, int flashbckgnd );
void send_HTTP_bridge( int selectoption, const char *webpass,
			const char *pppuser, const char *ppppass, const char *serialnum, int rebooting );
uint32_t* crc32_filltable( uint32_t *crc_table, int endian );

char var[8][65];	// HTML POST parsing
BOARD_IOCTL_PARMS IoctlParms = {0};		// Serialisation Data
int board_dev = 0;	// /dev/brcmboard
int rebootme  = 0;	// also POSTorder



int main(int argc, char *argv[])
{
	
	if (argc == 1)
	{
		printf( "Crude HTTP addon interface for changing the DSL Line Username / Password\n"
				"Usage: %s port [-p]\n", argv[0]);
		exit(1);
	}
	else if (argc == 3)
	{
		if ( !strcmp(argv[2], "-p") )
		{
			stop_ping = 1;
		}
	}
	
	
	
	
	
	daemonise();
	
	
	
	
	
	// Startup a global socket
	if ( (main_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
	{
		error("ERROR opening socket");
	}
	
	
	
	// Get Local IP / Subnet
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0", 6);	// Bridge Interface
	
	
	// When booting, wait for the interface to be created, upto 25 seconds
	int retry_time;
	for (retry_time = 0; retry_time <= 60; retry_time++)
	{
		if (ioctl(main_sock, SIOCGIFADDR, &ifrBR) == -1)
		{
			sleep (1);
		}
		else
		{
			break;
		}
	}
	
	
	
	
	
	
	
	
	struct sockaddr_in serv_addr;
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons( atoi(argv[1]) );
	if (bind(main_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		error("ERROR on binding");
	}
	
	
	
	
	
	// Fork off the HTTP Listen Thread
	//int i, *thread_sock;
	//struct ifreq ifrPPP;
	pthread_t sniffer_thread;
	// thread_sock = malloc(1);
	// *thread_sock = new_socket;
	pthread_create( &sniffer_thread, NULL, thread_socket_conn_handler, NULL );	// (void*) thread_sock );
	
	
	
	
	
	// Check IP Tables
	FILE *ppp_fd;
	while (keep_going)
	{
		ppp_fd = fopen ("/sys/class/net/pppoa0/carrier", "r");
		if (ppp_fd != NULL)	// Connected
		{
			fclose(ppp_fd);
			sleep(1);
			// Keep appling rules, just in case another process changes them
			system("iptables -D INPUT -p tcp --dport 30005 -i pppoa0 -j ACCEPT > /dev/null 2>&1");
			if ( stop_ping == 1 )
			{	// Added because one version of the software did not appear to work
				system("iptables -D INPUT -p icmp -i pppoa0 -j ACCEPT >/dev/null > /dev/null 2>&1");
				system("iptables -D INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT > /dev/null 2>&1");
				system("iptables -I INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT > /dev/null 2>&1");
			}
			sleep (590);
		}
		sleep (10);
	}
	
	
	close(main_sock);
	return 0; 
}



void daemonise()	// Copied from a get-started example
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

    /* Close all open file descriptors 
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
    {
        close (x);
    }
	*/
}



void error( const char *msg )
{
	perror(msg);	// e.g. Shows msg + 'Permission Denied'
	exit(1);
}



void *thread_socket_conn_handler()
{
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	int n;	//, netmask, local_subnet;
	//char buffer[4096];
	char *buffer;
	
	
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0", 6);	// Bridge Interface
	
	if (setsockopt(main_sock, SOL_SOCKET, SO_BINDTODEVICE, "br0", 6) == -1)
	{
		error("ERROR SO_BINDTODEVICE");
	}
	
	
	while (keep_going)
	{
		listen(main_sock, 3);	// Wait/Blocking
		
		/*                              Removed older type security check
		// Check with Local Subnet
		ioctl(main_sock, SIOCGIFNETMASK, &ifrBR);	// br0 NetMask
		netmask = ((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr;
		ioctl(main_sock, SIOCGIFADDR, &ifrBR);	// br0 IP
		local_subnet = (((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr) & netmask;
		*/
		
		clilen = sizeof(cli_addr);
		newsockfd = accept(main_sock, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0)
		{
			error("ERROR on accept");
		}
		
		// Warning - may have problems on EL machines
		//printf("IP: %x,%x,%x\n", local_subnet, cli_addr.sin_addr.s_addr, netmask);
		//if ( local_subnet == (cli_addr.sin_addr.s_addr & netmask) )
		//{
			buffer = (char*) malloc (4096);
			bzero(buffer, 4096);
			n = read(newsockfd, buffer, 4095);
			if (n < 0)
			{
				error("ERROR reading from socket");
			}
			/*
			printf("Message: %s\n", buffer);
			n = write(newsockfd, "Got message", 11);
			if (n < 0)
			{
				error("ERROR writing to socket");
			}
			
			printf("%x,%d\n", cli_addr.sin_addr, clilen);
			*/
			ProcessRequest( buffer );
			free( buffer );
		//}
		
		close( newsockfd );
		if ( rebootme )
		{
			sync();
			sleep(1);
			sync();
			reboot( RB_AUTOBOOT );	// LINUX_REBOOT_CMD_RESTART
		}
		
	}
	
	return 0;
}



void ProcessRequest( char *buff )
{
	if ( (strstr(buff, "POST") == NULL) ||  (strstr(buff, "User-Agent:") == NULL) )	// GET
	{
		return;	// Not Expected Browser Request, strict conditions follow
	}
	
	
	
	char *pos_body;
	
	pos_body = strstr(buff, "\r\n\r\n");
	if (pos_body == NULL)
	{
		pos_body = strstr(buff, "\n\n");
		if (pos_body == NULL)
		{
			return;	// Error
		}
		pos_body -= 2;
	}
	
	
	
	// Quick POST parsing
	//char var[8][65];	// 4 pairs of 64 bytes max
	int i = 4, Vcnt = 0, Pcnt = 0;
	
	while ( (char)*(pos_body+i) != 0 )
	{
		switch ((char)*(pos_body+i))
		{
		case 0x26:	// &
		case 0x3D:	// =
			var[Vcnt][Pcnt] = 0;
			Vcnt++;
			Pcnt = 0;
			break;
			
		default:
			var[Vcnt][Pcnt] = (char)*(pos_body+i);
			Pcnt++;
			if (Pcnt >= 65)
			{
				Pcnt -= 1;
			}
			
		}
		i++;
		
		if (Vcnt == 8)
		{
			break;
		}
	}
	var[Vcnt][Pcnt] = 0;
	
	
	
	/*
	char *X = (char*)malloc(999);
	sprintf(X,"%s,%s,%s,%s,", var[0], var[1], var[2], var[3]);
	write(newsockfd, X, 10);
	strcpy(var[0], "action");
	strcpy(var[1], "test");
	*/
	
	
	
	
	
	// Open IoCtl for the special? commands
	//   I using the proper? way to update it instead of overwriting the MTD,
	//   Because its supposed to update the running memory too.
	//BOARD_IOCTL_PARMS IoctlParms = {0};
	board_dev = 0;
	
	board_dev = open("/dev/brcmboard", 2);  // RDWR=02 WR 01 RD 00
	if (board_dev <= 0)
	{
		error("ERROR opening /dev/brcmboard\n");
	}
	// Read the Data
	IoctlParms.string = (char*) malloc (0x304);
	IoctlParms.strLen = 0x304;
	IoctlParms.offset = 0;
	IoctlParms.action = SERIALISATION;	// NVRAM;
	ioctl(board_dev, BOARD_IOCTL_FLASH_READ, &IoctlParms);
	
	
	
	/*
	// Using the MTD block
	int mtd_dev = 0;
	BOARD_IOCTL_PARMS IoctlParms = {0};
	
	mtd_dev = open("/dev/mtd3", 2);  // RDWR=02 WR 01 RD 00
	if (mtd_dev <= 0)
	{
		error("ERROR opening /dev/mtd3 (NVRAM)\n");
	}
	// Read the Data
	IoctlParms.string = (char*) malloc (0x10000);
	lseek(mtd_dev, 0, SEEK_SET);
	read(mtd_dev, IoctlParms.string, 0x10000);
	*/
	
	
	
	/*
	FILE *fd2 = fopen("/var/SERIALISATION.BIN", "wb");
	fwrite(IoctlParms.string, 1, 0x1000 , fd2 );
	fclose(fd2);
	*/
	
	
	
	
	// Quick Header Parsing, Look for DSL or BRIDGE web page
	int pos_dsl, pos_bridge;
	pos_body   = strstr(buff, "\r\n");	// POST /blaa.html HTTP/1.1
	pos_dsl    = strstr(buff, "/dsl.html");
	pos_bridge = strstr(buff, "/bridge.html");
	if ( (pos_dsl != NULL) && (pos_dsl < pos_body) )
	{
		process_html_dsl();
	}
	else if ( (pos_bridge != NULL) && (pos_bridge < pos_body) )
	{
		process_html_bridge();
	}
	
	
	
	free( IoctlParms.string );
	close( board_dev );
	//close( mtd_dev );
}	



void process_html_dsl()
{
	char *username = (char*) malloc (65);
	char *password = (char*) malloc (65);
	char *macaddr  = (char*) malloc (65);
	uint32_t *crc32_table; // = crc32_filltable(NULL, 1);
	//uint32_t data = (uint32_t) IoctlParms.string;
	uint8_t *data;
	uint32_t crc  = 0xFFFFFFFF;
	uint32_t size = 0x304;
	
	// Check the POST values
	if (!strcmp(var[0], "action")) {
		
		if (!strcmp(var[1], "test"))
		{
			send_HTTP_dsl ( "sky_test_user@skydsl", "test", "7C4CA50019FB", 0 );
		}
		else if (!strcmp(var[1], "getids"))
		{
			send_HTTP_dsl ( &IoctlParms.string[0x80], &IoctlParms.string[0xC0], &IoctlParms.string[0x40], 0 );	// NVRAM = 0x914 & 0x954 & 0x8D4
		}
		else if (!strcmp(var[1], "setids"))
		{
			if ( !strcmp(var[2], "dslusr") && !strcmp(var[4], "dslpwd")  && !strcmp(var[6], "macaddr") )
			{
				//printf("1,%s,%s,%s,\n",var[2],var[4],var[6]);
				//printf("2,%s,%s,%s,\n",var[3],var[5],var[7]);
				urldecode2 ( username, var[3] );
				urldecode2 ( password, var[5] );
				urldecode2 ( macaddr,  var[7] );
				memset ( &IoctlParms.string[0x80], 0, 64 );
				memcpy ( &IoctlParms.string[0x80], username, strlen(username) );
				memset ( &IoctlParms.string[0xC0], 0, 64 );
				memcpy ( &IoctlParms.string[0xC0], password, strlen(password) );
				memset ( &IoctlParms.string[0x40], 0, 64 );
				memcpy ( &IoctlParms.string[0x40], macaddr,  strlen(macaddr) );
				memset ( &IoctlParms.string[0x300], 0, 4 );
				
				crc32_table = crc32_filltable(NULL, 0);
				data = (uint8_t *) IoctlParms.string;
				while (size-- > 0) {
					crc = (crc >> 8) ^ crc32_table[(crc ^ *data++) & 0xff];		// line from cmsCrc_getCrc32
				}
				memcpy (&IoctlParms.string[0x300] , (char*)&crc, 4);
				//printf("CRC1: %x,%x,%x\n", crc, (char)IoctlParms.string[0x300], (uint32_t)IoctlParms.string[0x300]);
				// Write
				//IoctlParms.action = SOFT_UNPROT;
				//ioctl(board_dev, BOARD_IOCTL_FLASH_WRITE, &IoctlParms);	// CFE+NVRAM
				//IoctlParms.action = SERIALISATION;	// NVRAM;
				ioctl(board_dev, BOARD_IOCTL_FLASH_WRITE, &IoctlParms);
				//lseek(mtd_dev, 0, SEEK_SET);
				//ioctl(mtd_dev, MEMUNLOCK, 0);	// hmmm
				//write(mtd_dev, IoctlParms.string, 0x10000);
				usleep(10000);
				send_HTTP_dsl ( username, password, macaddr, 1 );
				free( crc32_table );
			}
		}
		
	}
	
	
	
	free( username );
	free( password );
	free( macaddr );
}



void process_html_bridge()
{
	int selectoption = 0, i;
	char *webpass = (char*) malloc (65);
	char *tmpval1 = (char*) malloc (65);
	char *tmpval2 = (char*) malloc (65);
	
	FILE *bridgefd;
	char *line = NULL;
	size_t  lenf = 0;
	ssize_t read;
	
	
	
	if ( !strcmp(var[0], "bridgemode") && !strcmp(var[2], "brgpass") )
	{
		selectoption = atoi ( var[1] );
		strcpy ( webpass, var[3] );
		rebootme = 1;
	}
	else if ( !strcmp(var[2], "bridgemode") && !strcmp(var[0], "brgpass") )
	{
		selectoption = atoi ( var[3] );
		strcpy ( webpass, var[1] );
		rebootme = 2;
	}
	
	
	
	if ( rebootme )
	{
		bridgefd = fopen (BRIDGE_MODE_FILE, "w");
		fprintf (bridgefd, "%d\n%s\n\n", selectoption, webpass);
		fclose (bridgefd);
		
		
		// Change a few web pages, so they partly appear
		char pages[][21] = {"sky_index", "sky_dynamic_dns", "sky_router_status",
							"sky_st_poe", "sky_wan_setup"};
		for (i = 0; i <= 4; i++)
		{
			sprintf (tmpval1, "/webs/%s.html", pages[i]);
			unlink (tmpval1);
			if ( (selectoption == 0) || (selectoption == 2) )	// None or Fake Mode
			{
				sprintf (tmpval2, "/webs/%s_normalmode.html", pages[i]);
			}
			else	// Normal Bridge Mode
			{
				sprintf (tmpval2, "/webs/%s_bridgemode.html", pages[i]);
			}
			symlink (tmpval2, tmpval1);
		}
		
	}
	
	
	bridgefd = fopen(BRIDGE_MODE_FILE, "r");
	if (bridgefd == NULL)
	{
		// No Conf file
		strcpy (webpass, "sky");
	}
	else
	{
		// Files exists
		read = getline (&line, &lenf, bridgefd);
		selectoption = atoi (line);
		read = getline (&line, &lenf, bridgefd);
		strcpy (webpass, line);

		free (line);
		fclose (bridgefd);
	}
	
	
	/*
		 0x80 = Username
		 0xC0 = Password
		0x1C0 = Serial
	*/
	send_HTTP_bridge( selectoption, webpass, &IoctlParms.string[0x80], &IoctlParms.string[0xC0],
						&IoctlParms.string[0x1C0], rebootme );
	
	free (webpass);
	free (tmpval1);
	free (tmpval2);
}



// This function is made by someone called Saul
void urldecode2( char *dst, const char *src )
{
	char a, b;
	while (*src) {
		if ((*src == '%') &&
			((a = src[1]) && (b = src[2])) &&
			(isxdigit(a) && isxdigit(b))) {
				if (a >= 'a')
						a -= 'a'-'A';
				if (a >= 'A')
						a -= ('A' - 10);
				else
						a -= '0';
				if (b >= 'a')
						b -= 'a'-'A';
				if (b >= 'A')
						b -= ('A' - 10);
				else
						b -= '0';
				*dst++ = 16*a+b;
				src+=3;
		} else {
				*dst++ = *src++;
		}
	}
	*dst++ = '\0';
}



void send_HTTP_dsl( const char *user, const char *pass, const char *mac, int flashbckgnd )
{
	// Firefox Browser complains about cross-site scripting, I chose to ignore it
	
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0:1", 6);				// Moved Bridge Interface
	if (ioctl(main_sock, SIOCGIFADDR, &ifrBR) == -1)	// br0 IP, if in Fake Bridge Mode
	{
		strncpy(ifrBR.ifr_name, "br0", 6);		// Bridge Interface
		ioctl(main_sock, SIOCGIFADDR, &ifrBR);	// br0 IP
	}
	
	char loc_ip[16];	// Apply the IP address without the new port number
	sprintf(loc_ip, "%s", (char*)inet_ntoa(( (struct sockaddr_in *)&ifrBR.ifr_addr )->sin_addr.s_addr) );
	
	
	char *buffer = (char*) malloc (4080);
	strcpy(buffer, "HTTP/1.1 200 Ok\r\nServer: sky_router\r\nContent-Type: text/html\r\n"
		"Connection: close\r\n\r\n<!DOCTYPE html><head>"
		"<style>input{width:195px;}body{font-size:15px;}</style></head>"	// Helps Ubuntu Firefox
		"<body id=\"bdy\" style=\"margin-left:20px;margin-top:20px;height:50px;padding:0;\">"
		"<form id=\"frmdsldets\" method=\"post\" action=\"\" onsubmit=\"return 0;\">"
		"<div class=\"row-holder\"><input type=\"hidden\" name=\"action\" value=\"test\"/>"
		"<label style=\"width:75px;font-size:15px;\">Username:</label>"
		"<input name=\"dslusr\" size=\"30\" maxlength=\"64\" value=\"");
	strcat(buffer, user);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div>"
		"<div class=\"row-holder\">"
		"<label style=\"width:75px;font-size:15px;\">Password: </label>"
		"<input name=\"dslpwd\" size=\"30\" maxlength=\"64\" value=\"");
	strcat(buffer, pass);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div>"
		"<div class=\"row-holder\">"
		"<label style=\"width:75px;font-size:15px;\">Mac Addr:</label>"
		"<input name=\"macaddr\" size=\"30\" maxlength=\"12\" value=\"");
	strcat(buffer, mac);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div></form>\n"
		"<div class=\"buttons-holder\">"
		"<a href=\"javascript: CanIt();\" class=\"btn42 btn-silver png\">"
		"<span class=\"png\">Cancel</span></a> <a href=\"javascript: DoIt();\" class=\"btn42 btn-pink png\">"
		"<span class=\"png\">Apply</span></a></div></body>\r\n"
		"<link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// To use the common CSS layouts
	strcat(buffer, "/assets/css/main.css\"/><link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// For people who change there IP address
	strcat(buffer, "/assets/css/fonts.css\"/><script>\r\n");
	if (flashbckgnd)
	{
		strcat(buffer,	"var col=0;var el=document.getElementById('bdy');var fl=window.setInterval(function(){"
						"el.style.background='rgba(128,255,128,'+Math.abs(Math.sin(col))+')';"
						"col+=0.03;if (col>=3.15){clearInterval(fl);}}, 10);\r\n");
	}
	strcat(buffer, "function DoIt() { var d = document.getElementById('frmdsldets');"
		"if (!(/(^[0-9A-F]{12}$)/i.test(d.macaddr.value))){window.alert('MAC Address must be 12 Hex Characters');return;}"
		"d.action.value=\"setids\";d.submit();}"
		"function CanIt() { var d = document.getElementById('frmdsldets');"
		"d.action.value=\"getids\";d.submit();}"
		"</script></html>");
	
	write( newsockfd, buffer, strlen(buffer) );
	free( buffer );
}



void send_HTTP_bridge( int selectoption, const char *webpass,
	const char *pppuser, const char *ppppass, const char *serialnum, int rebooting )
{
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0:1", 6);				// Moved Bridge Interface
	if (ioctl(main_sock, SIOCGIFADDR, &ifrBR) == -1)	// br0 IP, if in Fake Bridge Mode
	{
		strncpy(ifrBR.ifr_name, "br0", 6);		// Bridge Interface
		ioctl(main_sock, SIOCGIFADDR, &ifrBR);	// br0 IP
	}
	
	char loc_ip[16];	// Apply the IP address without the new port number
	sprintf(loc_ip, "%s", (char*)inet_ntoa(( (struct sockaddr_in *)&ifrBR.ifr_addr )->sin_addr.s_addr) );
	
	
	char *buffer = (char*) malloc (4080);
	strcpy(buffer, "HTTP/1.1 200 Ok\r\nServer: sky_router\r\nContent-Type: text/html\r\n"
		"Connection: close\r\n\r\n<!DOCTYPE html><head>"
		"<style>body{font-size:15px;}</style></head>"
		"<body id=\"bdy2\" style=\"margin-left:20px;margin-top:20px;height:50px;padding:0;\">"
		"<form id=\"frmbridgedets\" method=\"post\" action=\"\" onsubmit=\"return 0;\">"
		"<input type=\"radio\" name=\"bridgemode\" value=\"0\"");
	if ( selectoption == 0 )
	{
		strcat(buffer, " checked");
	}
	strcat(buffer, ">None / Ignore<br>"
		"<div class=\"boxed\" style=\"border-top:1px dotted grey;border-bottom:1px dotted grey;\">"
		"<input type=\"radio\" name=\"bridgemode\" value=\"1\"");
	if ( selectoption == 1 )
	{
		strcat(buffer, " checked");
	}
	strcat(buffer, ">Normal Modem-Only Bridge Mode &nbsp; (PPPoE)<br>"
		"<label style=\"width:75px;margin-left:20px;\">Required Web Interface Password: </label>"
		"<input style=\"width:195px;\" name=\"brgpass\" size=\"30\" maxlength=\"64\" value=\"");
	strcat(buffer, webpass);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/><br>"
		"<label style=\"width:75px;margin-left:20px;\">If you use Sky Broadband,</label><br>"
		"<label style=\"width:75px;margin-left:20px;\"> &nbsp; these options are <u>required</u> "
		"on your connected router:</label><br>"
		"<label style=\"width:75px;margin-left:20px;\"><span title=\"If you need it in Hex, "
		"there maybe a starting byte required\">DHCP Option 61 - Client ID: ");
	strcat(buffer, pppuser);
	strcat(buffer, "|");
	strcat(buffer, ppppass);
	strcat(buffer, "</span></label><br>"
		"<label style=\"width:75px;margin-left:20px;\">DHCP Option 60 - Class &nbsp;ID: 2.1r.3761.R|001|SR102|");
	strcat(buffer, serialnum);
	strcat(buffer, "</label><br>"
		"<label style=\"width:75px;margin-left:20px;\">Half the Sky web pages do not work "
		"in this mode</label><br></div>"
		"<input type=\"radio\" name=\"bridgemode\" value=\"2\"");
	if ( selectoption == 2 )
	{
		strcat(buffer, " checked");
	}
	strcat(buffer, ">Fake Bridge Mode &nbsp; (a single DHCP Client)<br>"
		"<label style=\"width:75px;margin-left:20px;\">Moves the PPPoA IP address to a connected device</label><br>"
		"<br></form>\n"
		"<div class=\"buttons-holder\">"
		"<a href=\"javascript: DoIt();\" class=\"btn42 btn-pink png\">"
		"<span class=\"png\">Apply &amp; Reboot</span></a>");
	if ( rebooting )
	{
		strcat(buffer, " &nbsp; Rebooting, please wait 2 mins");
	}
	strcat(buffer, "</div></body>\r\n"
		"<link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// To use the common CSS layouts
	strcat(buffer, "/assets/css/main.css\"/><link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// For people who change there IP address
	strcat(buffer, "/assets/css/fonts.css\"/><script>\r\n");
#if (0)
	if ( rebooting )
	{
		strcat(buffer,	"var col=0;var el=document.getElementById('bdy2');var fl=window.setInterval(function(){"
						"el.style.background='rgba(128,255,128,'+Math.abs(Math.sin(col))+')';"
						"col+=0.03;if (col>=3.15){clearInterval(fl);}}, 10);\r\n");
	}
#endif
	strcat(buffer, "function DoIt() { var d = document.getElementById('frmbridgedets');"
		"d.action.value=\"setids\";d.submit();}"
		"</script></html>");
	
	write( newsockfd, buffer, strlen(buffer) );
	free( buffer );	
}



// This function copied from Busybox (smaller code, compared to a big static array)
uint32_t* crc32_filltable( uint32_t *crc_table, int endian )	// 1=Big
{
	uint32_t polynomial = endian ? 0x04c11db7 : 0xedb88320;
	uint32_t c;
	int i, j;
	
	if (!crc_table) {
		crc_table = malloc(256 * sizeof(uint32_t));
		// *crc_table = (uint32_t) malloc(256);
	}
	for (i = 0; i < 256; i++) {
		c = endian ? (i << 24) : i;
		for (j = 8; j; j--) {
			if (endian)
				c = (c&0x80000000) ? ((c << 1) ^ polynomial) : (c << 1);
			else
				c = (c&1) ? ((c >> 1) ^ polynomial) : (c >> 1);
		}
		*crc_table++ = c;
	}
	
	return crc_table - 256;
}
