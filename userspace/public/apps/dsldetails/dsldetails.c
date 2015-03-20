/*
	
	The initial socket connection code copied from http://www.linuxhowtos.org/C_C++/socket.htm
	The get IP addresses code copied from http://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
	The rest is hand written (mostly) - Matt Goring - Feb 2015
	
	Basicly it opens port 8080 - for the web interface, only allowing local br0 subnet to connect.
	If there is no internet, it checks every 10 seconds,
		after that it checks the IPTABLES every 10 minutes.
	
	
	Make command line:
	/opt/toolchains/uclibc-crosstools-gcc-4.4.2-1/usr/bin/mips-linux-uclibc-gcc dsldetails.c -o dsldetails -lpthread
	
	
	The libcms_core? program flushes and remakes the tables on every re/disconnect.
		I wish OpenWrt worked on this router !
	
	iptables -D INPUT -p tcp --dport 30005 -i pppoa0 -j ACCEPT
	iptables -D INPUT -p icmp -i pppoa0 -j ACCEPT
	iptables -D INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT
	iptables -I INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT
	
	As you are reading this, you may want to add more remove-rules,
	   you will see a few via the 'IPTABLES -L -n -v' command.
	
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
struct ifreq ifrBR;			// br0 IP

void error( const char *msg );
void *thread_socket_conn_handler();
void ProcessRequest( char *buff );	// from HTTP
void urldecode2( char *dst, const char *src );
void SendHTTP( const char *user, const char *pass, const char *mac, int flashbckgnd );
uint32_t* crc32_filltable( uint32_t *crc_table, int endian );



int main(int argc, char *argv[])
{
	struct sockaddr_in serv_addr;
	//int i, *thread_sock;
	//struct ifreq ifrPPP;
	FILE *ppp_fd;
	
	
	if (argc < 2)
	{
		printf( "Crude HTTP interface for changing the DSL Line Username / Password\n"
				"Usage: %s port\n", argv[0]);
		exit(1);
	}
	main_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (main_sock < 0)
	{
		error("ERROR opening socket");
	}
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons( atoi(argv[1]) );
	if (bind(main_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		error("ERROR on binding");
	}
	
	
	// Fork off the Listen Thread
	pthread_t sniffer_thread;
	// thread_sock = malloc(1);
	// *thread_sock = new_socket;
	pthread_create( &sniffer_thread, NULL, thread_socket_conn_handler, NULL );	// (void*) thread_sock );
	
	
	
	// Check IP Tables
	while (keep_going)
	{
		ppp_fd = fopen ("/sys/class/net/pppoa0/carrier", "r");
		if (ppp_fd != NULL)	// Connected
		{
			fclose(ppp_fd);
			sleep(1);
			// Keep appling rules, just in case another process changes them
			system("iptables -D INPUT -p tcp --dport 30005 -i pppoa0 -j ACCEPT > /dev/null 2>&1");
			system("iptables -D INPUT -p icmp -i pppoa0 -j ACCEPT >/dev/null > /dev/null 2>&1");
			system("iptables -D INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT > /dev/null 2>&1");
			system("iptables -I INPUT -p icmp --icmp-type echo-reply -i pppoa0 -j ACCEPT > /dev/null 2>&1");
			sleep (590);
		}
		sleep (10);
	}
	
	
	close(main_sock);
	return 0; 
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
	int n, netmask, local_subnet;
	//char buffer[4096];
	char *buffer;
	
	
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0", 4);	// Bridge Interface
	
	
	while (keep_going)
	{
		listen(main_sock, 3);
		
		// Check with Local Subnet
		ioctl(main_sock, SIOCGIFNETMASK, &ifrBR);	// br0 NetMask
		netmask = ((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr;
		ioctl(main_sock, SIOCGIFADDR, &ifrBR);	// br0 IP
		local_subnet = (((struct sockaddr_in *)&ifrBR.ifr_addr)->sin_addr.s_addr) & netmask;
		
		
		clilen = sizeof(cli_addr);
		newsockfd = accept(main_sock, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0)
		{
			error("ERROR on accept");
		}
		
		// Warning - may have problems on EL machines
		//printf("IP: %x,%x,%x\n", local_subnet, cli_addr.sin_addr.s_addr, netmask);
		if ( local_subnet == (cli_addr.sin_addr.s_addr & netmask) )
		{
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
		}
		
		close( newsockfd );
		//sleep(1);
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
	char var[8][65];	// 4 pairs of 64 bytes max
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
				Pcnt-=1;
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
	BOARD_IOCTL_PARMS IoctlParms = {0};
	int board_dev = 0;
	
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
	FILE *fd2 = fopen("SERIALISATION.BIN", "wb");
	fwrite(IoctlParms.string, 1, 0x1000 , fd2 );
	fclose(fd2);
	*/
	
	
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
			SendHTTP ( "sky_test_user@skydsl", "test", "7C4CA50019FB", 0 );
		}
		else if (!strcmp(var[1], "getids"))
		{
			SendHTTP ( &IoctlParms.string[0x80], &IoctlParms.string[0xC0], &IoctlParms.string[0x40], 0 );	// NVRAM = 0x914 & 0x954 & 0x8D4
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
				SendHTTP ( username, password, macaddr, 1 );
				free( crc32_table );
			}
		}
		
	}
	
	
	free( IoctlParms.string );
	free( username );
	free( password );
	free( macaddr );
	close( board_dev );
	//close( mtd_dev );
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



void SendHTTP( const char *user, const char *pass, const char *mac, int flashbckgnd )
{
	// Firefox Browser complains about cross-site scripting, I dont care
	
	/*		This is already set by the last incoming request
	ifrBR.ifr_addr.sa_family = AF_INET;
	strncpy(ifrBR.ifr_name, "br0", 4);	// Bridge Interface
	ioctl(main_sock, SIOCGIFADDR, &ifrBR);	// br0 IP
	*/
	char loc_ip[16];	// Apply the IP address without the new port number
	sprintf(loc_ip, "%s", (char*)inet_ntoa(( (struct sockaddr_in *)&ifrBR.ifr_addr )->sin_addr.s_addr) );
	
	
	char *buffer = (char*) malloc (4080);
	strcpy(buffer, "HTTP/1.1 200 Ok\r\nServer: sky_router\r\nContent-Type: text/html\r\n"
		"Connection: close\r\n\r\n<!DOCTYPE html><head>"
		"<link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// To use the common CSS layouts
	strcat(buffer, "/assets/css/main.css\"/><link type=\"text/css\" rel=\"stylesheet\" href=\"http://");
	strcat(buffer, loc_ip);								// For people who change there IP address
	strcat(buffer, "/assets/css/fonts.css\"/>\r\n"
		"<style>input{width:195px;}body{font-size:15px;}</style>"	// Helps Ubuntu Firefox
		"</head><body id=\"bdy\" style=\"margin-left:20px;margin-top:20px;height:50px;padding:0;\">"
		"<form id=\"frmdsldets\" method=\"post\" action=\"\" onsubmit=\"return 0;\">"
		"<div class=\"row-holder\"><input type=\"hidden\" name=\"action\" value=\"test\"/>"
		"<label style=\"width:75px\">Username:</label>"
		"<input name=\"dslusr\" size=\"30\" maxlength=\"64\" value=\"");
	strcat(buffer, user);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div>"
		"<div class=\"row-holder\">"
		"<label style=\"width:75px\">Password: </label>"
		"<input name=\"dslpwd\" size=\"30\" maxlength=\"64\" value=\"");
	strcat(buffer, pass);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div>"
		"<div class=\"row-holder\">"
		"<label style=\"width:75px\">Mac Addr:</label>"
		"<input name=\"macaddr\" size=\"30\" maxlength=\"12\" value=\"");
	strcat(buffer, mac);
	strcat(buffer, "\" type=\"text\" autocomplete=\"off\"/>"
		"</div></form>"
		"<div class=\"buttons-holder\">"
		"<a href=\"javascript: CanIt();\" class=\"btn42 btn-silver png\">"
		"<span class=\"png\">Cancel</span></a> <a href=\"javascript: DoIt();\" class=\"btn42 btn-pink png\">"
		"<span class=\"png\">Apply</span></a></div></body><script>\r\n");
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
