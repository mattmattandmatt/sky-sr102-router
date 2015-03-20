/* vi: set sw=4 ts=4: */
/*
 * Mini syslogd implementation for busybox
 *
 * Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2001 by Gennady Feldman <gfeldman@gena01.com>
 *
 * Maintainer: Gennady Feldman <gfeldman@gena01.com> as of Mar 12, 2001
 *
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 */

/*
 * Done in syslogd_and_logger.c:
#include "libbb.h"
#define SYSLOG_NAMES
#define SYSLOG_NAMES_CONST
#include <syslog.h>
*/

#include <sys/un.h>
#include <sys/uio.h>

#if ENABLE_FEATURE_REMOTE_LOG
#include <netinet/in.h>
#endif

#if ENABLE_FEATURE_IPC_SYSLOG
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#endif

// brcm begin
#include <sky_routermodel_util.h>
#include "cms_util.h"
#include "cms_msg.h"
// brcm end

// send IETF compliant syslog output to remote server
#define IETF_SYSLOG_OUTPUT_FORMAT_SUPPORT 1

#define DEBUG 0
#ifdef SYSLOG_WLLDIAG
char *macAddr=NULL;
static void getMac();
#endif
/* MARK code is not very useful, is bloat, and broken:
 * can deadlock if alarmed to make MARK while writing to IPC buffer
 * (semaphores are down but do_mark routine tries to down them again) */
#undef SYSLOGD_MARK

/* Write locking does not seem to be useful either */
#undef SYSLOGD_WRLOCK

// brcm begin
/* All the access to /dev/log will be redirected to /var/log/log
 *  * which is TMPFS, memory file system.
 **/
#define BRCM_PATH_LOG "/var/log/log"
// brcm end
enum {
	MAX_READ = CONFIG_FEATURE_SYSLOGD_READ_BUFFER_SIZE,
	DNS_WAIT_SEC = 2 * 60,
};

/* Semaphore operation structures */
struct shbuf_ds {
	int32_t size;   /* size of data - 1 */
	int32_t tail;   /* end of message list */
	char data[1];   /* data/messages */
};

#if ENABLE_FEATURE_REMOTE_LOG
typedef struct {
	int remoteFD;
	unsigned last_dns_resolve;
	len_and_sockaddr *remoteAddr;
	const char *remoteHostname;
} remoteHost_t;
#endif

/* Allows us to have smaller initializer. Ugly. */
#define GLOBALS \
	const char *logFilePath;                \
	int logFD;                              \
	/* interval between marks in seconds */ \
	/*int markInterval;*/                   \
	/* level of messages to be logged */    \
	int logLevel;                           \
	int remotelogLevel;                     \
IF_FEATURE_ROTATE_LOGFILE( \
	/* max size of file before rotation */  \
	unsigned logFileSize;                   \
	/* number of rotated message files */   \
	unsigned logFileRotate;                 \
	unsigned curFileSize;                   \
	smallint isRegular;                     \
) \
IF_FEATURE_IPC_SYSLOG( \
	int shmid; /* ipc shared memory id */   \
	int s_semid; /* ipc semaphore id */     \
	int shm_size;                           \
	struct sembuf SMwup[1];                 \
	struct sembuf SMwdn[3];                 \
)

struct FactoryInfo {
	char sn[32];
	char mac[20];	
} g_skyFactoryInfo;

struct init_globals {
	GLOBALS
};

struct globals {
	GLOBALS

#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *remoteHosts;
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	struct shbuf_ds *shbuf;
#endif
	time_t last_log_time;
	/* localhost's name. We print only first 64 chars */
	char *hostname;

	/* We recv into recvbuf... */
	char recvbuf[MAX_READ * (1 + ENABLE_FEATURE_SYSLOGD_DUP)];
	/* ...then copy to parsebuf, escaping control chars */
	/* (can grow x2 max) */
	char parsebuf[MAX_READ*2];
	/* ...then sprintf into printbuf, adding timestamp (15 chars),
	 * host (64), fac.prio (20) to the message */
	/* (growth by: 15 + 64 + 20 + delims = ~110) */
	char printbuf[MAX_READ*2 + 128];
};

static const struct init_globals init_data = {
	.logFilePath = "/var/log/messages",
	.logFD = -1,
#ifdef SYSLOGD_MARK
	.markInterval = 60 * 60, // brcm
#endif
	.logLevel = -1,
	.remotelogLevel = -1, // brcm
#if ENABLE_FEATURE_ROTATE_LOGFILE
	.logFileSize = 50 * 1024,
	.logFileRotate = 1,
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	.shmid = -1,
	.s_semid = -1,
	.shm_size = ((CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE)*1024), // default shm size
	.SMwup = { {1, -1, IPC_NOWAIT} },
	.SMwdn = { {0, 0}, {1, 0}, {1, +1} },
#endif
};

#define G (*ptr_to_globals)
#define INIT_G() do { \
	SET_PTR_TO_GLOBALS(memcpy(xzalloc(sizeof(G)), &init_data, sizeof(init_data))); \
} while (0)


/* Options */
enum {
	OPTBIT_mark = 0, // -m
	OPTBIT_nofork, // -n
	OPTBIT_outfile, // -O
	OPTBIT_loglevel, // -l
	OPTBIT_remoteloglevel, // -r  // brcm
	OPTBIT_small, // -S
	IF_FEATURE_ROTATE_LOGFILE(OPTBIT_filesize   ,)	// -s
	IF_FEATURE_ROTATE_LOGFILE(OPTBIT_rotatecnt  ,)	// -b
	IF_FEATURE_REMOTE_LOG(    OPTBIT_remotelog  ,)	// -R
	IF_FEATURE_REMOTE_LOG(    OPTBIT_locallog   ,)	// -L
	IF_FEATURE_IPC_SYSLOG(    OPTBIT_circularlog,)	// -C
	IF_FEATURE_SYSLOGD_DUP(   OPTBIT_dup        ,)	// -D

	OPT_mark        = 1 << OPTBIT_mark    ,
	OPT_nofork      = 1 << OPTBIT_nofork  ,
	OPT_outfile     = 1 << OPTBIT_outfile ,
	OPT_loglevel    = 1 << OPTBIT_loglevel,
	OPT_remoteloglevel    = 1 << OPTBIT_remoteloglevel, // brcm
	OPT_small       = 1 << OPTBIT_small   ,
	OPT_filesize    = IF_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_filesize   )) + 0,
	OPT_rotatecnt   = IF_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_rotatecnt  )) + 0,
	OPT_remotelog   = IF_FEATURE_REMOTE_LOG(    (1 << OPTBIT_remotelog  )) + 0,
	OPT_locallog    = IF_FEATURE_REMOTE_LOG(    (1 << OPTBIT_locallog   )) + 0,
	OPT_circularlog = IF_FEATURE_IPC_SYSLOG(    (1 << OPTBIT_circularlog)) + 0,
	OPT_dup         = IF_FEATURE_SYSLOGD_DUP(   (1 << OPTBIT_dup        )) + 0,
};
#define OPTION_STR "m:nO:l:r:S" \
	IF_FEATURE_ROTATE_LOGFILE("s:" ) \
	IF_FEATURE_ROTATE_LOGFILE("b:" ) \
	IF_FEATURE_REMOTE_LOG(    "R:" ) \
	IF_FEATURE_REMOTE_LOG(    "L"  ) \
	IF_FEATURE_IPC_SYSLOG(    "C::") \
	IF_FEATURE_SYSLOGD_DUP(   "D"  )
#define OPTION_DECL *opt_m, *opt_l, *opt_r \
	IF_FEATURE_ROTATE_LOGFILE(,*opt_s) \
	IF_FEATURE_ROTATE_LOGFILE(,*opt_b) \
	IF_FEATURE_IPC_SYSLOG(    ,*opt_C = NULL)
#define OPTION_PARAM &opt_m, &G.logFilePath, &opt_l , &opt_r\
	IF_FEATURE_ROTATE_LOGFILE(,&opt_s) \
	IF_FEATURE_ROTATE_LOGFILE(,&opt_b) \
	IF_FEATURE_REMOTE_LOG(	  ,&remoteAddrList) \
	IF_FEATURE_IPC_SYSLOG(    ,&opt_C)


/* circular buffer variables/structures */
#if ENABLE_FEATURE_IPC_SYSLOG

#if CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE < 4
#error Sorry, you must set the syslogd buffer size to at least 4KB.
#error Please check CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE
#endif

/* our shared key (syslogd.c and logread.c must be in sync) */
enum { KEY_ID = 0x414e4547 }; /* "GENA" */

static void ipcsyslog_cleanup(void)
{
	if (G.shmid != -1) {
		shmdt(G.shbuf);
	}
	if (G.shmid != -1) {
		shmctl(G.shmid, IPC_RMID, NULL);
	}
	if (G.s_semid != -1) {
		semctl(G.s_semid, 0, IPC_RMID, 0);
	}
}


static void sky_getFactoryInfo() {
	FILE *fh = NULL;
	char buff[64] = {0x00};

	char *tok = NULL;


	memset(&g_skyFactoryInfo, 0x00, sizeof(struct FactoryInfo));

	if (NULL == (fh = fopen(SKY_ROUTER_MODEL_EXTENDED_FILENAME, "r"))) {
		fprintf(stderr, "Unable to get factory information\n");
		return;
	}
	
	fread(buff, 1, sizeof(buff), fh);

	if ((tok = strtok(buff, " "))) {
		strncpy(g_skyFactoryInfo.mac, tok, sizeof(g_skyFactoryInfo.mac));		
	}
	else {
		fclose(fh);
		return;
	}

	if ((tok = strtok(NULL, " "))) {
		strncpy(g_skyFactoryInfo.sn, tok, sizeof(g_skyFactoryInfo.sn));
	}
	
	fclose(fh);
}


static void ipcsyslog_init(void)
{
	if (DEBUG)
		printf("shmget(%x, %d,...)\n", (int)KEY_ID, G.shm_size);

	G.shmid = shmget(KEY_ID, G.shm_size, IPC_CREAT | 0644);
	if (G.shmid == -1) {
		bb_perror_msg_and_die("shmget");
	}

	G.shbuf = shmat(G.shmid, NULL, 0);
	if (G.shbuf == (void*) -1L) { /* shmat has bizarre error return */
		bb_perror_msg_and_die("shmat");
	}

	memset(G.shbuf, 0, G.shm_size);
	G.shbuf->size = G.shm_size - offsetof(struct shbuf_ds, data) - 1;
	/*G.shbuf->tail = 0;*/

	// we'll trust the OS to set initial semval to 0 (let's hope)
	G.s_semid = semget(KEY_ID, 2, IPC_CREAT | IPC_EXCL | 1023);
	if (G.s_semid == -1) {
		if (errno == EEXIST) {
			G.s_semid = semget(KEY_ID, 2, 0);
			if (G.s_semid != -1)
				return;
		}
		bb_perror_msg_and_die("semget");
	}
}

/* Write message to shared mem buffer */
static void log_to_shmem(const char *msg, int len)
{
	int old_tail, new_tail;

	if (semop(G.s_semid, G.SMwdn, 3) == -1) {
		bb_perror_msg_and_die("SMwdn");
	}

	/* Circular Buffer Algorithm:
	 * --------------------------
	 * tail == position where to store next syslog message.
	 * tail's max value is (shbuf->size - 1)
	 * Last byte of buffer is never used and remains NUL.
	 */
	len++; /* length with NUL included */
 again:
	old_tail = G.shbuf->tail;
	new_tail = old_tail + len;
	if (new_tail < G.shbuf->size) {
		/* store message, set new tail */
		memcpy(G.shbuf->data + old_tail, msg, len);
		G.shbuf->tail = new_tail;
	} else {
		/* k == available buffer space ahead of old tail */
		int k = G.shbuf->size - old_tail;
		/* copy what fits to the end of buffer, and repeat */
		memcpy(G.shbuf->data + old_tail, msg, k);
		msg += k;
		len -= k;
		G.shbuf->tail = 0;
		goto again;
	}
	if (semop(G.s_semid, G.SMwup, 1) == -1) {
		bb_perror_msg_and_die("SMwup");
	}
	if (DEBUG)
		printf("tail:%d\n", G.shbuf->tail);
}
#else
void ipcsyslog_cleanup(void);
void ipcsyslog_init(void);
void log_to_shmem(const char *msg);
#endif /* FEATURE_IPC_SYSLOG */


/* Print a message to the log file. */
static void log_locally(time_t now, char *msg)
{
#ifdef SYSLOGD_WRLOCK
	struct flock fl;
#endif
	int len = strlen(msg);

#if ENABLE_FEATURE_IPC_SYSLOG
	if ((option_mask32 & OPT_circularlog) && G.shbuf) {
		log_to_shmem(msg, len);
		return;
	}
#endif
	if (G.logFD >= 0) {
		/* Reopen log file every second. This allows admin
		 * to delete the file and not worry about restarting us.
		 * This costs almost nothing since it happens
		 * _at most_ once a second.
		 */
		if (!now)
			now = time(NULL);
		if (G.last_log_time != now) {
			G.last_log_time = now;
			close(G.logFD);
			goto reopen;
		}
	} else {
 reopen:
		G.logFD = open(G.logFilePath, O_WRONLY | O_CREAT
					| O_NOCTTY | O_APPEND | O_NONBLOCK,
					0666);
		if (G.logFD < 0) {
			/* cannot open logfile? - print to /dev/console then */
			int fd = device_open(DEV_CONSOLE, O_WRONLY | O_NOCTTY | O_NONBLOCK);
			if (fd < 0)
				fd = 2; /* then stderr, dammit */
			full_write(fd, msg, len);
			if (fd != 2)
				close(fd);
			return;
		}
#if ENABLE_FEATURE_ROTATE_LOGFILE
		{
			struct stat statf;
			G.isRegular = (fstat(G.logFD, &statf) == 0 && S_ISREG(statf.st_mode));
			/* bug (mostly harmless): can wrap around if file > 4gb */
			G.curFileSize = statf.st_size;
		}
#endif
	}

#ifdef SYSLOGD_WRLOCK
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_type = F_WRLCK;
	fcntl(G.logFD, F_SETLKW, &fl);
#endif

#if ENABLE_FEATURE_ROTATE_LOGFILE
	if (G.logFileSize && G.isRegular && G.curFileSize > G.logFileSize) {
		if (G.logFileRotate) { /* always 0..99 */
			int i = strlen(G.logFilePath) + 3 + 1;
			char oldFile[i];
			char newFile[i];
			i = G.logFileRotate - 1;
			/* rename: f.8 -> f.9; f.7 -> f.8; ... */
			while (1) {
				sprintf(newFile, "%s.%d", G.logFilePath, i);
				if (i == 0) break;
				sprintf(oldFile, "%s.%d", G.logFilePath, --i);
				/* ignore errors - file might be missing */
				rename(oldFile, newFile);
			}
			/* newFile == "f.0" now */
			rename(G.logFilePath, newFile);
#ifdef SYSLOGD_WRLOCK
			fl.l_type = F_UNLCK;
			fcntl(G.logFD, F_SETLKW, &fl);
#endif
			close(G.logFD);
			goto reopen;
		}
		ftruncate(G.logFD, 0);
	}
	G.curFileSize +=
#endif
			full_write(G.logFD, msg, len);
#ifdef SYSLOGD_WRLOCK
	fl.l_type = F_UNLCK;
	fcntl(G.logFD, F_SETLKW, &fl);
#endif
}

static int parse_fac_prio_20(int pri, char *res20)
{
	const CODE *c_pri, *c_fac;
// brcm begin
	int localLog=1;
	int remoteLog=1;
// brcm end

	if (pri != 0) {
		c_fac = facilitynames;
		while (c_fac->c_name) {
			if (c_fac->c_val != (LOG_FAC(pri) << 3)) {
				c_fac++;
				continue;
			}
			/* facility is found, look for prio */
			c_pri = prioritynames;
// brcm begin
			if (c_pri->c_val > G.logLevel)
			    localLog = 0;
			if (c_pri->c_val > G.remotelogLevel)
			    remoteLog = 0;
// brcm end
			while (c_pri->c_name) {
				if (c_pri->c_val != LOG_PRI(pri)) {
					c_pri++;
					continue;
				}
				snprintf(res20, 20, "%s.%s",
						c_fac->c_name, c_pri->c_name);
// brcm begin
				if (!localLog && !remoteLog)
				    return 1;
				else
				    return 0;
// brcm end
			}
			/* prio not found, bail out */
			break;
		}
		snprintf(res20, 20, "<%d>", pri);
	}
// brcm begin
	if (!localLog && !remoteLog)
	    return 1;
	else
	    return 0;
// brcm end
}

/* len parameter is used only for "is there a timestamp?" check.
 * NB: some callers cheat and supply len==0 when they know
 * that there is no timestamp, short-circuiting the test. */
static void timestamp_and_log(int pri, const char *msg, int len)
{
	char *timestamp;
	time_t now;

	/* Jan 18 00:11:22 msg... */
	/* 01234567890123456 */
	if (len < 16 || msg[3] != ' ' || msg[6] != ' '
	 || msg[9] != ':' || msg[12] != ':' || msg[15] != ' '
	) {
		time(&now);
		timestamp = ctime(&now) + 4; /* skip day of week */
	} else {
		now = 0;
		timestamp = msg;
		msg += 16;
	}
	timestamp[15] = '\0';

	if (option_mask32 & OPT_small)
		sprintf(G.printbuf, "%s %s\n", timestamp, msg);
	else {
		char res[20];
		int length; // brcm
		if( parse_fac_prio_20(pri, res) )
		    return;
		length = (strlen(timestamp)+strlen(G.hostname)+strlen(res)+strlen(msg)+9);
		sprintf(G.printbuf, "%s %.64s %s %s %3i\n", timestamp, G.hostname, res, msg, length); // brcm
	}

	/* Log message locally (to file or shared mem) */
	log_locally(now, G.printbuf);
}

#ifdef SYSLOGD_MARK
static void timestamp_and_log_internal(const char *msg)
{
	/* -L, or no -R */
	if (ENABLE_FEATURE_REMOTE_LOG && !(option_mask32 & OPT_locallog))
		return;
	timestamp_and_log(LOG_SYSLOG | LOG_INFO, (char*)msg, 0);
}
#endif

/* tmpbuf[len] is a NUL byte (set by caller), but there can be other,
 * embedded NULs. Split messages on each of these NULs, parse prio,
 * escape control chars and log each locally. */
static void split_escape_and_log(char *tmpbuf, int len)
{
	char *p = tmpbuf;

	tmpbuf += len;
	while (p < tmpbuf) {
		char c;
		char *q = G.parsebuf;
		int pri = (LOG_USER | LOG_NOTICE);

		if (*p == '<') {
			/* Parse the magic priority number */
			pri = bb_strtou(p + 1, &p, 10);
			if (*p == '>')
				p++;
			if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
				pri = (LOG_USER | LOG_NOTICE);
		}

		while ((c = *p++)) {
			if (c == '\n')
				c = ' ';
			if (!(c & ~0x1f) && c != '\t') {
				*q++ = '^';
				c += '@'; /* ^@, ^A, ^B... */
			}
			*q++ = c;
		}
		*q = '\0';

		/* Now log it */
		if (LOG_PRI(pri) < G.logLevel)
			timestamp_and_log(pri, G.parsebuf, q - G.parsebuf);
	}
}

#ifdef SYSLOGD_MARK
static void do_mark(int sig)
{
	if (G.markInterval) {
		timestamp_and_log_internal("-- MARK --");
		alarm(G.markInterval);
	}
}
#endif

// SKY changes
static void reset_syslogbuf(int sig)
{
	if(DEBUG)
		printf("clearing syslog buffers G.shbuf = 0x%x G.shm_size = %d G.shbuf->size = %d G.shbuf->tail = %d G.shbuf->data = 0x%x\n", G.shbuf, G.shm_size, G.shbuf->size, G.shbuf->tail, G.shbuf->data);
	memset(G.shbuf->data, 0, G.shbuf->size);
	G.shbuf->tail = 0;
	
	if(DEBUG)
		printf("after clearing syslog buffers G.shbuf->tail = %d\n", G.shbuf->tail);

	timestamp_and_log(LOG_SYSLOG | LOG_EMERG, "BCM96345 started: BusyBox v" BB_VER, 0);
}
/* Don't inline: prevent struct sockaddr_un to take up space on stack
 * permanently */
static NOINLINE int create_socket(void)
{
	struct sockaddr_un sunx;
	int sock_fd;
	char *dev_log_name;

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;

	/* Unlink old /dev/log or object it points to. */
	/* (if it exists, bind will fail) */
	strcpy(sunx.sun_path, BRCM_PATH_LOG); // brcm
	dev_log_name = xmalloc_follow_symlinks(BRCM_PATH_LOG); // brcm
	if (dev_log_name) {
		safe_strncpy(sunx.sun_path, dev_log_name, sizeof(sunx.sun_path));
		free(dev_log_name);
	}
	unlink(sunx.sun_path);

	sock_fd = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	xbind(sock_fd, (struct sockaddr *) &sunx, sizeof(sunx));
	chmod(BRCM_PATH_LOG, 0666); // brcm

	return sock_fd;
}

#if ENABLE_FEATURE_REMOTE_LOG
static int try_to_resolve_remote(remoteHost_t *rh)
{
	if (!rh->remoteAddr) {
		unsigned now = monotonic_sec();

		/* Don't resolve name too often - DNS timeouts can be big */
		if ((now - rh->last_dns_resolve) < DNS_WAIT_SEC)
			return -1;
		rh->last_dns_resolve = now;
		rh->remoteAddr = host2sockaddr(rh->remoteHostname, 514);
		if (!rh->remoteAddr)
			return -1;
	}
	return socket(rh->remoteAddr->u.sa.sa_family, SOCK_DGRAM, 0);
}
#endif

static void do_syslogd(void) NORETURN;
static void do_syslogd(void)
{
	int sock_fd;
#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *item;
#endif
#if ENABLE_FEATURE_SYSLOGD_DUP
	int last_sz = -1;
	char *last_buf;
#ifdef SYSLOG_WLLDIAG
     int len=0;
	char macrecvbuf[MAX_READ];
#endif
	char *recvbuf = G.recvbuf;
#else
#define recvbuf (G.recvbuf)
#endif

	/* Set up signal handlers (so that they interrupt read()) */
	signal_no_SA_RESTART_empty_mask(SIGTERM, record_signo);
	signal_no_SA_RESTART_empty_mask(SIGINT, record_signo);
	//signal_no_SA_RESTART_empty_mask(SIGQUIT, record_signo);
	signal(SIGHUP, SIG_IGN);
	signal(SIGUSR1, reset_syslogbuf); // SKY
// brcm begin
#ifdef BRCM_CMS_BUILD
	/* In CMS, daemons should ignore SIGINT */
	signal(SIGINT, SIG_IGN);
#endif
// brcm end
#ifdef SYSLOGD_MARK
	signal(SIGALRM, do_mark);
	alarm(G.markInterval);
#endif
	sock_fd = create_socket();

	if (ENABLE_FEATURE_IPC_SYSLOG && (option_mask32 & OPT_circularlog)) {
		ipcsyslog_init();
	}

	// timestamp_and_log_internal("syslogd started: BusyBox v" BB_VER);
	timestamp_and_log(LOG_SYSLOG | LOG_EMERG, "BCM96345 started: BusyBox v" BB_VER, 0);

	while (!bb_got_signal) {
		ssize_t sz;

#if ENABLE_FEATURE_SYSLOGD_DUP
		last_buf = recvbuf;
		if (recvbuf == G.recvbuf)
			recvbuf = G.recvbuf + MAX_READ;
		else
			recvbuf = G.recvbuf;
#endif

#ifdef SYSLOG_WLLDIAG
       len=sprintf(macrecvbuf,"<%s>",macAddr);
#endif

 read_again:
		sz = read(sock_fd, recvbuf, MAX_READ - 1);
		if (sz < 0) {
			if (!bb_got_signal)
				bb_perror_msg("read from %s", BRCM_PATH_LOG); // brcm
			break;
		}

		/* Drop trailing '\n' and NULs (typically there is one NUL) */
		while (1) {
			if (sz == 0)
				goto read_again;
			/* man 3 syslog says: "A trailing newline is added when needed".
			 * However, neither glibc nor uclibc do this:
			 * syslog(prio, "test")   sends "test\0" to /dev/log,
			 * syslog(prio, "test\n") sends "test\n\0".
			 * IOW: newline is passed verbatim!
			 * I take it to mean that it's syslogd's job
			 * to make those look identical in the log files. */
			if (recvbuf[sz-1] != '\0' && recvbuf[sz-1] != '\n')
				break;
			sz--;
		}
#if ENABLE_FEATURE_SYSLOGD_DUP
		if ((option_mask32 & OPT_dup) && (sz == last_sz))
			if (memcmp(last_buf, recvbuf, sz) == 0)
				continue;
		last_sz = sz;
#endif
#if ENABLE_FEATURE_REMOTE_LOG
		/* Stock syslogd sends it '\n'-terminated
		 * over network, mimic that */
		recvbuf[sz] = '\n';

		/* We are not modifying log messages in any way before send */
		/* Remote site cannot trust _us_ anyway and need to do validation again */
		for (item = G.remoteHosts; item != NULL; item = item->link) {
			remoteHost_t *rh = (remoteHost_t *)item->data;

			if (rh->remoteFD == -1) {
				rh->remoteFD = try_to_resolve_remote(rh);
				if (rh->remoteFD == -1)
					continue;
			}

      #ifdef SYSLOG_WLLDIAG
          strncat(macrecvbuf,recvbuf,MAX_READ-len-1);
	#endif
			
   
			/* Send message to remote logger, ignore possible error */
			/* TODO: on some errors, close and set G.remoteFD to -1
			 * so that DNS resolution and connect is retried? */
		#ifdef SYSLOG_WLLDIAG	 
           sendto(rh->remoteFD, macrecvbuf, sz+len+1, MSG_DONTWAIT,
				&(rh->remoteAddr->u.sa), rh->remoteAddr->len);
        #else

#ifdef IETF_SYSLOG_OUTPUT_FORMAT_SUPPORT
		   
		   // precautions
		   if (strlen(g_skyFactoryInfo.mac) < 6 || strlen(g_skyFactoryInfo.sn) < 4) {
			   // fallback if factory information seems incomplete
			   sendto(rh->remoteFD, recvbuf, sz+1, MSG_DONTWAIT,
					   &(rh->remoteAddr->u.sa), rh->remoteAddr->len);
		   }
		   else if (sz) {			   
			   unsigned char i = 0;
			   unsigned int len = 0;

			   char buff[1024] = {0};
			   char recv_dupl[1024];
			   char *remainder = recv_dupl;
			   char *tokens[7] = {0x00};
			   char *nl_pos = NULL;
			   
			   time_t raw_timestamp;
			   struct tm *timestamp = NULL;

			   // copy data
			   memset(recv_dupl, 0x00, sizeof(recv_dupl));
			   strncpy(recv_dupl, recvbuf, sizeof(recv_dupl));

			   // unfortunately timestamp from the original message is not usable 
			   // and must be probed again
			   time(&raw_timestamp);
			   timestamp = localtime(&raw_timestamp);

			   // the reason behind all this parsing is to remove the timestamp which has invalid format
			   // and extract information about the invoking source
			   tokens[i] = strtok(recvbuf, " :<>");
			   while ((tokens[i] != NULL)) {
				   i++;
				   if (i<7)
					   tokens[i] = strtok(NULL, " :<>");
				   else
					   break;
			   }			   

			   if ((!timestamp)) {
				   // fallback to the raw method in case of memory problem
				   sendto(rh->remoteFD, recvbuf, sz+1, MSG_DONTWAIT,
						   &(rh->remoteAddr->u.sa), rh->remoteAddr->len);
				   continue;
			   }

			   // move remainder pointer to the message itself if processing before was successful
			   if (i>=7) {
				   // dirty method, must suffice though due to lack of better one
				   unsigned int displ = ((tokens[6] - recvbuf) + strlen(tokens[6]) + 1);
				   remainder = displ <= strlen(recv_dupl) ? (recv_dupl + displ) : remainder;
			   }

			   // clear the buffer
			   memset(buff, 0x00, sizeof(buff));

			   // remove everything after newline - it seems that recvbuf does contain some junk from previous invocations
			   nl_pos = strchr(remainder,'\n');
			   if (nl_pos) {
				   *nl_pos = '\0';
			   }

			   // format the IETF string
			   len = snprintf(buff, sizeof(buff), "<%s>1 %04d-%02d-%02dT%02d:%02d:%02d.000Z skyhub.ihr %s - - "
					   "[skySDID@32666 mac=\"%s\" sn=\"%s\"] %s\n\0", 
					   tokens[0] == NULL ? "3" : tokens[0], // safety precaution + default syslog source set to 3 -> system daemons
					   timestamp->tm_year + 1900,
					   timestamp->tm_mon + 1,
					   timestamp->tm_mday,
					   timestamp->tm_hour,
					   timestamp->tm_min,
					   timestamp->tm_sec,					   
					   tokens[6] == NULL ? "syslog" : tokens[6], // should contain a daemon name if not fallback to syslog
					   g_skyFactoryInfo.mac,
					   g_skyFactoryInfo.sn,
					   remainder);

			   // send to remote server
			   sendto(rh->remoteFD, buff, len, MSG_DONTWAIT, &(rh->remoteAddr->u.sa), rh->remoteAddr->len);

			   /**
				* SR-1099 
				*
				* restore old format for local logging and IPC syslog. since some of the daemons rely on old message format
				* and have major problems dealing with new input
				*
				*/
			   strncpy(recvbuf, recv_dupl, strlen(recv_dupl));
		   }
		   else 
#endif
		   {
			   sendto(rh->remoteFD, recvbuf, sz+1, MSG_DONTWAIT,
					   &(rh->remoteAddr->u.sa), rh->remoteAddr->len);
		   } 
		#endif	  
		}
#endif
		if (!ENABLE_FEATURE_REMOTE_LOG || (option_mask32 & OPT_locallog)) {
			recvbuf[sz] = '\0'; /* ensure it *is* NUL terminated */
			split_escape_and_log(recvbuf, sz);
		}
	} /* while (!bb_got_signal) */

	// timestamp_and_log_internal("syslogd exiting"); // brcm
	timestamp_and_log(LOG_SYSLOG | LOG_EMERG, "syslogd exiting", 0);
	puts("syslogd exiting");
	if (ENABLE_FEATURE_IPC_SYSLOG)
		ipcsyslog_cleanup();
        close(sock_fd);
	kill_myself_with_sig(bb_got_signal);
#undef recvbuf
}

int syslogd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int syslogd_main(int argc UNUSED_PARAM, char **argv)
{
	int opts;
	char OPTION_DECL;
#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *remoteAddrList = NULL;
#endif

#ifdef BRCM_CMS_BUILD
    cmsLog_init(EID_SYSLOGD);
    cmsLog_setLevel(DEFAULT_LOG_LEVEL);
#endif

	INIT_G();
#ifdef SYSLOG_WLLDIAG
//getMac();
#endif
	sky_getFactoryInfo();

	/* No non-option params, -R can occur multiple times */
	opt_complementary = "=0" IF_FEATURE_REMOTE_LOG(":R::");
	opts = getopt32(argv, OPTION_STR, OPTION_PARAM);
#if ENABLE_FEATURE_REMOTE_LOG
	if (opts & OPT_remoteloglevel){ // -r  // brcm
		G.remotelogLevel = xatou_range(opt_r, 0, 7);
		if (G.remotelogLevel < LOG_EMERG)
		     G.remotelogLevel = LOG_ERR;
	}
	while (remoteAddrList) {
		remoteHost_t *rh = xzalloc(sizeof(*rh));
		rh->remoteHostname = llist_pop(&remoteAddrList);
		rh->remoteFD = -1;
		rh->last_dns_resolve = monotonic_sec() - DNS_WAIT_SEC - 1;
		llist_add_to(&G.remoteHosts, rh);
	}
#endif

#ifdef SYSLOGD_MARK
	if (opts & OPT_mark) // -m
		G.markInterval = xatou_range(opt_m, 0, INT_MAX/60) * 60;
#endif
	//if (opts & OPT_nofork) // -n
	//if (opts & OPT_outfile) // -O
	if (opts & OPT_loglevel) { // -l
		G.logLevel = xatou_range(opt_l, 0, 7); // brcm
		if (G.logLevel < LOG_EMERG)
		    G.logLevel = LOG_DEBUG;
	}
	//if (opts & OPT_small) // -S
#if ENABLE_FEATURE_ROTATE_LOGFILE
	if (opts & OPT_filesize) // -s
		G.logFileSize = xatou_range(opt_s, 0, INT_MAX/1024) * 1024;
	if (opts & OPT_rotatecnt) // -b
		G.logFileRotate = xatou_range(opt_b, 0, 99);
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	if (opt_C) // -Cn
		G.shm_size = xatoul_range(opt_C, 4, INT_MAX/1024) * 1024;
#endif

	/* If they have not specified remote logging, then log locally */
	if (ENABLE_FEATURE_REMOTE_LOG && !(opts & OPT_remotelog)) // -R
		option_mask32 |= OPT_locallog;

	/* Store away localhost's name before the fork */
	G.hostname = safe_gethostname();
	*strchrnul(G.hostname, '.') = '\0';

	if (!(opts & OPT_nofork)) {
		bb_daemonize_or_rexec(DAEMON_CHDIR_ROOT, argv);
	}

#ifdef BRCM_CMS_BUILD
    if (setsid() == -1)
    {
       cmsLog_error("Could not detach from terminal");
    }
    else
    {
       cmsLog_debug("detached from terminal");
    }
    /* set signal masks */
    signal(SIGPIPE, SIG_IGN); /* Ignore SIGPIPE signals */
#endif

	//umask(0); - why??
	write_pidfile("/var/syslogd.pid"); 
	do_syslogd();
	/* return EXIT_SUCCESS; */
}

/* Clean up. Needed because we are included from syslogd_and_logger.c */
#undef DEBUG
#undef SYSLOGD_MARK
#undef SYSLOGD_WRLOCK
#undef G
#undef GLOBALS
#undef INIT_G
#undef OPTION_STR
#undef OPTION_DECL
#undef OPTION_PARAM
