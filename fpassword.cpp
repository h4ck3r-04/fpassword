#include <iostream>
#include "include/fpassword.h"
#include <string.h>

#ifdef LIBNCURSES
#include <curses.h>
#include <term.h>
#endif

void usage_oracle(const char *service);
void usage_oracle_listener(const char *service);
void usage_cvs(const char *service);
void usage_xmpp(const char *service);
void usage_pop3(const char *service);
void usage_rdp(const char *service);
void usage_s7_300(const char *service);
void usage_nntp(const char *service);
void usage_imap(const char *service);
void usage_smtp_enum(const char *service);
void usage_smtp(const char *service);
void usage_svn(const char *service);
void usage_ncp(const char *service);
void usage_firebird(const char *service);
void usage_mysql(const char *service);
void usage_mongodb(const char *service);
void usage_irc(const char *service);
void usage_postgres(const char *service);
void usage_telnet(const char *service);
void usage_sapr3(const char *service);
void usage_sshkey(const char *service);
void usage_cisco_enable(const char *service);
void usage_cisco(const char *service);
void usage_ldap(const char *service);
void usage_smb(const char *service);
void usage_http_form(const char *service);
void usage_http_proxy(const char *service);
void usage_http_proxy_urlenum(const char *service);
void usage_snmp(const char *service);
void usage_http(const char *service);
void usage_smb2(const char *service);

// general services
extern void service_asterisk(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_telnet(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ftp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ftps(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pop3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_vmauthd(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_imap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3_cram_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3_digest_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_adam6500(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cisco(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cisco_enable(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_vnc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_socks5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rexec(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rlogin(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rsh(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_nntp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_head(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_get(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_post(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_get_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_post_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_icq(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pcnfs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_mssql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cobaltstrike(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cvs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_snmp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smtp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smtp_enum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_teamspeak(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pcanywhere(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_proxy(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_xmpp(char *target, char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_irc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_redis(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_proxy_urlenum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_s7_300(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rtsp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rpcap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);

extern int32_t service_adam6500_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cisco_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cisco_enable_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cvs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smtp_enum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_form_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ftp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_icq_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_imap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_irc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ldap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mssql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cobaltstrike_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_nntp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pcanywhere_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pcnfs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pop3_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_proxy_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_asterisk_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_redis_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rexec_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rlogin_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rsh_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smtp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_snmp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_socks5_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_teamspeak_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_telnet_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_proxy_urlenum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_vmauthd_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_vnc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_xmpp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_s7_300_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rtsp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rpcap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);

// additional services
#if defined(LIBSMBCLIENT)
extern int32_t service_smb2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smb2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif

#ifdef HAVE_MATH_H
extern void service_mysql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mysql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBPOSTGRES
extern void service_postgres(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_postgres_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBOPENSSL
extern void service_smb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_oracle_listener(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_listener_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_oracle_sid(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_sid_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_sip(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sip_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBFREERDP
extern void service_rdp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rdp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSAPR3
extern void service_sapr3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sapr3_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBFIREBIRD
extern void service_firebird(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_firebird_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBAFP
extern void service_afp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_afp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBNCP
extern void service_ncp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ncp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSSH
extern void service_ssh(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ssh_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_sshkey(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sshkey_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSVN
extern void service_svn(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_svn_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBORACLE
extern void service_oracle(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef HAVE_GCRYPT
extern void service_radmin2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_radmin2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBMCACHED
extern void service_mcached(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mcached_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBMONGODB
extern void service_mongodb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mongodb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif

// services name
std::string SERVICES = "adam6500 asterisk afp cisco cisco-enable cobaltstrike cvs firebird ftp[s] "
                 "http[s]-{head|get|post} http[s]-{get|post}-form http-proxy "
                 "http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] "
                 "memcached mongodb mssql mysql ncp nntp oracle oracle-listener oracle-sid "
                 "pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap "
                 "rsh rtsp s7-300 sapr3 sip smb smb2 smtp[s] smtp-enum snmp socks5 ssh "
                 "sshkey svn teamspeak telnet[s] vmauthd vnc xmpp";

// basic definitions
#define MAXBUF 520
#define MAXLINESIZE ((MAXBUF / 2) - 4)
#define MAXTASKS 64
#define MAXSERVERS 16
#define MAXFAIL 3
#define MAXENDWAIT 20
#define WAITTIME 32
#define TASKS 16
#define SKIPLOGIN 256
#define USLEEP_LOOP 10
#define MAX_LINES 50000000
#define MAX_BYTES 500000000

#define RESTOREFILE "./fpassword.restore"

// basic description
#define PROGRAM "FPASSWORD"
#define VERSION "v0.0dev"
#define AUTHOR "h4ck3r-04"
#define RESOURCE "https://github.com/h4ck3r-04/fpassword"

extern char *fpassword_strcasestr(const char *haystack, const char *needle);
extern void fpassword_tobase64(unsigned char *buf, int32_t buflen, int32_t bufsize);
extern char *fpassword_string_replace(const char *string, const char *substr, const char *replacement);
extern char *fpassword_address2string(char *address);
extern char *fpassword_address2string_beautiful(char *address);
extern uint32_t colored_output;
extern char quiet;
extern int32_t do_retry;
extern int32_t old_ssl;

void fpassword_kill_head(int32_t head_no, int32_t killit, int32_t fail);

// some enum definitions
typedef enum { HEAD_DISABLED = -1, HEAD_UNUSED = 0, HEAD_ACTIVE = 1 } head_state_t;

typedef enum { TARGET_ACTIVE = 0, TARGET_FINISHED = 1, TARGET_ERROR = 2, TARGET_UNRESOLVED = 3 } target_state_t;

// some struct definitions
typedef struct {
  pid_t pid;
  int32_t sp[2];
  int32_t target_no;
  char *current_login_ptr;
  char *current_pass_ptr;
  char reverse[256];
  head_state_t active;
  int32_t redo;
  time_t last_seen;
} fpassword_head;

typedef struct {
  char *target;
  char ip[36];
  char *login_ptr;
  char *pass_ptr;
  uint64_t login_no;
  uint64_t pass_no;
  uint64_t sent;
  int32_t pass_state;
  int32_t use_count;
  target_state_t done;
  int32_t fail_count;
  int32_t redo_state;
  int32_t redo;
  int32_t ok;
  int32_t failed;
  int32_t skipcnt;
  int32_t port;
  char *redo_login[MAXTASKS * 2 + 2];
  char *redo_pass[MAXTASKS * 2 + 2];
  char *skiplogin[SKIPLOGIN];
  //  char *bfg_ptr[MAXTASKS];
} fpassword_target;

typedef struct {
  int32_t active; // active tasks of fpassword_options.max_use
  int32_t targets;
  int32_t finished;
  int32_t exit;
  uint64_t todo_all;
  uint64_t todo;
  uint64_t sent;
  uint64_t found;
  uint64_t countlogin;
  uint64_t countpass;
  size_t sizelogin;
  size_t sizepass;
  FILE *ofp;
} fpassword_brain;

typedef struct {
  char *name;
  int32_t port;
  int32_t port_ssl;
} fpassword_portlist;

// required external variables
extern char *FPASSWORD_EXIT;
#if !defined(ANDROID) && !defined(__BIONIC__)
extern int32_t errno;
#endif
extern int32_t debug;
extern int32_t verbose;
extern int32_t waittime;
extern int32_t port;
extern int32_t found;
extern int32_t use_proxy;
extern int32_t proxy_count;
extern int32_t selected_proxy;
extern int32_t proxy_string_port[MAX_PROXY_COUNT];
extern char proxy_string_ip[MAX_PROXY_COUNT][36];
extern char proxy_string_type[MAX_PROXY_COUNT][10];
extern char *proxy_authentication[MAX_PROXY_COUNT];
extern char *cmdlinetarget;
extern char *fe80;

// required global variables
char *prg;
size_t size_of_data = -1;
fpassword_head **fpassword_heads = NULL;
fpassword_target **fpassword_targets = NULL;
fpassword_option fpassword_options;
fpassword_brain fpassword_brains;
char *sck = NULL;
int32_t prefer_ipv6 = 0;
int32_t conwait = 0;
int32_t loop_cnt = 0;
int32_t fck = 0;
int32_t options = 0;
int32_t killed = 0;
int32_t child_head_no = -1;
int32_t child_socket;
int32_t total_redo_count = 0;

// moved for restore feature
int32_t process_restore = 0;
int32_t dont_unlink;
char *login_ptr = NULL;
char *pass_ptr = "";
char *csv_ptr = NULL;
char *servers_ptr = NULL;
size_t countservers = 1;
size_t sizeservers = 0;
char empty_login[2] = "";
char unsupported[500] = "";

// required to save stack memory
char snpbuf[MAXBUF];
int32_t snpdone, snp_is_redo, snpbuflen, snpi, snpj, snpdont;

typedef void (*service_t)(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
typedef int32_t (*service_init_t)(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
typedef void (*service_usage_t)(const char *service);

static const struct {
  const char *name;
  service_init_t init;
  service_t exec;
  service_usage_t usage;
} services[]  = {
  {"adam6500", service_adam6500_init, service_adam6500, NULL},
  #ifdef LIBAFP
  {"afp", service_afp_init, service_afp, NULL},
  #endif
  {"asterisk", service_asterisk_init, service_asterisk, NULL},
  {"cisco", service_cisco_init, service_cisco, usage_cisco},
  {"cisco-enable", service_cisco_enable_init, service_cisco_enable, usage_cisco_enable},
  {"cvs", service_cvs_init, service_cvs, usage_cvs},
  #ifdef LIBFIREBIRD
  {"firebird", service_firebird_init, service_firebird, usage_firebird},
  #endif
  {"ftp", service_ftp_init, service_ftp, NULL},
  {"ftps", service_ftp_init, service_ftps, NULL},
  {"http-get", service_http_init, service_http_get, usage_http},
  {"http-get-form", service_http_form_init, service_http_get_form, usage_http_form},
  {"http-head", service_http_init, service_http_head, NULL},
  {"http-form", service_http_form_init, NULL, usage_http_form},
  {"http-post", service_http_init, service_http_post, usage_http},
  {"http-post-form", service_http_form_init, service_http_post_form, usage_http_form},
  {"http-proxy", service_http_proxy_init, service_http_proxy, usage_http_proxy},
  {"http-proxy-urlenum", service_http_proxy_urlenum_init, service_http_proxy_urlenum, usage_http_proxy_urlenum},
  {"icq", service_icq_init, service_icq, NULL},
  {"imap", service_imap_init, service_imap, usage_imap},
  {"irc", service_irc_init, service_irc, usage_irc},
  {"ldap", service_ldap_init, service_ldap2, usage_ldap},
  {"ldap2", service_ldap_init, service_ldap2, usage_ldap},
  {"ldap3", service_ldap_init, service_ldap3, usage_ldap},
  {"ldap3-crammd5", service_ldap_init, service_ldap3_cram_md5, usage_ldap},
  {"ldap3-digestmd5", service_ldap_init, service_ldap3_digest_md5, usage_ldap},
  #ifdef LIBMCACHED
  {"memcached", service_mcached_init, service_mcached, NULL};
  #endif
  {"mssql", service_mssql_init, service_mssql, NULL},
  {"cobaltstrike", service_cobaltstrike_init, service_cobaltstrike, NULL},
  #ifdef LIBMONGODB
  {"mongodb", service_mongodb_init, service_mongodb, usage_mongodb},
  #endif
  #ifdef HAVE_MATH_H
  {"mysql", service_mysql_init, service_mysql, usage_mysql},
  #endif
  #ifdef LIBNCP
  {"ncp", service_ncp_init, service_ncp, usage_ncp},
  #endif
  {"nntp", service_nntp_init, service_nntp, usage_nntp},
  #ifdef LIBORACLE
  {"oracle", service_oracle_init, service_oracle, usage_oracle}
  #endif
  #ifdef LIBOPENSSL
  {"oracle-listener", service_oracle_listener_init, service_oracle_listener, usage_oracle_listener},
  {"oracle-sid", service_oracle_sid_init, service_oracle_sid, NULL},
  #endif
  {"pcanywhere", service_pcanywhere_init, service_pcanywhere, NULL},
  {"pcnfs", service_pcnfs_init, service_pcnfs, NULL},
  {"pop3", service_pop3_init, service_pop3, usage_pop3},
  #ifdef LIBPOSTGRES
  {"postgresql", service_postgres_init, service_postgres, usage_postgres},
  #endif
  {"redis", service_redis_init, service_redis, NULL},
  {"rexec", service_rexec_init, service_rexec, NULL},
  #ifdef LIBFREERDP
  {"rdp", service_rdp_init, service_rdp, usage_rdp},
  #endif
  {"rlogin", service_rlogin_init, service_rlogin, NULL},
  {"rsh", service_rsh_init, service_rsh, NULL},
  {"rtsp", service_rtsp_init, service_rtsp, NULL},
  {"rpcap", service_rpcap_init, service_rpcap, NULL},
  {"s7-300", service_s7_300_init, service_s7_300, usage_s7_300},
  #ifdef LIBSAPR3
  {"sarp3", service_sapr3_init, service_sapr3, usage_sapr3},
  #endif
  #ifdef LIBOPENSSL
  {"sip", service_sip_init, service_sip, NULL},
  {"smbnt", service_smbnt_init, service_smbnt, usage_smb},
  {"smb", service_smb_init, service_smb, usage_smb},
  #endif
  #if defined(LIBSMBCLIENT)
  {"smb2", service_smb2_init, service_smb2, usage_smb2},
  #endif
  {"smtp", service_smtp_init, service_smtp, usage_smtp},
  {"smtp-enum", service_smtp_enum_init, service_smtp_enum, usage_smtp_enum},
  {"snmp", service_snmp_init, service_snmp, usage_snmp},
  {"socks5", service_socks5_init, service_socks5, NULL},
  #ifdef LIBSSH
  {"ssh", NULL, service_ssh, NULL},
  {"sshkey", service_sshkey_init, service_sshkey, usage_sshkey},
  #endif
  #ifdef LIBSVN
  {"svn", service_svn_init, service_svn, usage_svn},
  #endif
  {"teamspeak", service_teamspeak_init, service_teamspeak, NULL},
  {"telnet", service_telnet_init, service_telnet, usage_telnet},
  {"vmauthd", service_vmauthd_init, service_vmauthd, NULL},
  {"vnc", service_vnc_init, service_vnc, NULL},
  #ifdef HAVE_GCRYPT
  {"radmin2", service_radmin2_init, service_radmin2, NULL},
  #endif
  {"xmpp", service_xmpp_init, NULL, usage_xmpp}
};

int32_t check_flag(int32_t value, int32_t flag) {
  return (value & flag) == flag;
}

void help(int32_t ext){
  std::cout << ext << "Syntax: fpassword [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] |"
  "[-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W "
  "TIME] [-f] [-s PORT]"
  #ifdef HAVE_MATH_H
  " [-x MIN:MAX:CHARSET]"
  #endif
  " [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] "
  //"[server service [OPT]]|"
  "[service://server[:PORT][/OPT]]"
  << std::endl;
  std::cout << ext << std::endl << "Options" << std::endl;
  std::cout << ext << "  -R        restore a previous aborted/crashed session" << std::endl
  << "  -I        ignore an existing restore file (don't wait 10 seconds)" << std::endl
  #ifdef LIBOPENSSL
  << "  -S        perform an SSL connect" << std::endl
  #endif
  << "  -s PORT   if the service is on a different default port, define it here" << std::endl;
  std::cout << ext << "  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE" << std::endl
  << "  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE" << std::endl;
  std::cout << ext
  #ifdef HAVE_MATH_H
  << "  -x MIN:MAX:CHARSET  password bruteforce generation, type \"-x -h\" to get help" << std::endl
  << "  -y        disable use of symbols in bruteforce, see above" << std::endl
  << "  -r        use a non-random shuffling method for option -x" << std::endl
  #endif
  << "  -e nsr    try \"n\" null password, \"s\" login as pass and/or \"r\" reversed login" << std::endl
  << "  -u        loop around users, not passwords (effective! implied with -x)" << std::endl;
  std::cout << ext << "  -C FILE   colon separated \"login:pass\" format, instead of -L/-P options" << std::endl
  << "  -M FILE   list of servers to attack, one entry per line, ':' to specify port" << std::endl;
  std::cout << ext << "  -o FILE   write found login/password pairs to FILE instead of stdout" << std::endl
  << "  -b FORMAT specify the format for the -o FILE: text(default), json, jsonv1" << std::endl
  << "  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)" << std::endl;
  std::cout << ext << "  -t TASKS  run TASKS number of connects in parallel per target (default:" << TASKS << ")" << std::endl;
  std::cout << ext <<  "  -T TASKS  run TASKS connects in parallel overall (for -M, default: " << MAXTASKS << ")" << std::endl
  << "  -w / -W TIME  wait time for a response (" << WAITTIME << ") / between connects per thread (" << conwait << ")" << std::endl
  #ifdef MSG_PEEK
  << "  -c TIME   wait time per login attempt over all threads (enforces -t 1)" << std::endl
  #endif
  << "  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also in -M)" << std::endl
  << "  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode " << std::endl
  << "  -O        use old SSL v2 and v3" << std::endl
  << "  -K        do not redo failed attempts (good for -M mass scanning)" << std::endl
  << "  -q        do not print messages about connection errors" << std::endl;
  std::cout << ext << "  -U        service module usage details" << std::endl
  << "  -m OPT    options specific for a module, see -U output for information" << std::endl
  << "  -h        more command line options (COMPLETE HELP)" << std::endl
  << "  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)" << std::endl
  << "  service   the service to crack (see below for supported protocols)" << std::endl
  << "  OPT       some service modules support additional input (-U for module help)" << std::endl;
  std::cout << ext << std::endl << "Supported services: " << SERVICES << std::endl
  << std::endl << PROGRAM << " is a tool to guess/crack valid login/password pairs." << std::endl
  << "Licensed under MIT LICENSE. The newest version is always available at;" << std::endl << RESOURCE << std ::endl
  << "Please don't use in military or secret service organizations, or for illegal" << std::endl
  << "purposes. (This is a wish and non-binding - most such people do not care about" << std::endl
  << "laws and ethics anyway - and tell themselves they are one of the good ones.)" << std::endl;
  if (ext && strlen(unsupported) > 0) {
    if (unsupported[strlen(unsupported) - 1] == ' ')
      unsupported[strlen(unsupported) - 1] = 0;
    std::cout << "These services were not compiled in: " << unsupported << "." << std::endl;
  }
  std::cout << ext << std::endl << "Use FPASSWORD_PROXY_HTTP or FPASSWORD_PROXY environment variables for a proxy setup." << std::endl
  << "E.g. %% export FPASSWORD_PROXY=socks5://l:p@127.0.0.1:9150 (or: socks4:// connect://)" << std::endl
  << "     %% export FPASSWORD_PROXY=connect_and_socks_proxylist.txt  (up to 64 entries)" << std::endl
  << "     %% export FPASSWORD_PROXY_HTTP=http://login:pass@proxy:8080" << std::endl
  << "     %% export FPASSWORD_PROXY_HTTP=proxylist.txt  (up to 64 entries)" << std::endl;
  std::cout << ext << std::endl << "Example" << (ext == 0 ? "" : "s") << ":" << (ext == 0 ? "" : "\n") << " fpassword -l user -P passlist.txt ftp://192.168.0.1" << std::endl;
  std::cout << ext << "  fpassword -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN" << std::endl
  << "  fpassword -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5" << std::endl
  << "  fpassword -l admin -p password ftp://[192.168.0.0/24]/" << std::endl
  << "  fpassword -L logins.txt -P pws.txt -M targets.txt ssh" << std::endl;
  exit(-1);
}

void help_bfg() {
  std::cout << "Fpassword bruteforce password generation option usage:" << std::endl << std::endl;
  // To work
  exit(-1);
}

void module_usage() {
  int32_t i;
  std::cout << std::endl << "Help for module " << fpassword_options.service
   << std::endl << "=================================================" << std::endl;
  if (strncmp(fpassword_options.service, "https-", 6) == 0) memmove(fpassword_options.service + 4, fpassword_options.service + 5, strlen(fpassword_options.service) - 4);
  for (i = 0; 1 < sizeof(services) / sizeof(services[0]); i++) {
    if (strcmp(fpassword_options.service, services[i].name)==0) {
      if (services[i].usage) {
        services[i].usage(fpassword_options.service);
        exit(0);
      }
    }
  }
  std::cout << "The Module" << fpassword_options.service << "does not need or support optional parameters" << std::endl;
  exit(0);
}

#define STR_NULL(s) ((s) == NULL ? "(null)" : (s))

void fpassword_debug(int32_t force, char *string) {
  int32_t active = 0;
  int32_t inactive = 0;
  int32_t i;
  if (!debug && !force) return;
  std::cout << "[DEBUG] Code: " << string << "Time: " << (uint64_t)time(NULL) << std::endl;
  std::cout << std::endl;
  std::cout << std::endl;
  for (i = 0; i < fpassword_brains.targets; i++) {
    fpassword_target *target = fpassword_targets[i];
    std::cout << "[DEBUG] Target: " << i << " - target " << STR_NULL(target->target) << " ip " << fpassword_address2string_beautiful(target->ip)
    << " login_no " << target->login_no << " pass_no " << target->pass_no << " sent " << target->sent << " pass_state " << target->pass_state
    << " redo_state " << target->redo_state << "(" << target->redo << " redos) use_count " << target->use_count << " failed " << target->failed
    << " done " << target->done << " fail_count " << target->fail_count << " login_ptr " << STR_NULL(target->login_ptr) << " pass_ptr " << STR_NULL(target->pass_ptr) << std::endl;
  }
  if (fpassword_heads == NULL) return;
  for (i = 0; i < fpassword_options.max_use; i++) {
    if (fpassword_heads[i]->active >= HEAD_UNUSED) {
      std::cout << "[DEBUG] Task " << i << " - pid " << (int32_t)fpassword_heads[i]->pid << " active " << fpassword_heads[i]->active
      << " redo " << fpassword_heads[i]->redo << " current_login_ptr " << STR_NULL(fpassword_heads[i]->current_login_ptr) << " current_pass_ptr "
      << STR_NULL(fpassword_heads[i]->current_pass_ptr) << std::endl;
      if (fpassword_heads[i]->active == HEAD_UNUSED) inactive++;
      else active++;
    }
  }
  std::cout << "[DEBUG] Tasks " << inactive << " active " << active << std::endl;
}

void bail(char *text) {
  std::cout << stderr << "[ERROR]" << text << std::endl;
  exit(-1);
}

void fpassword_restore_write(int32_t print_msg);

void fpassword_restore_read();

void killed_childs(int32_t signo) {
  int32_t pid;
  int32_t i;
  killed++;
  pid = waitpid(-1, NULL, WNOHANG);
  for (i = 0; i < fpassword_options.max_use; i++) {
    if (pid == fpassword_heads[i]->pid) {
      fpassword_heads[i]->pid = -1;
      fpassword_kill_head(i, 1, 0);
      return;
    }
  }
}

void killed_childs_report(int32_t signo) {
  std::cout << "[ERROR] children crashed: " << child_head_no << std::endl;
  fck = write(child_socket, "E", 1);
  _exit(-1);
}

void kill_children(int32_t signo) {
  int32_t i;
  if (verbose) std::cout << "[ERROR] Received signal: " << signo << ", going fown ..." << std::endl;
  if (process_restore == 1) fpassword_restore_write(1);
  if (fpassword_heads  != NULL) {
    for (i = 0; i < fpassword_options.max_use; i++) { if (fpassword_heads[i] != NULL && fpassword_heads[i]->pid > 0) kill(fpassword_heads[i]->pid, SIGTERM); }
    for (i = 0; i < fpassword_options.max_use; i++) { if (fpassword_heads[i] != NULL && fpassword_heads[i]->pid > 0) kill(fpassword_heads[i]->pid, SIGKILL); }
  }
  exit(0);
}

uint64_t countlines(FILE *fd, int32_t colonmode);

void fill_mem(char *ptr, FILE *fd, int32_t colonmode);

char *fpassword_build_time() {
  static char datetime[24];
  struct tm *the_time;
  time_t epoch;
  time(&epoch);
  the_time = localtime(&epoch);
  strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", the_time);
  return (char *)&datetime;
}

void fpassword_service_init(int32_t target_no);

int32_t fpassword_spawn_head(int32_t head_no, int32_t target_no);

int32_t fpassword_lookup_port(char *service);

void fpassword_kill_head(int32_t head_no, int32_t killit, int32_t fail);

void fpassword_increase_fail_count(int32_t target_no, int32_t head_no);

char *fpassword_reverse_login(int32_t head_no, char *login) {
  int32_t i;
  int32_t j;
  char *start;
  char *pos;
  unsigned char keep;
  if (login == NULL || (j = strlen(login)) < 1) return empty_login;
  if (j > 248) j = 248; // limit to max length of login name
  for (i = 0; i < j; i++) {fpassword_heads[head_no]->reverse[i] = login[j - (i + 1)];}
  fpassword_heads[head_no]->reverse[j] = 0;
  start = fpassword_heads[head_no]->reverse;
  pos = start + j;
  while (start < --pos) {
    switch ((*pos & 0xF0) >> 4) {
      case 0xF:
        keep = *pos;
        *pos = *(pos - 3);
        *(pos - 3) = keep;
        keep = *(pos - 1);
        *(pos - 1) = *(pos - 2);
        *(pos - 2) = keep;
        pos -= 3;
        break;
      case 0xE:
        keep = *pos;
        *pos = *(pos - 2);
        *(pos - 2) = keep;
        pos -= 2;
        break;
      case 0xc:
      case 0xD:
        keep = *pos;
        *pos = *(pos - 1);
        *(pos - 1) = keep;
        pos--;
        break;
    }
  }
  return fpassword_heads[head_no]->reverse;
}

int32_t fpassword_send_next_pair(int32_t target_no, int32_t head_no);

void fpassword_skip_user(int32_t target_no, char *username);

int32_t fpassword_check_for_exit_condition() {
  int32_t i;
  int32_t k = 0;
  if (fpassword_brains.exit) {
    if (debug) std::cout << "[DEBUG] exit was forced" << std::endl;
    return -1;
  }
  if (fpassword_brains.targets <= fpassword_brains.finished && fpassword_brains.active < 1) {
    if (debug) std::cout << "[DEBUG] all targets done and all heads finished" << std::endl;
    return 1;
  }
  if (fpassword_brains.active < 1) {
    for (i = 0; i < fpassword_options.max_use && k == 0; i++) { if (fpassword_heads[i]->active >= HEAD_UNUSED) k = 1; }
    if (k == 0) {
      std::cout << stderr << "[ERROR] all children were disabled due too many connection errors" << std::endl;
      return -1;
    }
  }
  return 0;
}

int32_t fpassword_select_target() {
  int32_t target_no = -1;
  int32_t i;
  int32_t j = -1000;
  for (i = 0; i < fpassword_brains.targets; i++) {
    if (fpassword_targets[i]->use_count < fpassword_options.tasks && fpassword_targets[i]-> done == TARGET_ACTIVE)
      if (j < fpassword_options.tasks - fpassword_targets[i]->failed - fpassword_targets[i]->use_count) {
        target_no = i;
        j = fpassword_options.tasks - fpassword_targets[i]->failed - fpassword_targets[i]->use_count;
      }
  }
  return target_no;
}

void process_proxy_line(int32_t type, char *string);

int main(int argc, char* argv[]) {
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) help(1);
  if (argc < 2) help(0);

}

