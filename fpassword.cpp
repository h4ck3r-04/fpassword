#include <iostream>
#include <getopt.h>

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
char *SERVICES = "adam6500 asterisk afp cisco cisco-enable cobaltstrike cvs firebird ftp[s] "
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
  int32_t active;
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
int32_t prefer_ipv6 = 0, conwait = 0, loop_cnt = 0, fck = 0, options = 0, killed = 0;
int32_t child_head_no = -1, child_socket;
int32_t total_redo_count = 0;

void help(int32_t ext){
  std::cout << "help" << std::endl;
}

int main(int argc, char* argv[]) {
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) help(1);
  if (argc < 2) help(0);

}