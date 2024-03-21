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

void help(int32_t ext){
  std::cout << "help" << std::endl;
}

int main(int argc, char* argv[]) {
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) help(1);
  if (argc < 2) help(0);

}