#ifndef _FPASSWORD_MOD_H
#define _FPASSWORD_MOD_H

#include "fpassword.h"

#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX)
#include <inttypes.h>
#else
#include <stdint.h>
#endif

extern char quiet;

extern void fpassword_child_exit(int32_t code);
extern void fpassword_register_socket(int32_t s);
extern char *fpassword_get_next_pair();
extern char *fpassword_get_next_login();
extern char *fpassword_get_next_password();
extern void fpassword_completed_pair();
extern void fpassword_completed_pair_found();
extern void fpassword_completed_pair_skip();
extern void fpassword_report_found(int32_t port, char *svc, FILE *fp);
extern void fpassword_report_pass_found(int32_t port, char *ip, char *svc, FILE *fp);
extern void fpassword_report_found_host(int32_t port, char *ip, char *svc, FILE *fp);
extern void fpassword_report_found_host_msg(int32_t port, char *ip, char *svc, FILE *fp, char *msg);
extern void fpassword_report_debug(FILE *st, char *format, ...);
extern int32_t fpassword_connect_to_ssl(int32_t socket, char *hostname);
extern int32_t fpassword_connect_ssl(char *host, int32_t port, char *hostname);
extern int32_t fpassword_connect_tcp(char *host, int32_t port);
extern int32_t fpassword_connect_udp(char *host, int32_t port);
extern int32_t fpassword_disconnect(int32_t socket);
extern int32_t fpassword_data_ready(int32_t socket);
extern int32_t fpassword_recv(int32_t socket, char *buf, uint32_t length);
extern int32_t fpassword_recv_nb(int32_t socket, char *buf, uint32_t length);
extern char *fpassword_receive_line(int32_t socket);
extern int32_t fpassword_send(int32_t socket, char *buf, uint32_t size, int32_t options);
extern int32_t make_to_lower(char *buf);
extern unsigned char fpassword_conv64(unsigned char in);
extern void fpassword_tobase64(unsigned char *buf, uint32_t buflen, uint32_t bufsize);
extern void fpassword_dump_asciihex(unsigned char *string, int32_t length);
extern void fpassword_set_srcport(int32_t port);
extern char *fpassword_address2string(char *address);
extern char *fpassword_address2string_beautiful(char *address);
extern char *fpassword_strcasestr(const char *haystack, const char *needle);
extern void fpassword_dump_data(unsigned char *buf, int32_t len, char *text);
extern int32_t fpassword_memsearch(char *haystack, int32_t hlen, char *needle, int32_t nlen);
extern char *fpassword_strrep(char *string, char *oldpiece, char *newpiece);

#ifdef HAVE_PCRE
int32_t fpassword_string_match(char *str, const char *regex);
#endif
char *fpassword_string_replace(const char *string, const char *substr, const char *replacement);

int32_t debug;
int32_t verbose;
int32_t waittime;
int32_t port;
int32_t found;
int32_t proxy_count;
int32_t use_proxy;
int32_t selected_proxy;
char proxy_string_ip[MAX_PROXY_COUNT][36];
int32_t proxy_string_port[MAX_PROXY_COUNT];
char proxy_string_type[MAX_PROXY_COUNT][10];
char *proxy_authentication[MAX_PROXY_COUNT];
char *cmdlinetarget;

#ifndef __APPLE__
typedef int32_t BOOL;
#else /* __APPLE__ */
/* ensure compatibility with objc libraries */
#if (TARGET_OS_IPHONE && __LP64__) || TARGET_OS_WATCH
typedef bool BOOL;
#else
typedef signed char BOOL;
#endif
#endif /* __APPLE__ */

#define fpassword_report fprintf

#endif