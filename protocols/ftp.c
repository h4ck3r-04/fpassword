#include "include/fpassword-mod.h"

extern char *FPASSWORD_EXIT;
char *buf;

int32_t start_ftp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[510];

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "USER %.250s\r\n", login);

  if (fpassword_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = fpassword_receive_line(s);
  if (buf == NULL)
    return 1;
  /* special hack to identify 530 user unknown msg. suggested by
   * Jean-Baptiste.BEAUFRETON@turbomeca.fr */
  if (buf[0] == '5' && buf[1] == '3' && buf[2] == '0') {
    if (verbose)
      printf("[INFO] user %s does not exist, skipping\n", login);
    fpassword_completed_pair_skip();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }
  // for servers supporting anon access without password
  if (buf[0] == '2') {
    fpassword_report_found_host(port, ip, "ftp", fp);
    fpassword_completed_pair_found();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }
  if (buf[0] != '3') {
    if (buf) {
      if (verbose || debug)
        fpassword_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
      free(buf);
    }
    return 3;
  }
  free(buf);

  sprintf(buffer, "PASS %.250s\r\n", pass);

  if (fpassword_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = fpassword_receive_line(s);
  if (buf == NULL)
    return 1;
  if (buf[0] == '2') {
    fpassword_report_found_host(port, ip, "ftp", fp);
    fpassword_completed_pair_found();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 4;
    free(buf);
    return 1;
  }

  free(buf);
  fpassword_completed_pair();
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 4;

  return 2;
}

void service_ftp_core(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname, int32_t tls) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_FTP, mysslport = PORT_FTP_SSL;

  fpassword_register_socket(sp);
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    fpassword_child_exit(0);
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      //      usleepn(300);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = fpassword_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = fpassword_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }
      if (sock < 0) {
        if (verbose || debug)
          fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }
      usleepn(250);
      buf = fpassword_receive_line(sock);
      if (buf == NULL || buf[0] != '2') { /* check the first line */
        if (verbose || debug)
          fpassword_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
        fpassword_child_exit(2);
        if (buf != NULL)
          free(buf);
        fpassword_child_exit(2);
      }

      while (buf != NULL && strncmp(buf, "220 ", 4) != 0 && strstr(buf, "\n220 ") == NULL) {
        free(buf);
        buf = fpassword_receive_line(sock);
      }
      free(buf);

      // this mode is manually chosen, so if it fails we giving up
      if (tls) {
        if (fpassword_send(sock, "AUTH TLS\r\n", strlen("AUTH TLS\r\n"), 0) < 0) {
          fpassword_child_exit(2);
        }
        buf = fpassword_receive_line(sock);
        if (buf == NULL) {
          if (verbose || debug)
            fpassword_report(stderr, "[ERROR] Not an FTP protocol or service shutdown: %s\n", buf);
          fpassword_child_exit(2);
        }
        if (buf[0] == '2') {
          if ((fpassword_connect_to_ssl(sock, hostname) == -1) && verbose) {
            fpassword_report(stderr, "[ERROR] Can't use TLS\n");
            fpassword_child_exit(2);
          } else {
            if (verbose)
              fpassword_report(stderr, "[VERBOSE] TLS connection done\n");
          }
        } else {
          fpassword_report(stderr, "[ERROR] TLS negotiation failed %s\n", buf);
          fpassword_child_exit(2);
        }
        free(buf);
      }

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_ftp(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* error exit */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(2);
      break;
    case 4: /* clean exit */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(0);
      break;
    default:
      fpassword_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(2);
    }
    run = next_run;
  }
}

void service_ftp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ftp_core(ip, sp, options, miscptr, fp, port, hostname, 0); }

void service_ftps(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { service_ftp_core(ip, sp, options, miscptr, fp, port, hostname, 1); }

int32_t service_ftp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, fpassword will exit, so print a good error message here

  return 0;
}
