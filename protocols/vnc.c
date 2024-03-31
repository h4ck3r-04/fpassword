
/*
 * Tested against RealVNC P4.6.0 using 3.3 and 4.1 RFB
 * proto with None and VLC auth (david@)
 *
 */

#include "include/d3des.h"
#include "include/fpassword-mod.h"

#define CHALLENGESIZE 16

// for RFB 003.003 & 003.005
#define RFB33 1
// for RFB 3.7 and onwards
#define RFB37 2

int32_t vnc_client_version = RFB33;
int32_t failed_auth = 0;

extern char *FPASSWORD_EXIT;
static char *buf;

/*
 * Encrypt CHALLENGESIZE bytes in memory using a password.
 * Ripped from vncauth.c
 */

void vncEncryptBytes(unsigned char *bytes, char *passwd) {
  unsigned char key[8];
  int32_t i;

  /* key is simply password padded with nulls */
  for (i = 0; i < 8; i++) {
    if (i < strlen(passwd)) {
      key[i] = passwd[i];
    } else {
      key[i] = 0;
    }
  }
  deskey(key, EN0);
  for (i = 0; i < CHALLENGESIZE; i += 8) {
    des(bytes + i, bytes + i);
  }
}

int32_t start_vnc(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *pass;
  unsigned char buf2[CHALLENGESIZE + 4];

  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  recv(s, buf2, CHALLENGESIZE + 4, 0);

  if (vnc_client_version == RFB37) {
    int32_t i;

    // fprintf(stderr,"number of security types supported: %d\n", buf2[0]);
    if (buf2[0] == 0 || buf2[0] > CHALLENGESIZE + 4) {
      fpassword_report(stderr, "[ERROR] VNC server connection failed\n");
      fpassword_child_exit(0);
    }

    for (i = 1; i <= buf2[0]; i++) {
      // fprintf(stderr,"sec type %u\n",buf2[i]);
      // check if weak security types are available
      if (buf2[i] <= 0x2) {
        buf2[3] = buf2[i];
        break;
      }
    }
  }
  // supported security type
  switch (buf2[3]) {
  case 0x0:
    fpassword_report(stderr, "[ERROR] VNC server told us to quit %c\n", buf2[3]);
    fpassword_child_exit(0);
    break;
  case 0x1:
    fpassword_report(fp, "VNC server does not require authentication.\n");
    if (fp != stdout)
      fpassword_report(stdout, "VNC server does not require authentication.\n");
    fpassword_report_found_host(port, ip, "vnc", fp);
    fpassword_completed_pair_found();
    fpassword_child_exit(2);
    break;
  case 0x2:
    // VNC security type supported is the only type supported for now
    if (vnc_client_version == RFB37) {
      sprintf(buf, "%c", 0x2);
      if (fpassword_send(s, buf, strlen(buf), 0) < 0) {
        return 1;
      }
      // get authentication challenge from server
      if (recv(s, buf2, CHALLENGESIZE, 0) == -1)
        return 1;
      // send response
      vncEncryptBytes(buf2, pass);
      if (fpassword_send(s, (char *)buf2, CHALLENGESIZE, 0) < 0) {
        return 1;
      }
    } else {
      // in old proto, challenge is following the security type
      vncEncryptBytes((unsigned char *)buf2 + 4, pass);
      if (fpassword_send(s, (char *)buf2 + 4, CHALLENGESIZE, 0) < 0) {
        return 1;
      }
    }
    break;
  default:
    fpassword_report(stderr, "[ERROR] unknown VNC security type 0x%x\n", buf2[3]);
    fpassword_child_exit(2);
  }

  // check security result value
  recv(s, buf, 4, 0);
  if (buf == NULL)
    return 1;

  switch (buf[3]) {
  case 0x0:
    fpassword_report_found_host(port, ip, "vnc", fp);
    fpassword_completed_pair_found();
    free(buf);
    failed_auth = 0;
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 3;
    return 1;
  case 0x1:
    free(buf);
    if (verbose)
      fpassword_report(stderr, "[VERBOSE] Authentication failed for password %s\n", pass);
    fpassword_completed_pair();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 3;
    return 1;
  default:
    fpassword_report(stderr, "[ERROR] unknown VNC server security result %d\n", buf[3]);
    free(buf);
    return 1;
  }

  return 1; /* never reached */
}

void service_vnc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_VNC, mysslport = PORT_VNC_SSL;

  fpassword_register_socket(sp);
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
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
        fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }
      usleepn(300);
      buf = fpassword_receive_line(sock);

      if (buf == NULL || (strncmp(buf, "RFB", 3) != 0)) { /* check the first line */
        fpassword_report(stderr, "[ERROR] Not a VNC protocol or service shutdown: %s\n", buf);
        fpassword_child_exit(2);
      }
      if (strstr(buf, " security failures") != NULL) { /* check the first line */
        /*
           VNC has a 'blacklisting' scheme that blocks an IP address after five
           unsuccessful connection attempts. The IP address is initially blocked
           for ten seconds, but this doubles for each unsuccessful attempt
           thereafter. A successful connection from an IP address resets the
           blacklist timeout. This is built in to VNC Server and does not rely
           on operating system support.
         */
        failed_auth++;
        fpassword_report(stderr, "VNC server reported too many authentication "
                             "failures, have to wait some seconds ...\n");
        sleep(12 * failed_auth);
        free(buf);
        next_run = 1;
        break;
      }
      if (verbose)
        fpassword_report(stderr, "[VERBOSE] Server banner is %s\n", buf);
      if (((strstr(buf, "RFB 005.000") != NULL) || (strstr(buf, "RFB 004") != NULL) || (strstr(buf, "RFB 003.007") != NULL) || (strstr(buf, "RFB 003.008") != NULL))) {
        // using proto version 003.007 to talk to server 005.xxx and 004.xxx
        // same for 3.7 and 3.8
        vnc_client_version = RFB37;
        free(buf);
        buf = strdup("RFB 003.007\n");
      } else {
        // for RFB 3.3 and fake 3.5
        vnc_client_version = RFB33;
        free(buf);
        buf = strdup("RFB 003.003\n");
      }
      fpassword_send(sock, buf, strlen(buf), 0);
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_vnc(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(0);
      return;
    case 4:
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(2);
      return;
    default:
      fpassword_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_vnc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
