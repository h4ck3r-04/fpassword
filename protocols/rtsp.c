//
//  fpassword-rtsp.c
//  fpassword-rtsp
//
//  Created by Javier Sánchez on 18/04/15.
//
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "include/fpassword-mod.h"
#include "include/sasl.h"
#include <stdio.h>
#include <string.h>

extern char *FPASSWORD_EXIT;
char packet[500];
char packet2[500];

int32_t is_Unauthorized(char *s) {
  if (strcasestr(s, "401 Unauthorized") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int32_t is_NotFound(char *s) {
  if (strcasestr(s, "404 Stream") != NULL || strcasestr(s, "404 Not") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int32_t is_Authorized(char *s) {
  if (strcasestr(s, "200 OK") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int32_t use_Basic_Auth(char *s) {
  if (strcasestr(s, "WWW-Authenticate: Basic") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

int32_t use_Digest_Auth(char *s) {
  if (strcasestr(s, "WWW-Authenticate: Digest") != NULL) {
    return 1;
  } else {
    return 0;
  }
}

void create_core_packet(int32_t control, char *ip, int32_t port) {
  char *target = fpassword_address2string(ip);

  if (control == 0) {
    if (strlen(packet) <= 0) {
      sprintf(packet, "DESCRIBE rtsp://%.260s:%i RTSP/1.0\r\nCSeq: 2\r\n\r\n", target, port);
    }
  } else {
    if (strlen(packet2) <= 0) {
      sprintf(packet2, "DESCRIBE rtsp://%.260s:%i RTSP/1.0\r\nCSeq: 3\r\n", target, port);
    }
  }
}
int32_t start_rtsp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[1030], buffer2[500];
  char *lresp;

  memset(buffer, 0, sizeof(buffer));
  memset(buffer2, 0, sizeof(buffer2));

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  create_core_packet(0, ip, port);

  if (fpassword_send(s, packet, strlen(packet), 0) < 0) {
    return 1;
  }
  lresp = fpassword_receive_line(s);

  if (lresp == NULL) {
    fpassword_report(stderr, "[ERROR] no server reply\n");
    return 1;
  }

  if (is_NotFound(lresp)) {
    free(lresp);
    fpassword_report(stderr, "[INFO] Server does not need credentials\n");
    fpassword_completed_pair_found();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0) {
      return 3;
    }
    return 1;
  } else {
    create_core_packet(1, ip, port);

    if (use_Digest_Auth(lresp) == 1) {
      char aux[500] = "", dbuf[500] = "", *result = NULL;
      char *pbuffer = fpassword_strcasestr(lresp, "WWW-Authenticate: Digest ");

      strncpy(aux, pbuffer + strlen("WWW-Authenticate: Digest "), sizeof(aux));
      aux[sizeof(aux) - 1] = '\0';
      free(lresp);
#ifdef LIBOPENSSL
      result = sasl_digest_md5(dbuf, login, pass, aux, miscptr, "rtsp", fpassword_address2string(ip), port, "");
#else
      fpassword_report(stderr, "[ERROR] Digest auth required but compiled "
                           "without OpenSSL/MD5 support\n");
      return 3;
#endif
      if (result == NULL) {
        fpassword_report(stderr, "[ERROR] digest generation failed\n");
        return 3;
      }
      sprintf(buffer, "%.500sAuthorization: Digest %.500s\r\n\r\n", packet2, dbuf);
      if (debug)
        fpassword_report(stderr, "C:%s\n", buffer);
    } else if (use_Basic_Auth(lresp) == 1) {
      free(lresp);
      sprintf(buffer2, "%.249s:%.249s", login, pass);
      fpassword_tobase64((unsigned char *)buffer2, strlen(buffer2), sizeof(buffer2));
      sprintf(buffer, "%.500sAuthorization: : Basic %.500s\r\n\r\n", packet2, buffer2);
      if (debug)
        fpassword_report(stderr, "C:%s\n", buffer);
    } else {
      fpassword_report(stderr, "[ERROR] unknown authentication protocol\n");
      return 1;
    }

    if (strlen(buffer) == 0) {
      fpassword_report(stderr, "[ERROR] could not identify HTTP authentication used\n");
      return 1;
    }

    if (fpassword_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }

    lresp = NULL;
    lresp = fpassword_receive_line(s);

    if (lresp == NULL) {
      fpassword_report(stderr, "[ERROR] no server reply\n");
      return 1;
    }

    if (is_NotFound(lresp) || is_Authorized(lresp)) {
      free(lresp);
      fpassword_completed_pair_found();

      if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0) {
        return 3;
      }
      return 1;
    }
    free(lresp);
    fpassword_completed_pair();
  }

  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 3;

  // not rechead
  return 2;
}

void service_rtsp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_RTSP /*, mysslport = PORT_RTSP_SSL*/;

  fpassword_register_socket(sp);

  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0) {
        sock = fpassword_disconnect(sock);
      }
      if ((options & OPTION_SSL) == 0) {
        if (port != 0) {
          myport = port;
        }
        sock = fpassword_connect_tcp(ip, myport);
        port = myport;
      }
      if (sock < 0) {
        if (verbose || debug)
          fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_rtsp(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0) {
        sock = fpassword_disconnect(sock);
      }
      fpassword_child_exit(0);
      break;
    default:
      fpassword_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_rtsp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
