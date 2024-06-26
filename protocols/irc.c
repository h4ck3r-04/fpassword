#include "include/fpassword-mod.h"

/*

RFC 1459: Internet Relay Chat Protocol

*/

extern char *FPASSWORD_EXIT;
char buffer[300] = "";
int32_t myport = PORT_IRC, mysslport = PORT_IRC_SSL;

int32_t start_oper_irc(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp)
{
  char *empty = "";
  char *login, *pass;
  int32_t ret;

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  sprintf(buffer, "OPER %s %s\r\n", login, pass);
  if (fpassword_send(s, buffer, strlen(buffer), 0) < 0)
  {
    return 3;
  }
  ret = fpassword_recv(s, buffer, sizeof(buffer) - 1);
  if (ret >= 0)
    buffer[ret] = 0;
  /* :irc.debian.org 381 koma :You are now an IRC Operator */
  /* :irc.debian.org 464 koma :Invalid password */
  if ((ret > 0) && (strstr(buffer, " 381 ") != NULL))
  {
    fpassword_report_found_host(port, ip, "irc", fp);
    fpassword_completed_pair_found();
  }
  else
  {
    fpassword_completed_pair();
  }

  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 3;
  return 2;
}

int32_t send_nick(int32_t s, char *ip, char *pass)
{
  if (strlen(pass) > 0)
  {
    sprintf(buffer, "PASS %s\r\n", pass);
    if (fpassword_send(s, buffer, strlen(buffer), 0) < 0)
    {
      return -1;
    }
  }
  sprintf(buffer, "CAP LS\r\n");
  if (fpassword_send(s, buffer, strlen(buffer), 0) < 0)
  {
    return -1;
  }
  sprintf(buffer, "NICK fpassword%d\r\nUSER fpassword%d fpassword %s :fpassword\r\n", (int32_t)getpid(), (int32_t)getpid(), fpassword_address2string(ip));
  if (fpassword_send(s, buffer, strlen(buffer), 0) < 0)
  {
    return -1;
  }
  return 0;
}

int32_t irc_server_connect(char *ip, int32_t sock, int32_t port, unsigned char options, char *hostname)
{
  if (sock >= 0)
    sock = fpassword_disconnect(sock);
  //        usleepn(275);
  if ((options & OPTION_SSL) == 0)
  {
    if (port != 0)
      myport = port;
    sock = fpassword_connect_tcp(ip, myport);
    port = myport;
  }
  else
  {
    if (port != 0)
      mysslport = port;
    sock = fpassword_connect_ssl(ip, mysslport, hostname);
    port = mysslport;
  }
  return sock;
}

int32_t start_pass_irc(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *hostname)
{
  char *empty = "";
  char *pass;
  int32_t ret;

  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  s = irc_server_connect(ip, s, port, options, hostname);
  if (s < 0)
  {
    fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
    return 3;
  }

  if (send_nick(s, ip, pass) < 0)
  {
    return 3;
  }

  ret = fpassword_recv(s, buffer, sizeof(buffer) - 1);
  if (ret >= 0)
    buffer[ret] = 0;
#ifdef HAVE_PCRE
  if ((ret > 0) && (!fpassword_string_match(buffer, "ERROR\\s.*password")))
  {
#else
  if ((ret > 0) && (strstr(buffer, "ERROR") == NULL))
  {
#endif
    fpassword_report_pass_found(port, ip, "irc", fp);
    fpassword_completed_pair_found();
    fpassword_report(stderr,
                     "[INFO] Server password '%s' is working, you can pass it as "
                     "argument\nto irc module to then try login/password oper mode\n",
                     pass);
  }
  else
  {
    if (verbose && (miscptr != NULL))
      fpassword_report(stderr,
                       "[VERBOSE] Server is requesting a general password, '%s' "
                       "you entered is not working\n",
                       miscptr);
    fpassword_completed_pair();
  }

  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 3;
  return 4;
}

void service_irc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname)
{
  int32_t run = 1, next_run = 1, sock = -1, ret;
  char *buf;

  fpassword_register_socket(sp);

  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;
  while (1)
  {
    next_run = 0;
    switch (run)
    {
    case 1: /* connect and service init function */

      sock = irc_server_connect(ip, sock, port, options, hostname);
      if (sock < 0)
      {
        fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }

      if (miscptr == NULL)
      {
        miscptr = "";
      }
      if (send_nick(sock, ip, miscptr) < 0)
      {
        fpassword_child_exit(1);
      }

      buffer[0] = 0;
      if ((ret = fpassword_recv(sock, buffer, sizeof(buffer) - 1)) >= 0)
        buffer[ret] = 0;

        /* ERROR :Bad password */
#ifdef HAVE_PCRE
      if ((ret > 0) && (fpassword_string_match(buffer, "ERROR\\s.*password")))
      {
#else
      if ((ret > 0) && (strstr(buffer, "ERROR") != NULL))
      {
#endif
        if (verbose)
          fpassword_report(stderr, "[INFO] Server is requesting a password, will try to find it\n");
        if (sock >= 0)
          sock = fpassword_disconnect(sock);
        next_run = 4;
        break;
      }

      while (fpassword_data_ready(sock))
      {
        buf = fpassword_receive_line(sock);
        free(buf);
      }

      if ((ret > 0) && (strstr(buffer, " 432 ") != NULL))
      {
        /* :irc.debian.org 432 * fpassword_5075 :Erroneous nickname */
        if (verbose)
          fpassword_report(stderr, "[ERROR] Erroneous nickname\n");
        fpassword_child_exit(0);
      }

      if ((ret > 0) && (strstr(buffer, " 433 ") != NULL))
      {
        /* :irc.debian.org 433 * fpassword :Nickname already in use */
        if (verbose)
          fpassword_report(stderr, "[ERROR] Nickname already in use\n");
        fpassword_child_exit(0);
      }

      /* ERROR :Bad password is returned from ngircd when it s waiting for a
       * server password */
      if ((ret > 0) && (strstr(buffer, " 001 ") == NULL))
      {
        /* seems we not successfully connected */
        fpassword_report(stderr,
                         "[ERROR] should not be able to identify server msg, "
                         "please report it\n%s\n",
                         buffer);
        fpassword_child_exit(0);
      }

      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_oper_irc(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(0);
      return;
    case 4:
      next_run = start_pass_irc(sock, ip, port, options, miscptr, fp, hostname);
      break;
    default:
      fpassword_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_irc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname)
{
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

void usage_irc(const char *service)
{
  printf("Module irc is optionally taking the general server password, if the "
         "server is requiring one, and if none is passed the password from "
         "-p/-P will be used\n\n");
}
