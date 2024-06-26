#include "include/fpassword-mod.h"

#ifndef LIBAFP
void dummy_afp() { printf("\n"); }
#else

#define FREE(x)  \
  if (x != NULL) \
  {              \
    free(x);     \
    x = NULL;    \
  }

#include <afpfs-ng/afp.h>
#include <afpfs-ng/libafpclient.h>
#include <stdio.h>

extern char *FPASSWORD_EXIT;

void stdout_fct(void *priv, enum loglevels loglevel, int32_t logtype, const char *message)
{
  // fprintf(stderr, "[ERROR] Caught unknown error %s\n", message);
}

static struct libafpclient afpclient = {
    .unmount_volume = NULL,
    .log_for_client = stdout_fct,
    .forced_ending_hook = NULL,
    .scan_extra_fds = NULL,
    .loop_started = NULL,
};

static int32_t server_subconnect(struct afp_url url)
{
  struct afp_connection_request *conn_req;
  struct afp_server *server = NULL;

  conn_req = malloc(sizeof(struct afp_connection_request));
  //  server = malloc(sizeof(struct afp_server));

  memset(conn_req, 0, sizeof(struct afp_connection_request));

  conn_req->url = url;
  conn_req->url.requested_version = 31;

  // fprintf(stderr, "AFP connection - username: %s password: %s server: %s\n",
  // url.username, url.password, url.servername);

  if (strlen(url.uamname) > 0)
  {
    if ((conn_req->uam_mask = find_uam_by_name(url.uamname)) == 0)
    {
      fprintf(stderr, "[ERROR] Unknown UAM: %s\n", url.uamname);
      FREE(conn_req);
      FREE(server);
      return -1;
    }
  }
  else
  {
    conn_req->uam_mask = default_uams_mask();
  }

  // fprintf(stderr,  "Initiating connection attempt.\n");
  if ((server = afp_server_full_connect(NULL, conn_req)) == NULL)
  {
    FREE(conn_req);
    //    FREE(server);
    return -1;
  }
  // fprintf(stderr,  "Connected to server: %s via UAM: %s\n",
  // server->server_name_printable, uam_bitmap_to_string(server->using_uam));

  FREE(conn_req);
  FREE(server);

  return 0;
}

int32_t start_afp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp)
{
  char *empty = "";
  char *login, *pass, mlogin[AFP_MAX_USERNAME_LEN], mpass[AFP_MAX_PASSWORD_LEN];
  struct afp_url tmpurl;

  /* Build AFP authentication request */
  libafpclient_register(&afpclient);
  afp_main_quick_startup(NULL);
  init_uams();
  afp_default_url(&tmpurl);

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  strncpy(tmpurl.servername, fpassword_address2string(ip), AFP_SERVER_NAME_LEN - 1);
  tmpurl.servername[AFP_SERVER_NAME_LEN] = 0;
  strncpy(mlogin, login, AFP_MAX_USERNAME_LEN - 1);
  mlogin[AFP_MAX_USERNAME_LEN - 1] = 0;
  strncpy(mpass, pass, AFP_MAX_PASSWORD_LEN - 1);
  mpass[AFP_MAX_PASSWORD_LEN - 1] = 0;
  memcpy(&tmpurl.username, mlogin, AFP_MAX_USERNAME_LEN);
  memcpy(&tmpurl.password, mpass, AFP_MAX_PASSWORD_LEN);

  if (server_subconnect(tmpurl) == 0)
  {
    fpassword_report_found_host(port, ip, "afp", fp);
    fpassword_completed_pair_found();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 3;
    return 2;
  }
  else
  {
    fpassword_completed_pair();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 2;
  }
  return 1;
}

void service_afp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname)
{
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_AFP;

  fpassword_register_socket(sp);
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;

  while (1)
  {
    switch (run)
    {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      if ((options & OPTION_SSL) == 0)
      {
        if (port != 0)
          myport = port;
        sock = fpassword_connect_tcp(ip, myport);
        port = myport;
      }
      if (sock < 0)
      {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }

      next_run = 2;
      break;

    case 2:

      /*
       *      Here we start the password cracking process
       */

      next_run = start_afp(sock, ip, port, options, miscptr, fp);
      break;
    case 3:

      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      fpassword_child_exit(0);
      return;

    default:

      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(0);
    }
    run = next_run;
  }
}

#endif

int32_t service_afp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname)
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
