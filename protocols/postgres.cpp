/*
 *	PostgresSQL Support - by Diaul (at) devilopers.org
 *
 *
 * 110425 no obvious memleaks found
 */

#include "include/fpassword-mod.h"

#ifndef LIBPOSTGRES
void dummy_postgres() { printf("\n"); }
#else

#include "libpq-fe.h" // Postgres connection functions
#include <stdio.h>

#define DEFAULT_DB "template1"

extern fpassword_option fpassword_options;
extern char *FPASSWORD_EXIT;

int32_t start_postgres(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char database[256];
  char connection_string[1024];
  PGconn *pgconn;

  if (miscptr)
    strncpy(database, miscptr, sizeof(database) - 1);
  else
    strncpy(database, DEFAULT_DB, sizeof(database) - 1);
  database[sizeof(database) - 1] = 0;

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  /*
   *      Building the connection string
   */

  snprintf(connection_string, sizeof(connection_string), "host = '%s' dbname = '%s' user = '%s' password = '%s' ", fpassword_address2string(ip), database, login, pass);

  if (verbose)
    fpassword_report(stderr, "connection string: %s\n", connection_string);

  pgconn = PQconnectdb(connection_string);
  if (PQstatus(pgconn) == CONNECTION_OK) {
    PQfinish(pgconn);
    fpassword_report_found_host(port, ip, "postgres", fp);
    fpassword_completed_pair_found();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 3;
    return 2;
  } else {
    PQfinish(pgconn);
    fpassword_completed_pair();
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return 3;
  }
  return 1;
}

void service_postgres(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_POSTGRES, mysslport = PORT_POSTGRES_SSL;

  fpassword_register_socket(sp);
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      //                              usleepn(275);
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
      next_run = start_postgres(sock, ip, port, options, miscptr, fp);
      if ((next_run == 2 || next_run == 1) && fpassword_options.conwait)
        sleep(fpassword_options.conwait);
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

int32_t service_postgres_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_postgres(const char *service) {
  printf("Module postgres is optionally taking the database to attack, default "
         "is \"template1\"\n\n");
}
