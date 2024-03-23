// This plugin was written by <david dot maciejak at gmail D O T com>
// Tested on mongodb-server 1:3.6.3-0ubuntu1
// MONGODB-CR is been deprecated

#ifdef LIBMONGODB
#include <mongoc.h>
#endif

#include "include/fpassword-mod.h"

#ifndef LIBMONGODB
void dummy_mongodb() { printf("\n"); }
#else

extern int32_t fpassword_data_ready_timed(int32_t socket, long sec, long usec);

extern fpassword_option fpassword_options;
extern char *FPASSWORD_EXIT;
char *buf;

#define DEFAULT_DB "admin"

int is_error_msg(char *msg) {
  if (strstr(msg, "errmsg ")) {
    if (debug)
      fpassword_report(stderr, "[ERROR] %s\n", msg);
    return 1;
  }
  return 0;
}

int require_auth(int32_t sock) {
  unsigned char m_hdr[] = "\x3f\x00\x00\x00"                             // messageLength (63)
                          "\x00\x00\x00\x41"                             // requestID
                          "\xff\xff\xff\xff"                             // responseTo
                          "\xd4\x07\x00\x00"                             // opCode (2004 OP_QUERY)
                          "\x00\x00\x00\x00"                             // flags
                          "\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00" // fullCollectionName
                                                                         // (admin.$cmd)
                          "\x00\x00\x00\x00"                             // numberToSkip (0)
                          "\x01\x00\x00\x00"                             // numberToReturn (1)
                          "\x18\x00\x00\x00\x10\x6c\x69\x73\x74\x44\x61\x74\x61\x62\x61\x73\x65\x73"
                          "\x00\x01\x00\x00\x00\x00"; // query ({"listDatabases"=>1})

  if (fpassword_send(sock, m_hdr, sizeof(m_hdr), 0) > 0) {
    if (fpassword_data_ready_timed(sock, 0, 1000) > 0) {
      buf = fpassword_receive_line(sock);
      return is_error_msg(buf);
    }
  }
  return 2;
}

int32_t start_mongodb(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  char uri[256];
  mongoc_client_t *client;
  mongoc_database_t *database;
  mongoc_collection_t *collection;
  mongoc_cursor_t *cursor;
  bson_t q;
  const bson_t *doc;
  bson_error_t error;
  bool r;

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  mongoc_init();
  mongoc_log_set_handler(NULL, NULL);
  bson_init(&q);

  if (login[0] == '\0' && pass[0] == '\0') {
    snprintf(uri, sizeof(uri), "mongodb://%s:%d/?authSource=%s", fpassword_address2string(ip), port, miscptr);
  } else {
    snprintf(uri, sizeof(uri), "mongodb://%s:%s@%s:%d/?authSource=%s", login, pass, fpassword_address2string(ip), port, miscptr);
  }

  client = mongoc_client_new(uri);
  if (!client) {
    fpassword_completed_pair_skip();
    return 3;
  }

  mongoc_client_set_appname(client, "fpassword");
  collection = mongoc_client_get_collection(client, miscptr, "test");
  cursor = mongoc_collection_find_with_opts(collection, &q, NULL, NULL);
  r = mongoc_cursor_next(cursor, &doc);
  if (!r) {
    r = mongoc_cursor_error(cursor, &error);
    if (r) {
      if (verbose)
        fpassword_report(stderr, "[ERROR] Can not read document: %s\n", error.message);
      mongoc_cursor_destroy(cursor);
      mongoc_collection_destroy(collection);
      mongoc_client_destroy(client);
      mongoc_cleanup();
      fpassword_completed_pair();
      if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0) {
        return 3;
      }
      return 1;
    }
  }

  mongoc_cursor_destroy(cursor);
  mongoc_collection_destroy(collection);
  mongoc_client_destroy(client);
  mongoc_cleanup();

  fpassword_report_found_host(port, ip, "mongodb", fp);
  fpassword_completed_pair_found();
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 3;

  return 2;
}

void service_mongodb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  if (!miscptr) {
    if (verbose)
      fpassword_report(stderr, "[INFO] Using default database \"admin\"\n");
    miscptr = DEFAULT_DB;
  }

  fpassword_register_socket(sp);

  while (1) {
    if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
      return;

    switch (run) {
    case 1:
      next_run = start_mongodb(sock, ip, port, options, miscptr, fp);
      if (next_run == 1 && fpassword_options.conwait)
        sleep(fpassword_options.conwait);
      break;
    case 2:
      fpassword_child_exit(0);
      return;
    default:
      if (!verbose)
        fpassword_report(stderr, "[ERROR] Caught unknown return code, try verbose "
                             "option for more details\n");
      fpassword_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_mongodb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.

  int32_t myport = PORT_MONGODB;
  int32_t sock = -1;

  if (port != 0)
    myport = port;

  if ((options & OPTION_SSL) == 0)
    sock = fpassword_connect_tcp(ip, myport);
  else
    sock = fpassword_connect_ssl(ip, myport, hostname);

  if (sock < 0) {
    if (verbose || debug)
      fpassword_report(stderr, "[ERROR] Can not connect\n");
    return -1;
  }

  if (!require_auth(sock)) {
    fpassword_report_found_host(port, ip, "mongodb", fp);
    fpassword_report(stderr, "[ERROR] Mongodb server does not require any authentication\n");
    if (sock >= 0)
      sock = fpassword_disconnect(sock);
    return -1;
  }
  if (sock >= 0)
    sock = fpassword_disconnect(sock);
  return 0;
}

#endif

void usage_mongodb(const char *service) {
  printf("Module mongodb is optionally taking a database name to attack, "
         "default is \"admin\"\n\n");
}
