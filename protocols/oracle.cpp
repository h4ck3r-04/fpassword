/*

david: code is based on SNORT spo_database.c

tested with :
-instantclient_10_2 on Oracle 10.2.0
-instantclient-basic-linux.*-11.2.0.3.0.zip +
instantclient-sdk-linux.*-11.2.0.3.0.zip on Oracle 9i and on Oracle 11g

*/

#include "include/fpassword-mod.h"

#ifndef LIBORACLE

void dummy_oracle() { printf("\n"); }

#else

#include <oci.h>
#include <stdbool.h>
#include <sys/types.h>

extern fpassword_option fpassword_options;
extern char *FPASSWORD_EXIT;

OCIEnv *o_environment;
OCISvcCtx *o_servicecontext;
OCIBind *o_bind;
OCIError *o_error;
OCIStmt *o_statement;
OCIDefine *o_define;
text o_errormsg[512];
sb4 o_errorcode;

void print_oracle_error(char *err) {
  if (verbose) {
    OCIErrorGet(o_error, 1, NULL, &o_errorcode, o_errormsg, sizeof(o_errormsg), OCI_HTYPE_ERROR);
    fprintf(stderr, "[ERROR] Oracle_error: %s - %s\n", o_errormsg, err);
  }
}

int32_t start_oracle(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[200], sid[100];

  if (strlen(login = fpassword_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = fpassword_get_next_password()) == 0)
    pass = empty;

  strncpy(sid, miscptr, sizeof(sid) - 1);
  sid[sizeof(sid) - 1] = 0;
  snprintf(buffer, sizeof(buffer), "//%s:%d/%s", fpassword_address2string(ip), port, sid);

  /*

     To use the Easy Connect naming method, PHP must be linked with Oracle 10g
     or greater Client libraries. The Easy Connect string for Oracle 10g is of
     the form: [//]host_name[:port][/service_name]. With Oracle 11g, the syntax
     is: [//]host_name[:port][/service_name][:server_type][/instance_name].
     Service names can be found by running the Oracle utility lsnrctl status on
     the database server machine.

     The tnsnames.ora file can be in the Oracle Net search path, which includes
     $ORACLE_HOME/network/admin and /etc. Alternatively set TNS_ADMIN so that
     $TNS_ADMIN/tnsnames.ora is read. Make sure the web daemon has read access
     to the file.

   */

  if (OCIInitialize(OCI_DEFAULT, NULL, NULL, NULL, NULL)) {
    print_oracle_error("OCIInitialize");
    return 4;
  }
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) {
    print_oracle_error("OCIEnvInit");
    return 4;
  }
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) {
    print_oracle_error("OCIEnvInit 2");
    return 4;
  }
  if (OCIHandleAlloc(o_environment, (dvoid **)&o_error, OCI_HTYPE_ERROR, (size_t)0, NULL)) {
    print_oracle_error("OCIHandleAlloc");
    return 4;
  }

  bool success = true;
  if (OCILogon(o_environment, o_error, &o_servicecontext, (const OraText *)login, strlen(login), (const OraText *)pass, strlen(pass), (const OraText *)buffer, strlen(buffer))) {
    success = false;
    OCIErrorGet(o_error, 1, NULL, &o_errorcode, o_errormsg, sizeof(o_errormsg), OCI_HTYPE_ERROR);
    // database: oracle_error: ORA-01017: invalid username/password; logon
    // denied database: oracle_error: ORA-12514: TNS:listener does not currently
    // know of service requested in connect descriptor database: oracle_error:
    // ORA-28000: the account is locked Failed login attempts is set to 10 by
    // default
    if (verbose) {
      fpassword_report(stderr, "[VERBOSE] database: oracle_error: %s\n", o_errormsg);
    }
    if (strstr((const char *)o_errormsg, "ORA-12514") != NULL) {
      fpassword_report(stderr, "[ERROR] ORACLE SID is not valid, you should try to "
                           "enumerate them.\n");
      fpassword_completed_pair();
      return 3;
    }
    if (strstr((const char *)o_errormsg, "ORA-28000") != NULL) {
      fpassword_report(stderr, "[INFO] ORACLE account %s is locked.\n", login);
      fpassword_completed_pair_skip();
      if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
        return 3;
      return 2;
    }
    // ORA-28002: the password will expire within 7 days
    if (strstr((const char *)o_errormsg, "ORA-28002") != NULL) {
      fpassword_report(stderr, "[INFO] ORACLE account %s password will expire soon.\n", login);
      success = true;
    }
  }

  if (success) {
    OCILogoff(o_servicecontext, o_error);
    fpassword_report_found_host(port, ip, "oracle", fp);
    fpassword_completed_pair_found();
  } else {
    fpassword_completed_pair();
  }
  if (o_error) {
    OCIHandleFree((dvoid *)o_error, OCI_HTYPE_ERROR);
  }
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return 3;
  return success ? 1 : 2;
}

void service_oracle(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_ORACLE;

  fpassword_register_socket(sp);
  if (memcmp(fpassword_get_next_pair(), &FPASSWORD_EXIT, sizeof(FPASSWORD_EXIT)) == 0)
    return;

  if ((miscptr == NULL) || (strlen(miscptr) == 0)) {
    // SID is required as miscptr
    fpassword_report(stderr, "[ERROR] Oracle SID is required, using ORCL as default\n");
    miscptr = "ORCL";
  }

  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);
      if (port != 0)
        myport = port;
      sock = fpassword_connect_tcp(ip, myport);
      port = myport;

      if (sock < 0) {
        if (verbose || debug)
          fpassword_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        fpassword_child_exit(1);
      }
      next_run = 2;
      break;
    case 2:
      next_run = start_oracle(sock, ip, port, options, miscptr, fp);
      if ((next_run == 1 || next_run == 2) && fpassword_options.conwait)
        sleep(fpassword_options.conwait);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = fpassword_disconnect(sock);

      // by default, set in sqlnet.ora, the trace file is generated in pwd to log
      // any errors happening, as we don't care, we are deleting the file set
      // these parameters to not generate the file LOG_DIRECTORY_CLIENT =
      // /dev/null LOG_FILE_CLIENT = /dev/null
      unlink("sqlnet.log");
      fpassword_child_exit(0);
      return;
    default:
      fpassword_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      fpassword_child_exit(2);
    }
    run = next_run;
  }
}

#endif

int32_t service_oracle_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_oracle(const char *service) {
  printf("Module oracle / ora is optionally taking the ORACLE SID, default is "
         "\"ORCL\"\n\n");
}
