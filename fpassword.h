#ifndef _FPASSWORD_H

#include <iostream>
#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX) || defined(__APPLE__)
#include <inttypes.h>
#else
#include <stdint.h>
#endif

#if defined(_INTTYPES_H) || defined(__CLANG_INTTYPES_H)
#define hPRIu64 PRIu64
#else
#define hPRIu64 "lu"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#define HYDRA_SSL
#endif
#ifdef HAVE_SSL
#ifndef HYDRA_SSL
#define HYDRA_SSL
#endif
#endif

#ifdef LIBSSH
#include <libssh/libssh.h>
#endif

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define OPTION_SSL 1

#ifdef LIBOPENSSL
#ifndef NO_RSA_LEGACY
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define NO_RSA_LEGACY
#endif
#endif
#endif



#endif