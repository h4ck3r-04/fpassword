#
# Makefile for FPASSWORD
#
WARN_CLANG=-Wformat-nonliteral -Wstrncat-size -Wformat-security -Wsign-conversion -Wconversion -Wfloat-conversion -Wshorten-64-to-32 -Wuninitialized -Wmissing-variable-declarations  -Wmissing-declarations
WARN_GCC=-Wformat=2 -Wformat-overflow=2 -Wformat-nonliteral -Wformat-truncation=2 -Wnull-dereference -Wstrict-overflow=2 -Wstringop-overflow=4 -Walloca-larger-than=4096 -Wtype-limits -Wconversion -Wtrampolines -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fno-common -Wcast-align
CFLAGS ?= -g
OPTS=-I. -O3 $(CFLAGS) -fcommon -Wno-deprecated-declarations
CPPFLAGS += -D_GNU_SOURCE
# -Wall -g -pedantic
LIBS=-lm
DESTDIR ?=
BINDIR = /bin
MANDIR = /man/man1/
DATADIR = /etc
PIXDIR = /share/pixmaps
APPDIR = /share/applications

SRC = protocols/vnc.c protocols/pcnfs.c protocols/rexec.c protocols/nntp.c protocols/socks5.c \
      protocols/telnet.c protocols/cisco.c protocols/http.c protocols/ftp.c protocols/imap.c \
      protocols/pop3.c protocols/smb.c protocols/icq.c protocols/cisco-enable.c protocols/ldap.c \
      protocols/memcached.c protocols/mongodb.c protocols/mysql.c protocols/mssql.c protocols/xmpp.c \
      protocols/http-proxy-urlenum.c protocols/snmp.c protocols/cvs.c protocols/smtp.c \
      protocols/smtp-enum.c protocols/sapr3.c protocols/ssh.c protocols/sshkey.c protocols/teamspeak.c \
      protocols/postgres.c protocols/rsh.c protocols/rlogin.c protocols/oracle-listener.c \
      protocols/svn.c protocols/pcanywhere.c protocols/sip.c protocols/oracle.c protocols/vmauthd.c \
      protocols/asterisk.c protocols/firebird.c protocols/afp.c protocols/ncp.c protocols/rdp.c \
      protocols/oracle-sid.c protocols/http-proxy.c protocols/http-form.c protocols/irc.c \
      protocols/s7-300.c protocols/redis.c protocols/adam6500.c protocols/rtsp.c \
      protocols/rpcap.c protocols/radmin2.c protocols/cobaltstrike.c \
      fpassword-time.c crc32.c d3des.c bfg.c ntlm.c sasl.c hmacmd5.c fpassword-mod.c \
      smb2.c
OBJ = protocols/vnc.o protocols/pcnfs.o protocols/rexec.o protocols/nntp.o protocols/socks5.o \
      protocols/telnet.o protocols/cisco.o protocols/http.o protocols/ftp.o protocols/imap.o \
      protocols/pop3.o protocols/smb.o protocols/icq.o protocols/cisco-enable.o protocols/ldap.o \
      protocols/memcached.o protocols/mongodb.o protocols/mysql.o protocols/mssql.o protocols/cobaltstrike.o protocols/xmpp.o \
      protocols/http-proxy-urlenum.o protocols/snmp.o protocols/cvs.o protocols/smtp.o \
      protocols/smtp-enum.o protocols/sapr3.o protocols/ssh.o protocols/sshkey.o protocols/teamspeak.o \
      protocols/postgres.o protocols/rsh.o protocols/rlogin.o protocols/oracle-listener.o \
      protocols/svn.o protocols/pcanywhere.o protocols/sip.o protocols/oracle-sid.o protocols/oracle.o \
      protocols/vmauthd.o protocols/asterisk.o protocols/firebird.o protocols/afp.o \
      protocols/ncp.o protocols/http-proxy.o protocols/http-form.o protocols/irc.o \
      protocols/redis.o protocols/rdp.o protocols/s7-300.c protocols/adam6500.o protocols/rtsp.o \
      protocols/rpcap.o protocols/radmin2.o \
      crc32.o d3des.o bfg.o ntlm.o sasl.o hmacmd5.o fpassword-mod.o fpassword-time.o \
      protocols/smb2.o

OBJ1 = vnc.o pcnfs.o rexec.o nntp.o socks5.o \
      telnet.o cisco.o http.o ftp.o imap.o \
      pop3.o smb.o icq.o cisco-enable.o ldap.o \
      memcached.o mongodb.o mysql.o mssql.o cobaltstrike.o xmpp.o \
      http-proxy-urlenum.o snmp.o cvs.o smtp.o \
      smtp-enum.o sapr3.o ssh.o sshkey.o teamspeak.o \
      postgres.o rsh.o rlogin.o oracle-listener.o \
      svn.o pcanywhere.o sip.o oracle-sid.o oracle.o \
      vmauthd.o asterisk.o firebird.o afp.o \
      ncp.o http-proxy.o http-form.o irc.o \
      redis.o rdp.o s7-300.c adam6500.o rtsp.o \
      rpcap.o radmin2.o \
      crc32.o d3des.o bfg.o ntlm.o sasl.o hmacmd5.o fpassword-mod.o fpassword-time.o \
      smb2.o
BINS = fpassword

EXTRA_DIST = README README.arm README.palm CHANGES TODO INSTALL LICENSE \
             include/fpassword-mod.h include/fpassword.h include/crc32.h include/d3des.h

all:	fpassword
	@echo
	@echo Now type "make install"

fpassword:	fpassword.c $(OBJ)
	$(CC) $(OPTS) $(SEC) $(LIBS) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o fpassword fpassword.c $(OBJ1) $(LIBS) $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)
	@echo

.c.o:
	$(CC) $(OPTS) $(SEC) $(CFLAGS) $(CPPFLAGS) -c $< $(XDEFINES) $(XIPATHS)

strip:	all
	-strip $(BINS)

install:	strip
	-mkdir -p $(DESTDIR)$(PREFIX)$(BINDIR)
	cp -f $(BINS) $(DESTDIR)$(PREFIX)$(BINDIR)
	-mkdir -p $(DESTDIR)$(PREFIX)$(MANDIR)
	-cp -f fpassword.1 $(DESTDIR)$(PREFIX)$(MANDIR)

clean:
	rm -rf fpassword *.o core *.core *.stackdump *~ Makefile.in Makefile dev_rfc fpassword.restore arm/*.ipk arm/ipkg/usr/bin/*
	cp -f Makefile.orig Makefile

uninstall:
	-rm -f $(DESTDIR)$(PREFIX)$(BINDIR)/fpassword
	-rm -f $(DESTDIR)$(PREFIX)$(MANDIR)/fpassword.1