FROM debian:buster-slim

COPY . .

RUN set -x \
  && apt-get update \
  && apt-get -y install \
  #libmysqlclient-dev \
  default-libmysqlclient-dev \
  libgpg-error-dev \
  libmemcached-dev \
  #libgcrypt11-dev \
  libgcrypt-dev \
  #libgcrypt20-dev \
  #libgtk2.0-dev \
  libpcre3-dev \
  #firebird-dev \
  libidn11-dev \
  libssh-dev \
  #libsvn-dev \
  libssl-dev \
  #libpq-dev \
  make \
  curl \
  gcc \
  1>/dev/null \
  # The next line fixes the curl "SSL certificate problem: unable to get local issuer certificate" for linux/arm
  && c_rehash

RUN chmod +x configure \
  && ./configure \
  && make \
  && make install


ENTRYPOINT ["fpassword"]