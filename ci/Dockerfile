FROM zeek/zeek-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
  netcat-openbsd

WORKDIR /udp-logging
COPY ./scripts ./scripts
COPY ./testing ./testing

RUN cd testing && btest -d -j
