# zeekjs-udp-logging

## About

A UDP logging package to quickly integrate Syslog or other UDP-based log receiver
systems with [Zeek](https://github.com/zeek/zeek). The package leverages Zeek's
[JavaScript support](https://docs.zeek.org/en/master/scripting/javascript.html)
and the [Log::log_stream_policy](https://docs.zeek.org/en/master/scripts/base/frameworks/logging/main.zeek.html#id-Log::log_stream_policy)
hook for tapping into the logging framework.

## Installation

    $ zkg install zeekjs-udp-logging

## Quick Start

To send all logs produced by Zeek when listening in standalone mode on `interface`
to `127.0.0.1:9514` using the `cisco-sna-syslog` format, run:

    $ zeek -i <interface> zeekjs-udp-logging

## Configuration

The script currently respects the UDP_LOGGING_HOST and UDP_LOGGING_PORT variables
for configuring the UDP server's address:

    $ export UDP_LOGGING_HOST=192.168.0.1
    $ export UDP_LOGGING_PORT=9514
    $ zeek -i <interface> zeekjs-udp-logging

To use IPV6, set UDP_LOGGING_TYPE to ``udp6``.

## Supported Formats

The format for log record serialization can be selected by setting the
`UDP_LOGGING_FORMAT` environment variable.

### Cisco SNA Syslog (default)

```
UDP_LOGGING_FORMAT=cisco-sna-syslog
```

By default, the script sends UDP packets using the RFC 5424 format where
the message is the JSON encoded payload of the log record prefixed with
`zeek_filename="<prefix>conn.log"`. The prefix defaults to `/var/zeek/logs/current/`,
but can be configured by setting the environment variable `UDP_LOGGING_ZEEK_FILENAME_PREFIX`.

    <158>1 2025-12-30T17:17:50.184000+00:00 zeek Zeek - - - zeek_filename="/var/zeek/logs/current/files.log" {"ts":1767115070.136616,"fuid":"FshbmjO7BSRyzRFR9","uid":"CIgGHgNopOHHQgCO1","id.orig_h":"141.142.228.5","id.orig_p":59856,"id.resp_h":"192.150.187.43","id.resp_p":80,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.04547309875488281,"local_orig":false,"is_orig":false,"seen_bytes":4705,"total_bytes":4705,"missing_bytes":0,"overflow_bytes":0,"timedout":false}

    <158>1 2025-12-30T17:17:50.185000+00:00 zeek Zeek - - - zeek_filename="/var/zeek/logs/current/http.log" {"ts":1767115070.106275,"uid":"CIgGHgNopOHHQgCO1","id.orig_h":"141.142.228.5","id.orig_p":59856,"id.resp_h":"192.150.187.43","id.resp_p":80,"trans_depth":1,"method":"GET","host":"bro.org","uri":"/download/CHANGES.bro-aux.txt","version":"1.1","user_agent":"Wget/1.14 (darwin12.2.0)","request_body_len":0,"response_body_len":4705,"status_code":200,"status_msg":"OK","tags":[],"resp_fuids":["FshbmjO7BSRyzRFR9"],"resp_mime_types":["text/plain"]}
    <158>1 2025-12-30T17:17:55.243000+00:00 zeek Zeek - - - zeek_filename="/var/zeek/logs/current/conn.log" {"ts":1767115070.060597,"uid":"CIgGHgNopOHHQgCO1","id.orig_h":"141.142.228.5","id.orig_p":59856,"id.resp_h":"192.150.187.43","id.resp_p":80,"proto":"tcp","service":"http","duration":0.18209600448608398,"orig_bytes":136,"resp_bytes":5007,"conn_state":"SF","local_orig":false,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":7,"orig_ip_bytes":512,"resp_pkts":7,"resp_ip_bytes":5379,"ip_proto":6}


This format should be compatible with [Cisco's SNA](https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/zeek/7_5_2_Zeek_Configuration_Guide_DV_1_0.pdf) system.


### Tagged RFC5424

```
UDP_LOGGING_FORMAT=tagged-rfc5424
```

This format uses the Structured Data field of RFC 5424 format to set ``zeek_filename``
as Structured Data element. It isn't compatible with Cisco SNA, it's here as
that was the first attempt to produce a compatible format.

    <85>1 2025-11-18T09:28:46.634Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="http.log"] {"ts":1763458126.600419,"uid":"CRudTvORUWvlRqRz5","id.orig_h":"192.168.0.109","id.orig_p":45538,"id.resp_h":"192.0.78.212","id.resp_p":80,"trans_depth":1,"method":"GET","host":"zeek.org","uri":"/","version":"1.1","user_agent":"curl/8.5.0","request_body_len":0,"response_body_len":162,"status_code":301,"status_msg":"Moved Permanently","tags":[],"resp_fuids":["FmQGaAZRt93axdHi6"],"resp_mime_types":["text/html"]}
    <85>1 2025-11-18T09:28:46.710Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="conn.log"] {"ts":1763458065.435613,"uid":"CEvhV93jXZEA5UPcKh","id.orig_h":"192.168.0.109","id.orig_p":49549,"id.resp_h":"192.168.0.1","id.resp_p":1900,"proto":"udp","duration":1.2656450271606445,"orig_bytes":94,"resp_bytes":7278,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"Dd","orig_pkts":1,"orig_ip_bytes":122,"resp_pkts":17,"resp_ip_bytes":7754,"ip_proto":17}
    <85>1 2025-11-18T09:28:46.711Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="ssl.log"] {"ts":1763458126.681856,"uid":"Cy4rVk3lxsm8DQh7R1","id.orig_h":"192.168.0.109","id.orig_p":34284,"id.resp_h":"192.0.78.212","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"x25519","server_name":"zeek.org","resumed":false,"established":true,"ssl_history":"CsiI"}


### Raw JSON

```
UDP_LOGGING_FORMAT=raw-json
```

UDP packets contain only the JSON part. Note that you might want to use a
"ext func" to extend Zeek's record with the path and write timestamp.

    {"ts":1763459228.086805,"uid":"CT4kMH2Zm7H23mEr5k","id.orig_h":"192.168.0.109","id.orig_p":36862,"id.resp_h":"192.0.78.150","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"x25519","server_name":"zeek.org","resumed":false,"established":true,"ssl_history":"CsiI"}
    {"ts":1763459225.503546,"uid":"CSUYyp49OivWWaenRb","id.orig_h":"192.168.0.109","id.orig_p":36850,"id.resp_h":"192.0.78.150","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.18991804122924805,"orig_bytes":795,"resp_bytes":163862,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":64,"orig_ip_bytes":3375,"resp_pkts":91,"resp_ip_bytes":167514,"ip_proto":6}
    {"ts":1763459225.440854,"uid":"CDlZEC3MW7TKfUL3lf","id.orig_h":"192.168.0.109","id.orig_p":46134,"id.resp_h":"192.0.78.212","id.resp_p":80,"proto":"tcp","service":"http","duration":0.2576940059661865,"orig_bytes":71,"resp_bytes":441,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":6,"orig_ip_bytes":331,"resp_pkts":4,"resp_ip_bytes":613,"ip_proto":6}
