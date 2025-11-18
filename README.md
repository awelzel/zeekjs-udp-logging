# zeekjs-udp-logging

## About

A proof-of-concept JavaScript based UDP logger to integrate Syslog or
other UDP-based log receiver systems with Zeek.

If this doesn't fulfill your performance or reliability requirements, you
can always implement a C++ Zeek plugin adding a UDP log writer component.
See the Zeek documentation for more details.

## Supported Formats

### Tagged RFC5424

By default, the script sends UDP packets using tagged RFC5424 format with the
msg being the JSON encoded payload of the log record.

    <85> 1 2025-11-18T09:28:46.634Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="http.log"] {"ts":1763458126.600419,"uid":"CRudTvORUWvlRqRz5","id.orig_h":"192.168.0.109","id.orig_p":45538,"id.resp_h":"192.0.78.212","id.resp_p":80,"trans_depth":1,"method":"GET","host":"zeek.org","uri":"/","version":"1.1","user_agent":"curl/8.5.0","request_body_len":0,"response_body_len":162,"status_code":301,"status_msg":"Moved Permanently","tags":[],"resp_fuids":["FmQGaAZRt93axdHi6"],"resp_mime_types":["text/html"]}
    <85> 1 2025-11-18T09:28:46.710Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="conn.log"] {"ts":1763458065.435613,"uid":"CEvhV93jXZEA5UPcKh","id.orig_h":"192.168.0.109","id.orig_p":49549,"id.resp_h":"192.168.0.1","id.resp_p":1900,"proto":"udp","duration":1.2656450271606445,"orig_bytes":94,"resp_bytes":7278,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"Dd","orig_pkts":1,"orig_ip_bytes":122,"resp_pkts":17,"resp_ip_bytes":7754,"ip_proto":17}
    <85> 1 2025-11-18T09:28:46.711Z zeek zeekjs-udp-logging 1372605 - [zeek_filename="ssl.log"] {"ts":1763458126.681856,"uid":"Cy4rVk3lxsm8DQh7R1","id.orig_h":"192.168.0.109","id.orig_p":34284,"id.resp_h":"192.0.78.212","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"x25519","server_name":"zeek.org","resumed":false,"established":true,"ssl_history":"CsiI"}

This may be compatible with [Cisco's SNA](https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/zeek/7_5_2_Zeek_Configuration_Guide_DV_1_0.pdf) system, but hasn't been integration tested yet.

### Raw JSON

Setting ``UDP_LOGGING_FORMAT=raw-json`` allows to change the format to have
UDP packets contain only the JSON part. Not that you likely want to use a
"ext func" to extend Zeek's record with the path and write timestamp.

    {"ts":1763459228.086805,"uid":"CT4kMH2Zm7H23mEr5k","id.orig_h":"192.168.0.109","id.orig_p":36862,"id.resp_h":"192.0.78.150","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"x25519","server_name":"zeek.org","resumed":false,"established":true,"ssl_history":"CsiI"}
    {"ts":1763459225.503546,"uid":"CSUYyp49OivWWaenRb","id.orig_h":"192.168.0.109","id.orig_p":36850,"id.resp_h":"192.0.78.150","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.18991804122924805,"orig_bytes":795,"resp_bytes":163862,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":64,"orig_ip_bytes":3375,"resp_pkts":91,"resp_ip_bytes":167514,"ip_proto":6}
    {"ts":1763459225.440854,"uid":"CDlZEC3MW7TKfUL3lf","id.orig_h":"192.168.0.109","id.orig_p":46134,"id.resp_h":"192.0.78.212","id.resp_p":80,"proto":"tcp","service":"http","duration":0.2576940059661865,"orig_bytes":71,"resp_bytes":441,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADadFf","orig_pkts":6,"orig_ip_bytes":331,"resp_pkts":4,"resp_ip_bytes":613,"ip_proto":6}


## Installation

    $ zkg install zeekjs-udp-logging

## Running

To send all logs to 127.0.0.1:9514, run as follows after installation:

    $ zeek -i <interface> zeekjs-udp-logging

## Configuration

The script currently respects the UDP_LOGGING_HOST and UDP_LOGGING_PORT variables:

    $ export UDP_LOGGING_HOST=192.168.0.1
    $ export UDP_LOGGING_PORT=19514
    $ export UDP_LOGGING_FORMAT=raw-json

    $ zeek -i <interface> zeekjs-udp-logging

For IPV6, set UDP_LOGGING_TYPE to ``udp6``.
