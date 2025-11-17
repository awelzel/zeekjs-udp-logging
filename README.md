# zeekjs-udp-logging

## About

A proof-of-concept JavaScript based UDP logger to integrate
Zeek with Cisco's Secure Network Analytics platform.

See: https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/zeek/7_5_2_Zeek_Configuration_Guide_DV_1_0.pdf

If this doesn't fulfill your performance or reliability requirements, you
can always implement a C++ Zeek plugin adding a UDP writer. See the Zeek
documentation for more details.

## Installation

    $ zkg install https://github.com/awelzel/zeekjs-udp-logging

## Running

To send all logs to 127.0.0.1:9514, run as follows after installation:

    $ zeek -i <interface> zeekjs-udp-logging

## Configuration

The script currently respects the UDP_LOGGING_HOST and UDP_LOGGING_PORT variables:

    $ export UDP_LOGGING_HOST=192.168.0.1
    $ export UDP_LOGGING_PORT=19514

    $ zeek -i <interface> zeekjs-udp-logging

For IPV6, set UDP_LOGGING_TYPE to ``udp6``.
