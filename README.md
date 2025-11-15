# zeekjs-udp-logging

## About

A proof-of-concept JavaScript based UDP logger to integrate
Zeek with Cisco's Secure Network Analytics platform.

See: https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/zeek/7_5_2_Zeek_Configuration_Guide_DV_1_0.pdf

If this doesn't fulfill your performance or reliability requirements, you
can always implement a C++ Zeek plugin adding a UDP writer. See the Zeek
documentation for more details.

This script uses safe-stable-stringify for rendering log records to JSON.

    npm install safe-stable-stringify@2.5.0
