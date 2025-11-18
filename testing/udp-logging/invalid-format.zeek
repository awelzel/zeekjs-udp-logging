# @TEST-DOC: Check behavior when selecting an invalid format.
#
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC-FAIL: UDP_LOGGING_FORMAT=InVaLiD zeek -b %INPUT $PACKAGE >zeek.out 2>&1
# @TEST-EXEC: btest-diff zeek.out

redef exit_only_after_terminate = T;
