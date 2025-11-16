# @TEST-DOC: Basic testing when the netcat listener is disabled
#
# @TEST-EXEC: timeout --preserve-status 1 zeek -C -r $TRACES/http/get.trace $PACKAGE %INPUT > zeek.out 2>&1
# @TEST-EXEC: btest-diff zeek.out
