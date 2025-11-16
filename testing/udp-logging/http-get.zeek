# @TEST-DOC: Basic testing using netcat.
#
# @TEST-REQUIRES: which nc
# @TEST-SERIALIZE: nc-19514
#
# @TEST-EXEC: btest-bg-run nc 'run-nc-udp-listen > ../nc.log'
# @TEST-EXEC: timeout --preserve-status 1 zeek -C -r $TRACES/http/get.trace $PACKAGE %INPUT > zeek.out 2>&1
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: btest-diff zeek.out
# @TEST-EXEC: btest-diff nc.log

event zeek_init() {
	# packet_filter.log is using current time rather than pcap time / 0.0
	Log::disable_stream(PacketFilter::LOG);
}
