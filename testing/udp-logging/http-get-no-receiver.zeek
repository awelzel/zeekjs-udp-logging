# @TEST-DOC: Basic testing when the netcat listener is disabled
#
# @TEST-SERIALIZE: nc-19514
#
# @TEST-EXEC: zeek -C -r $TRACES/http/get.trace $PACKAGE %INPUT > zeek.out 2>&1
# @TEST-EXEC: btest-diff zeek.out

event zeek_init() {
	# packet_filter.log is using current time rather than pcap time / 0.0
	Log::disable_stream(PacketFilter::LOG);
}
