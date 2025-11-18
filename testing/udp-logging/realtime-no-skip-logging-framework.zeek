# @TEST-DOC: Check reconnect attempts when no listener is running
#
# @TEST-SERIALIZE: nc-19514
#
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run nc 'run-nc-udp-listen > ../nc.log'
# @TEST-EXEC: btest-bg-run zeek 'UDP_SKIP_LOGGING_FRAMEWORK=0 zeek -b %INPUT $PACKAGE >../zeek.out 2>&1'
# @TEST-EXEC: btest-bg-wait -k 1
# @TEST-EXEC: btest-diff zeek.out
# @TEST-EXEC: zeek-cut -m < zeek/test.log > test.log
# @TEST-EXEC: btest-diff test.log
# @TEST-EXEC: btest-diff nc.log

redef exit_only_after_terminate = T;

module Test;

global t: time = 0;
function next_time(): time
	{
	t = t + 1sec;
	return t;
	}

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &default=next_time() &log;
		msg: string &log;
	};
}

const n = 100;

event tick(i: count) {
	Log::write(LOG, [$msg=fmt("tick %s", i)]);

	if ( i < n )
		schedule 1msec { tick(++i) };
	else
		terminate();
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	event tick(1);
	}

