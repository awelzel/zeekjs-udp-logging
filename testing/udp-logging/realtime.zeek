# @TEST-DOC: Check reconnection working
#
# @TEST-REQUIRES: which nc
# @TEST-SERIALIZE: nc-19514
#
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run zeek 'cp %INPUT main.zeek && zeek -b ./main.zeek $PACKAGE >out 2>&1'
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: btest-diff zeek/out

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
	if ( i == n ) {
		terminate();
		return;
	}

	Log::write(LOG, [$msg=fmt("tick %s", i)]);
	schedule 1msec { tick(++i) };
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	event tick(1);
	}

