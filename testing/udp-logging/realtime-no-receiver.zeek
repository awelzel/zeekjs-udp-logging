# @TEST-DOC: Check realtimer Log::write() calls.
#
# @TEST-SERIALIZE: nc-19514
#
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run zeek 'zeek -b %INPUT $PACKAGE >out 2>&1'
# @TEST-EXEC: btest-bg-wait -k 1
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

const n = 10;

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

