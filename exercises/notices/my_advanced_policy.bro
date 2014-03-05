module SSH;

redef enum Notice::Type += {
	Login,
};

const watched_servers: set[addr] = {
	172.16.238.136,
	172.16.238.168,
} &redef;

event SSH::heuristic_successful_login(c: connection)
	{
	NOTICE([$note=Login, $msg="Possible SSH login success", $conn=c]);
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Login && n$id$resp_h in watched_servers )
		add n$actions[Notice::ACTION_ALARM];
	}
