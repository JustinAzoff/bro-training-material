module SSH;

redef enum Notice::Type += {
	Login,
};

global brute_forcers: set[addr] &write_expire=24hrs;

event SSH::heuristic_successful_login(c: connection)
	{
	NOTICE([$note=Login, $msg="Possible SSH login success", $conn=c]);
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Password_Guessing )
		add brute_forcers[n$src];
	else if ( n$note == SSH::Login && n$id$orig_h in brute_forcers )
		{
		add n$actions[Notice::ACTION_ALARM];
		n$sub = "Was previously a password guesser";
		}
	}
