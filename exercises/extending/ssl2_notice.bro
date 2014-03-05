module SSL;

redef enum Notice::Type += {
	SSLv2_Client_Hello
};

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: count_set)
	{
	if ( version == SSLv2 )
		{
		local message = fmt("SSL client %s sent v2 hello", c$id$orig_h);
		local ident = fmt("%s", c$id$orig_h);
		NOTICE([$note=SSLv2_Client_Hello,
				$msg=message,
				$conn=c,
				$identifier=ident]);
		}
	}
