event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( c$id$resp_p == 53/udp && query != "" )
        SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
    }

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="dns.distinct.thresholding",
                      $epoch=6hrs,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["dns.lookup"];
                        # We want at least 50 DNS requests before even applying this
                        # ratio based threshold.
                        if ( r$num < 50 )
                            return 0.0;

                        return (r$unique+0.0)/(r$num+0.0);
                        },
                      $threshold=0.95,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["dns.lookup"];
                        print fmt("%.0f%% or more of the %d DNS requests made by %s are distinct.",
                                  ((r$unique+0.0)/(r$num+0.0)*100), r$num, key$host);
                        }]);
    }
