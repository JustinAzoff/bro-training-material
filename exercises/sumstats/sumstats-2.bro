event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( c$id$resp_p == 53/udp && query != "" )
        SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
    }

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="dns.thresholding",
                      $epoch=6hrs,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["dns.lookup"]$unique+0.0;
                        },
                      $threshold=150.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        print fmt("%s did more than 150 unique requests!", key$host);
                        }]);
    }
