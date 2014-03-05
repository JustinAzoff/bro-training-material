================================
Bro SumStats Framework Exercises
================================

.. class:: opening

    The SumStats framework is a continuation and rename of the old
    Metrics framework from Bro 2.0 and 2.1.  The API and capabilities
    have been greatly expanded and improved.  A major goal for SumStats
    has been to provide advanced statistical and summarization 
    capabilities in a way that is both relatively easy to use and can
    perform on clusters.

Part 1: Analysis and Thresholding
=================================

For all of these exercises we'll be using the `exercise-traffic.pcap <http://www.bro.org/static/traces/exercise-traffic.pcap>`_ file.

.. exercise::

    First we need to observe something so we need to consider the very base thing
    we want to measure.  DNS query names by the requester perhaps?  Copy the following 
    code into a file named `sumstats-1.bro <sumstats-1.bro>`_.

    .. code:: bro
        
        event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
            {
            if ( c$id$resp_p == 53/udp && query != "" )
                SumStats::observe("dns.lookup", [$host=c$id$orig_h], [$str=query]);
            }

    Running this script as it is won't provide any output, we haven't 
    instructed the SumStats framework to do anything with those observations. 
    In the same script, below the previous chunk of code, paste this code:

    .. code:: bro

        event bro_init()
            {
            local r1 = SumStats::Reducer($stream="dns.lookup", $apply=set(SumStats::UNIQUE));
            SumStats::create([$name="dns.requests.unique",
                              $epoch=6hr,
                              $reducers=set(r1),
                              $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                local r = result["dns.lookup"];
                                print fmt("%s did %d total and %d unique DNS requests in the last 6 hours.",
                                           key$host, r$num, r$unique);
                                },
                              $epoch_finished(ts: time) =
                                {
                                print "-----------";
                                }]);
            }

    This script creates a reducer which collects unique values of the third 
    argument of the "observe" call above (DNS queries).  The reducer is then
    added to the SumStat we're creating which has a measurement epoch of 6
    hours.  At the end of the 6 hour period, the "epoch_result" callback will 
    be called once for each result value being tracked.  There will be a 
    result value for each "Key" which is the second argument in the observe
    call above.  Once all of the keys have been processed through the epoch_result
    callback, the epoch_finished callback will be called.

    We should now be able to take a look at our result from this script.

    .. console::

        bro -r exercise-traffic.pcap sumstats-1.bro

.. visible_solution::

    ::

	-----------
	192.168.1.104 did 20 total and 10 unique DNS requests in the last 6 hours.
	192.168.1.103 did 18 total and 6 unique DNS requests in the last 6 hours.
	192.168.1.102 did 17 total and 6 unique DNS requests in the last 6 hours.
	-----------
	192.168.1.104 did 112 total and 90 unique DNS requests in the last 6 hours.
	192.168.1.103 did 219 total and 168 unique DNS requests in the last 6 hours.
	192.168.1.105 did 508 total and 306 unique DNS requests in the last 6 hours.
	192.168.1.102 did 430 total and 343 unique DNS requests in the last 6 hours.
	-----------

.. exercise::

    Now we can go a slightly different direction and set a threshold on the number
    of unique DNS requests.  Use the same bit of code from above for doing the 
    observation but replace the bro_init event handler from the previous exercise 
    with the following code into a new file named `sumstats-2.bro <sumstats-2.bro>`_.

    .. code:: bro

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

    You can see that this script is slightly different in that it doesn't have the
    epoch_result or epoch_finished callbacks.  Instead it has several threshold
    related fields filled out.  "threshold_val" is a callback that must be provided
    when doing SumStat thresholding and it needs to return a double value of the 
    current value you want your threshold applied to.  "threshold" is just a double
    that you want the threshold to be.  "threshold_crossed" is a callback that is 
    called when a threshold has been crossed.

    Now run

    .. console::

        bro -r exercise-traffic.pcap sumstats-2.bro

.. visible_solution::

    ::

        192.168.1.103 did more than 150 unique requests!
        192.168.1.105 did more than 150 unique requests!
        192.168.1.102 did more than 150 unique requests!

.. exercise::

    One final small change we can make is to do a threshold on a ratio of
    unique to total DNS requests.  Using the same "observe" call we've been
    using this whole time, now use the following SumStat to set a threshold
    on the number of distinct DNS lookups being performed by a host by
    comparing the number of unique requests to the total number of requests.
    Name this file `sumstat-3.bro <sumstat-3.bro>`_.

    .. code:: bro

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

    Now run this script:

    .. console::

        bro -r exercise-traffic.pcap sumstats-3.bro

.. visible_solution::

    ::

        95% or more of the 60 DNS requests made by 192.168.1.104 are distinct.

Part 2: Probabilistic Top-K
===========================

There are times where the top most frequently seen things are something
that is interesting from a performance monitoring, network tuning, or
even security perspective.  Bro 2.2's new probabilistic Top-K support 
can provide that data in an easy to consume way.

.. exercise::

    If you want to know the top 10 names being requested over DNS on 
    a network that would normally be quite difficult, but with the
    SumStats framework it's actually a relatively small bit of 
    code to get that data on a single Bro process or to get the same
    result on a large cluster.

    Paste the following code sample into a file named `sumstats-4.bro <sumstats-4.bro>`_.

    .. code::

        event bro_init()
            {
            local r1 = SumStats::Reducer($stream="dns.lookups", $apply=set(SumStats::TOPK), $topk_size=50);
            SumStats::create([$name="top_dns_lookups",
                              $epoch=12hrs,
                              $reducers=set(r1),
                              $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                local r = result["dns.lookups"];
                                local s: vector of SumStats::Observation;
                                s = topk_get_top(r$topk, 10);
                                print fmt("Top 10 DNS requests by %s for %D through %D", key$host, r$begin, r$end);
                                for ( i in s ) 
                                    {
                                    if ( i == 10 )
                                        break;

                                    print fmt("   Name: %s (estimated count: %d)", 
                                                  s[i]$str, topk_count(r$topk, s[i]));
                                    }
                                    # Add an extra line for nice formatting.
                                    print "";
                                }
                              ]);
            }

        event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
            {
            if ( c$id$resp_p == 53/udp && query != "" )
                SumStats::observe("dns.lookups", [$host=c$id$orig_h], [$str=query]);
            }

    This is very similar to the code samples from before and the main difference
    to pay attention to is the reducer.  You can see the TOPK algorithm is being
    applied to observations being fed into the reducer.

    Now run

    .. console::

        bro -r exercise-traffic.pcap sumstats-4.bro

.. visible_solution::

    ::
    
        Top 10 DNS requests by 192.168.1.104 for 2009-11-18-03:16:43 through 2009-11-18-13:16:49
           Name: sn21.mailshell.net (estimated count: 18)
           Name: patft.uspto.gov (estimated count: 4)
           Name: www.uspto.gov (estimated count: 4)
           Name: ebiz1.uspto.gov (estimated count: 4)
           Name: patimg1.uspto.gov (estimated count: 4)
           Name: safebrowsing.clients.google.com (estimated count: 4)
           Name: safebrowsing-cache.google.com (estimated count: 4)
           Name: version.avg.com (estimated count: 3)
           Name: newsrss.bbc.co.uk (estimated count: 3)
           Name: streamerapi.finance.yahoo.com (estimated count: 3)

        Top 10 DNS requests by 192.168.1.105 for 2009-11-18-11:21:20 through 2009-11-18-13:19:50
           Name: update.avg.com (estimated count: 16)
           Name: cdn.visiblemeasures.com (estimated count: 11)
           Name: games.espn.go.com (estimated count: 11)
           Name: scores.espn.go.com (estimated count: 11)
           Name: ak1.abmr.net (estimated count: 10)
           Name: smp.specificmedia.com (estimated count: 10)
           Name: espn.vad.go.com (estimated count: 10)
           Name: assets.espn.go.com (estimated count: 10)
           Name: games-ak.espn.go.com (estimated count: 10)
           Name: creativeby1.unicast.com (estimated count: 10)

        Top 10 DNS requests by 192.168.1.102 for 2009-11-18-03:15:43 through 2009-11-18-13:18:27
           Name: sn21.mailshell.net (estimated count: 19)
           Name: issuu.com (estimated count: 11)
           Name: www.comicscontinuum.com (estimated count: 11)
           Name: www.nation.co.ke (estimated count: 10)
           Name: www.allmovie.com (estimated count: 10)
           Name: www.ireport.com (estimated count: 9)
           Name: www.cnnchile.com (estimated count: 9)
           Name: www.slashfilm.com (estimated count: 9)
           Name: moviesblog.mtv.com (estimated count: 9)
           Name: www.cinemablend.com (estimated count: 9)

        Top 10 DNS requests by 192.168.1.103 for 2009-11-18-03:56:22 through 2009-11-18-12:55:50
           Name: sn21.mailshell.net (estimated count: 17)
           Name: evintl-crl.verisign.com (estimated count: 6)
           Name: lvb.avg.com (estimated count: 6)
           Name: www.addthis.com (estimated count: 6)
           Name: www.delphion.com (estimated count: 5)
           Name: a.ads2.msn.com (estimated count: 5)
           Name: ec.atdmt.com (estimated count: 5)
           Name: www.mate1.com (estimated count: 5)
           Name: www.google.com (estimated count: 5)
           Name: bks5.books.google.com (estimated count: 5)

.. exercise::

    The previous example was nice because it showed calculating lots of 
    separate Top-10 results.  Something a bit more useful in live network
    traffic might be to calculate the Top-10 DNS requests for everything
    in the entire network.

    Paste the folowing code into a file named `sumstats-5.bro <sumstats-5.bro>`_.

    .. code::

        event bro_init()
            {
            local r1 = SumStats::Reducer($stream="dns.lookups", $apply=set(SumStats::TOPK), $topk_size=50);
            SumStats::create([$name="top_dns_lookups",
                              $epoch=12hrs,
                              $reducers=set(r1),
                              $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                local r = result["dns.lookups"];
                                local s: vector of SumStats::Observation;
                                s = topk_get_top(r$topk, 10);
                                print fmt("Top 10 DNS requests for %D through %D", r$begin, r$end);
                                for ( i in s ) 
                                    {
                                    if ( i == 10 )
                                        break;

                                    print fmt("   Name: %s (estimated count: %d)", s[i]$str, topk_count(r$topk, s[i]));
                                    }
                                    # Add an extra line for nice formatting.
                                    print "";
                                }]);
            }

        event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
            {
            if ( c$id$resp_p == 53/udp && query != "" )
                SumStats::observe("dns.lookups", [], [$str=query]);
            }

    Now run

    .. console::

        bro -r exercise-traffic.pcap sumstats-5.bro

.. visible_solution::

    ::
    
        Top 10 DNS requests for 2009-11-18-03:15:43 through 2009-11-18-13:19:50
           Name: sn21.mailshell.net (estimated count: 60)
           Name: www.comicscontinuum.com (estimated count: 27)
           Name: update.avg.com (estimated count: 26)
           Name: issuu.com (estimated count: 26)
           Name: smp.specificmedia.com (estimated count: 26)
           Name: cdn.visiblemeasures.com (estimated count: 26)
           Name: geo.eyewonder.com (estimated count: 26)
           Name: brsseavideo-ak.espn.go.com (estimated count: 26)
           Name: amch.questionmarket.com (estimated count: 26)
           Name: a.dlqm.net (estimated count: 26)
