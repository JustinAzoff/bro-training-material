==============================================
Exercise: Understanding and Examining Bro Logs
==============================================

.. class:: opening

   During the course of its normal operation, Bro 
   produces a large volume of log files.  This series of exercises
   examines the Bro log output format, and highlights a few
   extremely useful utilities that can be used to extract data from 
   and/or process this information.

Part 1: Generating Logs
=======================

.. exercise:: 

   Run bro with the ``-r`` option, and provide the `http.pcap
   <http://www.bro.org/static/traces/http.pcap>`_ file.  For more information on bro options, please run
   bro with the ``-h`` option.

   .. note:: 

      Logs will be generated in the current working directory!

.. visible_solution:: 

   .. console::

      mkdir /tmp/bro-logs
      cd /tmp/bro-logs
      bro -r traces/http.pcap

Part 2: Matching Records to Log Fields
======================================

.. exercise::

   For this, you'll need `misc.pcap <http://www.bro.org/static/traces/misc.pcap>`_.

   Run this command:

   .. console:: bro -r misc.pcap

   and then interpret the fields in each of the resulting logs.  Examine
   relevant records in the associated script files; be sure to look for
   the ``&log`` directive when examining those files.

   .. note:: Record definitions can normally be found in
      ``$PREFIX/share/bro/base/protocols/<PROTO>/main.bro`` in the 
      in the installation directory (or ``scripts/base/protocols/...``
      in the Bro source tree).

Part 3: Connection Statistics
=============================

Bro summarizes each TCP and UDP connection as a single line in the
``conn.log``. Because these connection summaries are quite detailed, you can
extract plenty useful statistics from it. For the following two parts, use the
log files generated from the trace `2009-M57-day11-18.trace.gz`__
via ``bro -r 2009-M57-day11-18.trace.pcap``.

__ http://www.bro.org/static/traces/2009-M57-day11-18.trace.gz

.. exercise::
    List the connections by in increasing order of duration, i.e., the longest
    connections at the end.

.. visible_solution::
    .. console::

        awk 'NR > 4' < conn.log | sort -t$'\t' -k 9 -n

    The ``duration`` field records the number of seconds per connection. Its
    location is by default field number 9. Because we want the whole line
    without the comments, we skip the first four lines. Then we sort by the
    same field (``-k 9``) numerically (``-n``).
    
    ::

        138	udp	-	-	-	-	S0	-	0	D	1	229	0	0
        1258532683.876479	6XCmETILKQj	192.168.1.103	138	192.168.1.255	138	udp	-	-	-	-	S0	-	0	D	1	240	0	0
        1258532824.338291	Up71DFBWvn9	192.168.1.104	138	192.168.1.255	138	udp	-	-	-	-	S0	-	0	D	1	229	0	0
        1258533406.310783	t3XZuevetC4	192.168.1.103	138	192.168.1.255	138	udp	-	-	-	-	S0	-	0	D	1	240	0	0
        1258533546.501981	l26lscUQs05	192.168.1.104	138	192.168.1.255	138	udp	-	-	-	-	S0	-	0	D	1	229	0	0
        1258533745.340248	7mcJ1A7fK8f	192.168.1.1	5353	224.0.0.251	5353	udp	-	-	-	-	S0	-	0	D	1	105	0	0
        1258533766.050097	Ah3IckDD2p4	192.168.1.102	138	192.168.1.255	138	udp	-	-	-	-	S0	-	0	D	1	229	0	0
        1258534161.354320	0tze0IPUea6	192.168.1.102	1180	68.216.79.113	37	tcp	-	-	-	-	S0	-	0	S	1	48	0	0
        ...
        

.. exercise::
    Find all connections that are last longer than one minute.

.. visible_solution::

    .. console::

        awk 'NR > 4 && $9 > 60' conn.log

    We look again at field number 9, but this time add another filter to
    display only those lines whose duration is greater than 60 seconds.
    
    ::

        1258535660.158200	qho9DFjZlob	192.168.1.104	1196	65.55.184.16	443	tcp	ssl	67.887666	57041	8510	RSTR	-	0	ShADdar	54	59209	26	9558
        1258543996.442969	Y5tkDNnwDci	192.168.1.103	138	192.168.1.255	138	udp	-	60.629434	560	0	S0	-	0	D	3	644	0	0
        1258551306.134546	enTlgt1EdPg	192.168.1.104	138	192.168.1.255	138	udp	-	61.005932	549	0	S0	-	0	D	3	633	0	0
        1258561885.476082	7PMLf3OCwgh	192.168.1.105	49210	65.55.184.155	443	tcp	ssl	66.419106	55531	7475	RSTR	-	0	ShADdar	52	57623	21	8323
        1258562522.926514	RLxZxpgN0X4	192.168.1.104	1386	74.125.164.85	80	tcp	http	63.735504	683	30772	SF	-	0	ShADadfF	13	1211	28	31900
        1258562636.223671	dYR9bmgCfqf	192.168.1.104	1387	74.125.164.85	80	tcp	http	65.450666	694	11708	SF	-	0	ShADadfF	9	1062	14	12276
        1258562701.674828	jnI3OrUbadg	192.168.1.104	1423	74.125.164.85	80	tcp	http	65.169595	3467	60310	SF	-	0	ShADadfF	21	4315	54	62478
        1258562522.748378	y0HGSpY912g	192.168.1.104	1385	74.125.19.102	80	tcp	http	244.158006	950	1800	SF	-	0	ShADadfF	6	1198	6	2048
        1258562766.844923	tJHQEO0r3I4	192.168.1.104	1424	74.125.164.85	80	tcp	http	75.058910	3384	83613	SF	-	0	ShADadfF	23	4312	72	86501
        1258562679.607431	rtqNEtM6mu2	192.168.1.104	1413	74.125.19.148	80	tcp	http	252.293422	427	347	SF	-	0	ShADadfF	6	675	6	595
        ...

.. exercise::
    Find all IP addresses of web servers that send more than more than 1 KB
    back to a client.

.. visible_solution::
    .. console::

        bro-cut service resp_bytes id.resp_h < conn.log \
            | awk '$1 == "http" && $2 > 1000000 { print $3 }' \
            | sort -u
    
    First, we extract the relevant fields from the ``conn.log``, which are
    ``id.resp_h``, ``service``, and ``resp_bytes``. The idea is to filter all
    connections labeled as HTTP where the responder (i.e., the server) sent
    more than 1,000 bytes.

    Recall ``awk``'s pattern-action statement, wich looks like ``pattern {
    action }``. The filter conditions appear in the pattern, whereas the
    print directives in the action. Here, we print only the third field that we
    extracted with ``bro-cut``, namely ``id.resp_h``. Finally, we weed out
    duplicates via ``sort -u``.
    
    ::

        130.59.10.36
        137.226.34.227
        151.207.243.129
        193.1.193.64
        198.189.255.73
        198.189.255.74
        198.189.255.82
        208.111.128.122
        208.111.129.48
        208.111.129.62
        65.54.95.201
        65.54.95.209
        65.54.95.7
        68.142.123.21
        68.142.123.31

.. exercise::
    Are there any web servers on non-standard ports (i.e., 80 and 8080)?

.. visible_solution::
    .. console::

        bro-cut service id.resp_p id.resp_h < conn.log \
            | awk '$1 == "http" && ! ($2 == 80 || $2 == 8080) { print $3 }' \
            | sort -u

    This ``awk`` exercise is similar to the above in terms of complexity, with
    the only difference being a different filter expression. The output is
    empty, meaning that Bro did not find any web servers on non-standard ports
    in this trace.

.. exercise::
    Show a breakdown of the number of connections by service.

.. visible_solution::
    .. console::

        bro-cut service < conn.log | sort | uniq -c | sort -n

    This is a typical *aggregation* question. The standard procedure almost
    always contains a combination of ``sort`` and ``uniq``. The main idea is to
    massage the lines such that sorting and counting them yields a reasonable
    output. The advantage of this approach is that it does not accumulate any
    in-memory state and can rely on external sorting, which is imperative for
    large sets of logs.

    One can also think about these aggregation tasks as a MapReduce job, where
    the first part of the pipeline is the map phase, ``sort`` the shuffle
    phase, and ``uniq`` a primitive reducer.
    
    ::

           2 ftp
           2 ftp-data
          21 smtp
         113 ssl
        1786 -
        2386 http
        3992 dns

.. exercise::
    Show the top 10 destination ports in descending order.

.. visible_solution::
    .. console::

        bro-cut id.resp_p < conn.log | sort | uniq -c | sort -rn | head -n 10

    In the spirit as above, we aggregate the destination ports and sort the
    final output again to emit only the top 10 values.
    
    ::

        3455 53
        2730 80
         776 138
         553 137
         196 67
         189 139
          87 5353
          73 443
          62 37
          53 995

.. exercise::
    What are the top 10 hosts (originators) that send the most traffic?

.. visible_solution::
    .. console::

        bro-cut id.orig_h orig_bytes < conn.log             \
            | sort                                          \
            | awk '{ if (host != $1) {                      \
                         if (size != 0)                     \
                             print $1, size;                \
                          host=$1;                          \
                          size=0                            \
                      } else                                \
                          size += $2                        \
                    }                                       \
                    END {                                   \
                        if (size != 0)                      \
                             print $1, size                 \
                        }'                                  \
            | sort -k 2                                     \
            | head -n 10

    This is a more involved example with a more complicated "reducer" function.
    The main idea is to order the output such that the traffic of one host is
    grouped together. Each group can then processed with constant space in
    ``awk`` by only maintaining two variables ``host`` and ``size``. Finally,
    once we have the per-host aggregate of the sent volume, we sort the
    second field (``-k 2``) and display the top 10 entries.
    
    ::

        192.168.1.103 1079461
        192.168.1.104 1332571
        192.168.1.105 2050085
        192.168.1.102 207289
        192.168.1.1 2172
        169.254.173.77 6116
        192.168.1.105 800067


Part 4: HTTP Statistics
========================

.. exercise::
    What are the distinct browsers in this trace? What are the distinct MIME
    types of the downloaded URLS?

.. visible_solution::
    .. console::

        bro-cut user_agent < http.log | sort -u
        bro-cut mime_type < http.log | sort -u

    First, we extract the relevant field with ``bro-cut`` and then restrict
    the output to the distinct values. The query is not very complicated, yet
    can still be quite insightful.
    
    ::

        AVGDM-
        AVGDM-WVSXX86 85 BUILD=39 LOC=1033 BRD=cnet-0-0
        AVGDM-WVSXX86 85 BUILD=40 LOC=1033 PRD=US-F-AVF
        AVGINET9-WVSXX86 90 AVI=270.14.71/2510 BUILD=707 LOC=1033 LIC=9I-ASXNN-X4WGW-M0XFR-T84VX-3VX02 DIAG=51E OPF=0 PCA=
        AVGINET9-WVSXX86 90 AVI=270.14.72/2511 BUILD=707 LOC=1033 LIC=9I-ASXNN-X4WGW-M0XFR-T84VX-3VX02 DIAG=51E OPF=0 PCA=
        AVGINET9-WVSXX86 90FREE AVI=270.14.73/2512 BUILD=707 LOC=1033 LIC=9AVFREE-VKPCB-6BWFM-TRLQR-BRUHP-CP86G DIAG=310 OPF=0 PCA=
        AVGINET9-WXPPX86 90 AVI=270.14.71/2510 BUILD=707 LOC=1033 LIC=9I-ASXNN-X4WGW-M0XFR-T84VX-3VX02 DIAG=51E OPF=0 PCA=
        AVGINET9-WXPPX86 90 AVI=270.14.72/2511 BUILD=707 LOC=1033 LIC=9I-ASXNN-X4WGW-M0XFR-T84VX-3VX02 DIAG=51E OPF=0 PCA=
        AVGINET9-WXPPX86 90 AVI=270.14.73/2512 BUILD=707 LOC=1033 LIC=9I-ASXNN-X4WGW-M0XFR-T84VX-3VX02 DIAG=51E OPF=0 PCA=
        Google Update/1.2.183.13;winhttp
        Google Update/1.2.183.13;winhttp;cup
        JNLP/6.0 javaws/1.6.0_16 (b01) Java/1.6.0_16
        MSDW
        Microsoft BITS/7.0
        Microsoft NCSI
        Microsoft-CryptoAPI/5.131.2600.5512
        Microsoft-CryptoAPI/6.0
        Microsoft-WebDAV-MiniRedir/6.0.6002
        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.0.04506)
        Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)
        Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.23) Gecko/20090812 Lightning/0.9 Thunderbird/2.0.0.23
        Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.23) Gecko/20090812 Thunderbird/2.0.0.23
        Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5
        Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.33 Safari/532.0
        Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)
        SCSDK-6.0.0
        Shockwave Flash
        Windows-Update-Agent
        clamav/0.92.1
        jupdate
        live-client/2.0
        
    ::

        -
        application/octet-stream
        application/pdf
        application/vnd.ms-cab-compressed
        application/x-123
        application/x-dosexec
        application/x-elc
        application/x-shockwave-flash
        application/xml
        image/gif
        image/jpeg
        image/png
        image/x-icon
        image/x-ms-bmp
        text/html
        text/plain
        text/troff
        text/x-c
        text/x-c++
        text/x-java
        text/xml
        video/x-flv
    
.. exercise::
    What are the three most commonly accessed web sites?

.. visible_solution::
    .. console::

        bro-cut host < http.log | sort | uniq -c | sort -n | tail -n 3

    In this case, we are interested in the ``Host`` header of the HTTP request,
    which the ``http.log`` provides in the ``host`` field. We interpret the
    "most commonly accessed" phrase as number of requests, i.e., number of
    lines in the log file. The aggregation is similar to what we have seen in
    the previous part.
    
    ::

         231 safebrowsing-cache.google.com
         259 scores.espn.go.com
         421 download.windowsupdate.com

.. exercise::
    What are the top 10 referred hosts?

.. visible_solution::
    .. console::

        bro-cut referrer < http.log                     \
            | awk 'sub(/[[:alpha:]]+:\/\//, "", $1)     \
                   {                                    \
                       split($1, s, /\//);              \
                       print s[1]                       \
                   }'                                   \
            | sort                                      \
            | uniq -c                                   \
            | sort -rn                                  \
            | head -n 10

    Although the value of the ``Referer`` (sic) header is readily available via
    the ``referrer``  field in the ``http.log``, it may not be in the
    appropriate format. For example, sometimes we observe values containing a
    full URL path, and sometimes just the host. Therefore, we perform an extra
    sanitization step that strips an optional protocol part (``sub``) and
    then extracts only the value of the host name of the referring URL.
    
    ::

         275 adsatt.espn.go.com
         234 espn.go.com
         230 www.google.com
         217 co108w.col108.mail.live.com
         165 www.carmax.com
         160 www.toysrus.com
         139 support.dell.com
         122 www.engadget.com
         120 sports.espn.go.com
         117 www.msn.com

Part 5: Tweaking Log Output
===========================

.. exercise:: 

  Tell Bro to include the `new_separator.bro <new_separator.bro>`_
  script, and then re-process ``http.pcap``. After verifying that the
  separator character has, in fact, changed, modify the separator
  character defined in ``new_separator.bro`` to be something slightly
  more interesting. Next, re-run Bro and verify that the separator
  character worked as expected and that the ``#separator`` field at the
  top of the file was updated appropriately. Now, add a line to
  ``new_separator.bro`` that will change the comment character used in
  the log file; consult ``base/frameworks/logging/writers/ascii.bro`` to
  determine the appropriate incantation.

.. visible_solution:: 

  Your ``new_separator.bro`` should look something like:

  .. code:: bro

     redef LogAscii::separator = ",";
     redef LogAscii::header_prefix = "//";

  .. note::
     While bro may accept a two-character separator, keep in mind that some parsers may not understand
     how to correctly parse a CSV file that uses a string of characters to separate individual fields.
