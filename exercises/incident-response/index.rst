.. _illauth.pcap: http://www.bro.org/static/traces/illauth.pcap
.. _theft.pcap: http://www.bro.org/static/traces/theft.pcap
.. _email.pcap: http://www.bro.org/static/traces/email.pcap
.. _notube.pcap: http://www.bro.org/static/traces/notube.pcap
.. _dairystock.pcap: http://www.bro.org/static/traces/dairystock.pcap


==============================================
Exercise: Intelligence-Based Incident Response
==============================================

.. class:: opening

  A typical incident response task begins with a piece of obtained intelligence
  that the security analyst uses as starting point in an investigation. This
  workshop session features several scenarios of this kind.

  Please read the `background story <background.html>`_ for the following
  exercises to familiarize yourself with the necessary context.

Part 1: Ill-Considered Authentication
=====================================

You discover that the users at HBDairy don't have much sense when it comes to
passwords. One employee uses a single password for many different web services,
and it appears clear that one of those services uses a weak form of
standardized web authentication because Synonymous was able to public
demonstrate that they possess the user's password.

.. exercise::

  Examine the web traffic in the `illauth.pcap`_ trace to discover which web
  server used the weak authentication scheme.

.. visible_solution::

  The first step is to find out about the weak forms of web authentication. A
  quick search through the web provides us with two names: *Basic* and *Digest*
  authentication, both of which are implemented by means of the
  ``Authorization`` HTTP header. For Basic authentication, the header value
  contains the word ``Basic`` plus a Base64-encoded string of the format
  ``username:password``.

  Let us look at the values of these headers. Bro's default HTTP script checks
  for the existence of ``Authorization`` headers in HTTP requests, readily
  decodes Basic authentication headers, and puts the credentials into the
  ``http.log`` under the fields ``username`` and ``password``. 

  That is, all we need to do is run Bro with ``bro -r illauth.pcap`` and
  inspect ``http.log``:

  .. console::

     bro-cut id.orig_h id.resp_h username password < http.log  | awk -F$'\t' '$3 != "-"'
    
  As we can see from the output::

    192.168.121.175	192.168.121.176	hbdairye4	-
    192.168.121.175	192.168.121.176	hbdairye4	-

  the web server 192.168.121.176 uses weak authentication.

.. exercise::

  What was the user's password?

.. visible_solution::

  By default, Bro does not log personal user information, such as passwords and
  PII data. In this exercise, however, we are interested in extracting the
  user's password. To this end, we need to tell Bro to capture passwords. As
  this merely involves flipping a boolean switch, we can do it on the command
  line:

  .. console::

     bro -r illauth.pcap "HTTP::default_capture_password=T"

  Running the previous command to extract the credentials:

  .. console::

     bro-cut id.orig_h id.resp_h username password < http.log  | awk -F$'\t' '$3 != "-"'

  now yields::

    192.168.121.175	192.168.121.176	hbdairye4	cheesecake
    192.168.121.175	192.168.121.176	hbdairye4	cheesecake

  That is, 192.168.121.175 logs into 192.168.121.176 with username
  ``hbdairye4`` and password ``cheesecake``.

Part 2: Information Theft From a Web Server
===========================================

Mr. Cheeze informs you that some of the sensitive information that Synonymous
leaked came from a file on the HBDairy web server, though the file was not part
of the content to which the server was supposed to provide access. He is
reluctant to tell you the specifics of the information, but wants you to
determine how the theft occurred.

.. exercise::

  Analyze the web accesses in the `theft.pcap`_ trace. Determine the type of
  attack used to access the file.

.. visible_solution::

  We were told that there HBDairy's web server is involved. Let's look at a few
  requested URLs:

  .. console::

     bro-cut host uri < http.log \
        | awk -F$'\t' '$1 ~ /hbdairy/' \
        | head

  shows output::

    www.hbdairy.com	/index.php?file=../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../../../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../../../../../../../cheddar.pdf
    www.hbdairy.com	/index.php?file=../cheddar.pdf
    www.hbdairy.com	/index.php?file=../../cheddar.pdf

  Okidoke, a bunch of attempts to find a cheesy PDF. This is evidence for a
  *directory traversal attack*.

.. exercise::

  How do you know it was successfully accessed? What was the filename?

.. visible_solution::

  To answer this question, we look at the HTTP reply status codes:

  .. console::

     bro-cut host status_code < http.log \
        | awk -F$'\t' '$1 ~ /hbdairy/ { print $2 } ' \
        | sort \
        | uniq -c

  shows output::

     1 200
    90 404

  90 failed attempts and a single successful one. Let's inspect the successful
  one in more detail:

  .. console::

     bro-cut host uri status_code < http.log \
        | awk -F$'\t' '$1 ~ /hbdairy/ && $3 != "404"'

  shows us::

    www.hbdairy.com	/index.php?file=\xc0\xae\xc0\xae\xc0\xaf\xc0\xae\xc0\xae\xc0\xaf\xc0\xae\xc0\xae\xc0\xafcheddar.pdf	200
  
  Now we also see the full filename on the web server:
  ``/index.php?file=\xc0\xae\xc0\xae\xc0\xaf\xc0\xae\xc0\xae\xc0\xaf\xc0\xae\xc0\xae\xc0\xafcheddar.pdf``.
  Apparently the web server does not properly sanitize all encodings of
  ``../``, which allowed the attacker to successfully fetch the file
  ``cheddar.pdf``.
    

Part 3: Email Leakage
=====================

Due to some other information leaked by Synonymous, HBDairy is certain that
someone carelessly forwarded a sensitive document using unencrypted email.

.. exercise::

  Analyze the SMTP traffic in the `email.pcap`_ trace to locate the document
  and determine who sent the email.

.. visible_solution::

  We begin with running Bro with ``bro -r email.pcap``, which generates two
  interesting files: ``smtp.log`` and ``smtp_entities.log``. This is an HBDairy
  investigation, so we begin with finding some candidate entries:

  .. console::

    grep hbdairy smtp.log

  yields::

    1302419719.507237	WVVfjCeD7	192.168.121.179	51158	192.168.121.176	25	1	[192.168.121.179]	<lesharq@dchlaw.com>	<mondo.cheeze@hbdairy.com>	Sun, 17 Apr 2011 04:44:08 -0400	lesharq <lesharq@dchlaw.com>	mondo.cheeze@hbdairy.com	-	<1303029848.21831.7.camel@seed-desktop>	-	[Confidential] advice	-	-	-	250 2.0.0 Ok: queued as 1774A73E60	192.168.121.176,192.168.121.179	Evolution 2.26.1 
      
  This amount of detail is a bit overwhelming, let's narrow down the output to
  the relevant fields:

  .. console::

     bro-cut uid from to subject < smtp.log | awk -F$'\t' '$1 == "WVVfjCeD7"'

  ::

    WVVfjCeD7	lesharq <lesharq@dchlaw.com>	mondo.cheeze@hbdairy.com	[Confidential] advice
    WVVfjCeD7	-	-	-
  
  With the connection UID from ``smtp.log``, we now investigate the log file
  ``smtp_entities.log``, which has more detailed information about the email
  MIME structure:

  .. console::

     awk -F$'\t' '$2 == "WVVfjCeD7"' smtp_entities.log

  ::

    1302419719.561710	WVVfjCeD7	192.168.121.179	51158	192.168.121.176	25	1	-	122	text/plain	-	-	-
    1302419719.561710	WVVfjCeD7	192.168.121.179	51158	192.168.121.176	25	1	advice.pdf	38218	application/pdf	-	-	-
  
  In summary, ``lesharq@dchlaw.com`` sent an email to Mondo Cheeze
  containing a PDF attachment with the filename ``advice.pdf``.

.. exercise::

  Who appears to have authored the document? What are the two links contained
  in the document?

.. visible_solution::

  To answer this question, we need to look inside the document. This means we
  need to extract it from the trace and save it to disk. Bro does not do this
  by default, but we can easily do it with the File Analysis Framework as follows:

  Write the following script and call it `extract-file.bro <extract-file.bro>`_.

  .. code:: bro

    global ext_map: table[string] of string = {
        ["application/x-dosexec"] = "exe",
        ["application/pdf"] = "pdf",
        ["text/plain"] = "txt",
        ["image/jpeg"] = "jpg",
        ["image/png"] = "png",
        ["text/html"] = "html",
    } &default ="";

    event file_new(f: fa_file)
        {
        if ( ! f?$mime_type || f$mime_type != "application/pdf" )
            return;

        local ext = "";

        if ( f?$mime_type )
            ext = ext_map[f$mime_type];

        local fname = fmt("%s-%s.%s", f$source, f$id, ext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
        }

  After running

  .. console::

     bro -r email.pcap extract-file.bro

  We now see a new file in the directory extract_files: 
  ``SMTP-FAhpVH1rNrOi4Mm9uf.pdf``

  Opening the PDF with our favorite PDF viewer, we find that **Sylvester B.
  LeSharq, Esq.** leaked the confidential document **advice.pdf**, which
  contains the two links http://bit.ly/gmTIIO and
  http://www.dairyconnection.com/faqs.jsp.

Part 4: YouTube Becomes NoTube
==============================
One of the competitive benefits that HBDairy provides to its employees is
on-the-job access to YouTube. Lately, many disgruntled employees have
complained that they have lost this benefit because their browsers report "page
could not be loaded" when they try to access YouTube.

.. exercise::

  Analyze the web traffic in the `notube.pcap`_ trace to find out how
  Synonymous disrupted the YouTube access.

.. visible_solution::

  We need to find traffic that relates to YouTube, i.e., the IP address of the
  corresponding TCP connections. To find the name-to-address mapping, we 
  inspect the DNS log after running with ``bro -r notube.pcap``:

  .. console::

     bro-cut query answers < dns.log | awk -F$'\t' '$1 ~ /youtube/' | less

  gives the output::

    ...
    www.youtube.com	74.125.224.68,74.125.224.67,74.125.224.76,74.125.224.64,youtube-ui.l.google.com,74.125.224.69,74.125.224.72,74.125.224.70,74.125.224.73,74.125.224.74,74.125.224.75,74.125.224.77,74.125.224.78,74.125.224.79,74.125.224.65,74.125.224.66,74.125.224.71
    v3.lscache6.c.youtube.com	173.194.25.46
    upload.youtube.com	74.125.53.117,74.125.53.116,yt-video-upload.l.google.com
    help.youtube.com	74.125.224.80,74.125.224.84,www.l.google.com,www.google.com,74.125.224.81,74.125.224.82,74.125.224.83
    s.youtube.com	74.125.224.68,74.125.224.67,74.125.224.76,74.125.224.64,74.125.224.69,74.125.224.72,74.125.224.74,74.125.224.75,74.125.224.70,74.125.224.7
    ...

  Looks like the YouTube content distribution network (CDN) uses addresses from
  the block 74.125.*. What about the TCP states of connections involving
  these addresses?

  .. console::

     bro-cut id.resp_h conn_state < conn.log \
        | awk -F$'\t' '$1  ~ /^74.125/ { print $2 }' \
        | sort \
        | uniq -c

  lists connection state totals::

       6 OTH
     376 REJ
      27 RSTO
      42 RSTOS0
       5 RSTR
     143 S0
      27 S1
       2 S2
      13 S3
     214 SF
     128 SH
  
  Yikes, 376 failing connections that receive RST packet after the initial SYN
  (``REJ``)! A plausible explanation is that an attacker injected these RSTs
  after having observed a connection request to a YouTube IP address.

.. exercise::

  How much downtime did this result in?

.. visible_solution::

  To obtain a coarse estimate, we examine the first and last timestamp of the
  sequence of rejected connections:

  .. console::

     bro-cut id.resp_h conn_state ts < conn.log \
        | awk -F$'\t' '$1  ~ /^74.125/ && $2 == "REJ" { print $3 }' \
        | sort \
        | head -n 1

  ::

    1258409589.906464

  .. console::

     bro-cut id.resp_h conn_state ts < conn.log \
        | awk -F$'\t' '$1  ~ /^74.125/ && $2 == "REJ" { print $3 }' \
        | sort \
        | tail -n 1

  ::

    1258411809.009357

  .. console::

     echo "1258411809.009357-1258409589.906464" | bc

  ::

    2219.102893

  Thus, we get a downtime estimate of 2,219 seconds (roughly 37 minutes). To
  make sure this is a sound estimate (and not multiple separate RST injection
  attacks), we look more closely at the occurrences of the rejected
  connections:

  .. image:: youtube-dos.png

  This plot has a point for each rejected connection, with time starting at the
  first such connection. We observe that such connections never had more than 3
  minutes (180 seconds) between them, a small amount relative to the total
  downtime of 37 minutes, so we conclude that the above downtime estimate
  appears plausible.

.. exercise::
  Who were the poor victims of the outage?

.. visible_solution::

  .. console::

     bro-cut id.resp_h conn_state id.orig_h < conn.log \
        | awk -F$'\t' '$1  ~ /^74.125/ && $2 == "REJ" { print $3 }' \
        | sort | uniq -c

  ::

     176 192.168.121.147
      64 192.168.121.148
      38 192.168.121.149
      98 192.168.121.150

Part 5: The Mysterious DairyStock Transaction
=============================================
DairyStock is a stock management web application favored by HBDairy employees
that allows registered users to buy and sell stocks and transfer them to each
other. Synonymous denounces its use as an example of HBDairy's ineptitude when
dealing with Internet security issues, and states that as a demonstration they
arranged to introduce a bogus transaction for a "modest" sum of money.

.. exercise::

  Examine the traffic in the `dairystock.pcap`_ trace to find the
  unauthorized transfer Synonymous refers to. Sketch the attacker's steps.

.. visible_solution::

  This exercise involves looking at transactions of a web application, which
  likely implemented as HTTP POST requests. After running Bro with ``bro -r
  dairystock.pcap``, let's investigate a few relevant requests:

  .. console::

     bro-cut id.orig_h id.orig_p id.resp_h method host uri < http.log \
        | awk -F$'\t' '$4 == "POST" && $5 ~ /dairy/ { print $1, $2, $3, $5, $6 }'

  ::

    192.168.121.147 48205 85.47.63.142 www.dairystock.com /index.php
    192.168.121.177 53796 85.47.63.142 www.dairystock.com /transfer.php
    192.168.121.184 56436 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.167 33447 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.157 51135 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.147 48207 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.177 53796 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.157 51136 85.47.63.142 www.dairystock.com /stock.php
    192.168.121.167 33448 85.47.63.142 www.dairystock.com /transfer.php
    192.168.121.157 51137 85.47.63.142 www.dairystock.com /transfer.php
    192.168.121.184 56469 85.47.63.142 www.dairystock.com /transfer.php

  The page ``transfer.php`` looks telling. Let's peek into the HTTP body to
  get an understanding of what has been sent to ``www.dairystock.com``. To
  this end, we extract the TCP contents of corresponding connections by
  writing a little script, let's call it ``extract.bro``:

  .. code:: bro

    @load base/protocols/http

    event connection_established(c: connection)
    	{
    		if ( (c$id$orig_h == 192.168.121.147 || 
    		      c$id$orig_h == 192.168.121.157 ||
    		      c$id$orig_h == 192.168.121.167 ||
    		      c$id$orig_h == 192.168.121.177 ||
    		      c$id$orig_h == 192.168.121.184) &&
    		     c$id$resp_h == 85.47.63.142 )
    			{
    			c$extract_orig = T;
    			c$extract_resp = T;
    			}
    	}

  After running the script via ``bro -r dairystock.pcap extract.bro``, we see
  a bunch of files named ``contents_192.168.121_*.dat`` in our directory. The
  connections involving ``transfer.php`` have source ports 33448, 51137, and
  56469. By browsing through the three originator payloads, we see several
  money transfers as part of the POST requests::

    dollars=37&recipient=mrmustard8362&submission=Send
    dollars=90&recipient=mrmustard8362&submission=Send
    dollars=100&recipient=synonymous6203&submission=Send

  There could be something fishy with the last transfer involving a Synonymous
  account; let's examine it in more detail
  (``contents_192.168.121.184:56469-85.47.63.142:80_orig.dat``)::

    POST /transfer.php HTTP/1.1
    Host: www.dairystock.com
    User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.16) Gecko/20110319 Firefox/3.6.16
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-us,en;q=0.5
    Accept-Encoding: gzip,deflate
    Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
    Keep-Alive: 115
    Connection: keep-alive
    Referer: http://www.playfivestars.com/
    Cookie: DollarLogin=YToyOntpOjA7czoxMjoiZmVsaWNpdHk1MDE2IjtpOjE7czozMjoiNWI2OWNhYzUxN2JiOTI2NjBlZTM1MDdmZTgwOGNlZGYiO30%3D
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 52

    dollars=100&recipient=synonymous6203&submission=Send

  A couple of things are worth investigating: first, the ``Referer`` header
  contains ``www.playfivestars.com``, which means that this POST request
  originated at a different site! This very possibly means that we are seeing
  a `cross-site request forgery (CSRF)`__ attack. Second, the cookie value can
  tell us something about the victim 192.168.121.184.

  __ http://en.wikipedia.org/wiki/Cross-site_request_forgery

  Let us look for the cookie value in the ``contents.*`` files by simply
  grepping for the value. Indeed, it shows up several times. Just by looking at
  the first file, we find that the same cookie value is used after a POST
  request with the HTTP body of::

    login_username=mrmustard8362&login_password=mrmustard&submit_login=Log+in

  Poor Mr. Mustard, you were probably the victim of this CSRF attack conducted
  by Synonymous. 

.. TODO. How do we get pop3 traffic into the basic Bro output to analyze the
  email that lead to the CSRF?
  .. exercise::
    What action triggered the transfer in the first place?
  .. visible_solution::
    We now look at how Mr. Mustard got to the malicious site
    ``www.playfivestars.com`` in the first place by checking other types of
    activity. 
