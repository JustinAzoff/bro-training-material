.. _faf-exercise.pcap: http://www.bro.org/static/traces/faf-exercise.pcap

.. _file_new: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_new
.. _file_over_new_connection: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_over_new_connection
.. _file_timeout: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_timeout
.. _file_gap: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_gap
.. _file_state_remove: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_state_remove
.. _file_hash: http://bro.org/sphinx-git/scripts/base/bif/event.bif.html?highlight=file_new#id-file_hash

===========================
Bro File Analysis Exercises
===========================

.. class:: opening

    The file analysis framework (FAF) is a new feature being introduced
    with Bro 2.2 that provides a generalized presentation of
    file-related information.  A goal of Bro's file analysis is to
    borrow patterns/idioms from network protocol analysis, but do so in
    a way that's independent from the actual network connections that
    transport the files.  That is, programming and configuring Bro to
    analyze files should feel familiar to analyzing network connections
    in some aspects, but you don't have to care if a file is sent over
    HTTP, FTP, SMTP, etc. unless you want to.

Part 1: The Default
===================

For all the exercises, we'll be using the `faf-exercise.pcap`_ trace, so
download it first.

.. exercise::

    Run the following command to have Bro perform the default analysis
    for any files it finds within the trace file:

    .. console::

        bro -r faf-exercise.pcap

    And examine the contents of the ``files.log`` that is generated.

    .. console::

        cat files.log

.. visible_solution::

    ::

        #separator \x09
        #set_separator  ,
        #empty_field    (empty)
        #unset_field    -
        #path   files
        #open   2013-08-05-12-54-47
        #fields ts  fuid    tx_hosts    rx_hosts    conn_uids   source  depth   analyzers   mime_type   filename    duration    local_orig  is_orig seen_bytes  total_bytes missing_bytes   overflow_bytes  timedout    parent_fuid md5 sha1    sha256  extracted
        #types  time    string  table[addr] table[addr] table[string]   string  count   table[string]   string  string  interval    bool    bool    count   count   count   count   bool    string  string  string  string  string
        1258544215.370560   jx7vkrOqivf 77.67.44.206    192.168.1.104   vH67tZXVZ97 HTTP    0   (empty) text/plain  -   0.000011    -   3306    3306    0   0   F   -   -   -   -   -
        1258544216.720958   eTHOYU8rFri 77.67.44.206    192.168.1.104   kyGUR5boAtj HTTP    0   (empty) text/html   -   0.000000    -   238 238 0   0   F   -   -   -   -   -
        1258544216.937570   soLFLv9ei91 198.189.255.75  192.168.1.104   ntncwjHInpi HTTP    0   (empty) application/x-dosexec   -   0.062331    95323   95323   0   0   F   -   -   -   -   -
        1258544217.346549   NIbcnAtmMi8 77.67.44.206    192.168.1.104   i4CaXZPj1g6 HTTP    0   (empty) text/html   -   0.000000    -   239 239 0   0   F   -   -   -   -   -
        1258544217.374786   RoBkm8ENUW9 198.189.255.75  192.168.1.104   ZZ4MAjQYOFa HTTP    0   (empty) application/x-dosexec   -   0.030731    30540   30540   0   0   F   -   -   -   -   -
        1258544217.752541   FnnATnkHnv  77.67.44.206    192.168.1.104   MVDh74qVSFh HTTP    0   (empty) text/html   -   0.000000    -   236 236 0   0   F   -   -   -   -   -
        1258544217.781285   p3g3uNM55Nb 198.189.255.75  192.168.1.104   PIY3GyBl6pl HTTP    0   (empty) application/x-dosexec   -   0.000027    4989    4989    0   0   F   -   -   -   -   -
        1258544218.127308   5t6RQz8HPJ4 77.67.44.206    192.168.1.104   HRqePVFf66a HTTP    0   (empty) text/html   -   0.000000    -   239 239 0   0   F   -   -   -   -   -
        1258544218.156042   UxRTi5ccYTg 198.189.255.75  192.168.1.104   uJp4NigCYA5 HTTP    0   (empty) application/x-dosexec   -   0.000000    1411    1411    0   0   F   -   -   -   -   -
        1258562477.772691   Hlo3DRaL1B5 63.245.221.11   192.168.1.104   l6aHHdOrJEk HTTP    0   (empty) text/html   -   0.000013    -   1911    -   0   0   F   -   -   -   -   -
        1258562478.199620   ozXYTPDLH2f 63.245.221.11   192.168.1.104   l6aHHdOrJEk HTTP    0   (empty) image/jpeg  -   0.000000    -   418 418 0   0   F   -   -   -   -   -
        1258562478.329343   gQh2CHCWc43 63.245.221.11   192.168.1.104   ssXPIKeYbQg HTTP    0   (empty) image/png   -   0.067702    -   3804    3804    0   0   F   -   -   -   -   -
        1258562478.322408   k50x70YL8Pi 63.245.221.11   192.168.1.104   l6aHHdOrJEk HTTP    0   (empty) image/jpeg  -   0.131609    -   12591   12591   0   0   F   -   -   -   -   -
        1258574141.253078   7qRbBI6ptod 192.168.1.1 192.168.1.104   IelaVugI6A1 SMTP    1   (empty) text/plain  -   0.000000    -   482 -   0   0   F   -   -   -   -   -
        1258577484.801527   s6Nww0kivWb 192.168.1.1 192.168.1.104   9bHIKr3p26c SMTP    1   (empty) text/plain  -   0.000000    -   215 -   0   0   F   -   -   -   -   -
        1258577841.064438   Y4nz2mQiBtc 192.168.1.1 192.168.1.104   QDIrZlJRfPf SMTP    1   (empty) text/plain  -   0.000000    -   124 -   0   0   F   -   -   -   -   -
        1258587444.924450   oqqelaZiZz7 198.189.255.75  192.168.1.104   1WtNHsVNwO5 HTTP    0   (empty) application/x-dosexec   -   0.706064    95423   95423   0   0   F   -   -   -   -   -
        1258587446.016265   sNsA0UgDha5 198.189.255.75  192.168.1.104   KdtQbILFsMk HTTP    0   (empty) application/x-dosexec   -   0.023266    21359   21359   0   0   F   -   -   -   -   -
        1258594163.644682   cRBCU4djxGj 143.166.11.10   192.168.1.105   QBAbj8Slzz7 FTP_DATA    0   (empty) application/x-dosexec   -   21.704438   -   F   4255056 -   0   0   T   -   -   -
        #close  2013-08-05-12-54-47

.. exercise::

    Compare and contrast this log file with the ``conn.log``, which contains
    a summary/overview of analysis of each network connection.

.. visible_solution::

    Similarities:

        * Each file and each connection is assigned a "uid" string
          which is helpful for connecting it to the activity in other
          log files.  E.g. ``files.log`` references the uid of the
          connection(s) over which is was transferred.
        * Basic meta-data tracking of first time seen, number of bytes
          transferred, duration, etc.

    Differences:

        * Connections can be uniquely identified by the 5-tuple of
          (orig host, resp host, orig port, resp port, proto), but
          files must rely on the uid or md5/sha1/sha256 fields for
          uniqueness testing (file hashes are covered in a later
          exercise).

Part 2: Add File Hashing
========================

By default, file hashes aren't calculated, but turning that on is simple.

.. exercise::

    Run this command:

    .. console::

        bro -r faf-exercise.pcap frameworks/files/hash-all-files.bro

    Now re-examine to ``files.log`` to verify that MD5 and SHA1
    hashes are calculated for each file.

.. exercise::

    The "frameworks/files/hash-all-files.bro" referenced in the previous
    command is telling bro to now load a `specific script
    <http://bro.org/sphinx-git/_downloads/hash-all-files.bro>`_ that's
    distributed with Bro, but not loaded by default.  And this new
    script that's loaded has the code to turn on file hashing for MD5
    and SHA1.  Now write your own script that tells Bro to also do
    SHA256 hashing.  The reference documentation for the
    `Files::add_analyzer
    <http://bro.org/sphinx-git/scripts/base/frameworks/files/main.html#id-Files::add_analyzer>`_
    function may be helpful.

.. visible_solution::

    Write a new `all-hashes-all-files.bro <all-hashes-all-files.bro>`_ with the following content:

    .. code:: bro

        event file_new(f: fa_file)
            {
            Files::add_analyzer(f, Files::ANALYZER_MD5);
            Files::add_analyzer(f, Files::ANALYZER_SHA1);
            Files::add_analyzer(f, Files::ANALYZER_SHA256);
            }

    Then run the following command

    .. console::

        bro -r faf-exercise.pcap all-hashes-all-files.bro

Part 3: Extract All The Files
=============================

To have Bro extract files from the network stream and save them to the
local disk for later use, there's an "extraction" analyzer specifically
designed to do that and just needs to be told which file to extract.

.. exercise::

    Copy this Bro script and save it in a local file, say
    "extract-all.bro":

    .. code:: bro

        global ext_map: table[string] of string = {
            ["application/x-dosexec"] = "exe",
            ["text/plain"] = "txt",
            ["image/jpeg"] = "jpg",
            ["image/png"] = "png",
            ["text/html"] = "html",
        } &default ="";

        event file_new(f: fa_file)
            {
            local ext = "";

            if ( f?$mime_type )
                ext = ext_map[f$mime_type];

            local fname = fmt("%s-%s.%s", f$source, f$id, ext);
            Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
            }

    Now run the command:

    .. console::

        bro -r faf-exercise.pcap extract-all.bro

    Examine the extracted files in the new ``extract_files/``
    subdirectory and determine how "Pat" likes his coffee.

.. visible_solution::

    .. console::

        cat extract_files/SMTP-7qRbBI6ptod.txt

    ::

        Pat McGoo wrote:
        > Charlie, Terry,
        >  
        >     just checking up on your preferences for coffee - jo is going 
        > shopping tomorrow, let us know what you want.
        >  
        > Jo, I like my coffee cinnamon apple flavor with just a whisper of 
        > cream - be sure to get the heavy whipping cream, NOT the half and 
        > half.  See if they have any of those nice pumpkin muffins, too.
        >  
        > Pat
        Can I just get hot chocolate instead?  I like the little sprinkles and 
        whipped cream with it.

.. exercise::

    What email client did Pat appear to use to send his coffee preference?

.. visible_solution::

    .. console::

        grep 7qRbBI6ptod smtp.log

    ::

        1258574141.215730   ZIUKV7xsQe  192.168.1.104   1572    192.168.1.1 25  1   [192.168.1.104] <charlie@m57.biz>   <pat@m57.biz>   Wed, 18 Nov 2009 11:58:15 -0800 Charlie <charlie@m57.biz>   Pat McGoo <pat@m57.biz><4B0451D7.6080508@m57.biz>   <98CC40FE46EA4F9CB82A95B0E7634C9A@m57pat>   Re: COFFEE  -   -   -   250 2.0.0 Ok: queued as 3B2C92AF471 192.168.1.1,192.168.1.104   Thunderbird 2.0.0.23 (Windows/20090812) 7qRbBI6ptod

    Looks like Thunderbird.

Part 4: Tone It Down a Bit
==========================

Just because Bro can analyze and extract all files it sees on the
network doesn't mean you have to.  This is where Bro being a programming
language starts to get helpful -- it's easy to change the analysis
depending on context available at runtime.

.. exercise::

    Let's say we don't care to have any email such as Pat's coffee
    preferences archived to disk.  Alter the ``extract-all.bro`` script
    used in the previous part to only extract executable files by adding
    a condition inside the body of the ``file_new`` event.

.. visible_solution::

    Write a new `extract-all2.bro <extract-all2.bro>`_ with the following content:

    .. code:: bro

        global ext_map: table[string] of string = {
            ["application/x-dosexec"] = "exe",
            ["text/plain"] = "txt",
            ["image/jpeg"] = "jpg",
            ["image/png"] = "png",
            ["text/html"] = "html",
        } &default ="";

        event file_new(f: fa_file)
            {
            if ( ! f?$mime_type || f$mime_type != "application/x-dosexec" )
                return;

            local ext = "";

            if ( f?$mime_type )
                ext = ext_map[f$mime_type];

            local fname = fmt("%s-%s.%s", f$source, f$id, ext);
            Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
            }

    Now run the command:

    .. console::

        bro -r faf-exercise.pcap extract-all2.bro

Part 5: Other File Events/Info To Program Around
================================================

So far we've only seen the use of `file_new`_ as the entry point for
file analysis programming, but there's also several others that may be
useful: `file_over_new_connection`_, `file_timeout`_, `file_gap`_,
`file_state_remove`_, and `file_hash`_.  For example, in order to
determine if Bro saw all the bits in a file, that check can be done in
`file_state_remove`_ for protocols/connections that advertised the total
file size (some may not do that).

.. exercise::

    Write a script to determine the average file size served by host
    ``198.189.255.75`` in `faf-exercise.pcap`_.

.. visible_solution::

    Write a new `file-avg.bro <file-avg.bro>`_ with the following content:

    .. code:: bro

        @load base/frameworks/files

        global file_count = 0;
        global file_bytes = 0;
        const target_server = 198.189.255.75 &redef;

        event file_state_remove(f: fa_file)
            {
            if ( target_server !in f$info$tx_hosts )
                return;

            ++file_count;
            file_bytes += f$info$seen_bytes;
            }

        event bro_done()
            {
            local avg = file_count > 0 ? file_bytes / file_count : 0;    print fmt("Avg. file size served by %s = %d bytes", target_server, avg);
            }

    .. console::

        bro -r faf-exercise.pcap file-avg.bro

    ::

        Avg. file size served by 198.189.255.75 = 41507 bytes

Part 6: Next Steps
==================

The amount of different file analysis currently offered by the new
framework by itself is quite modest, but the scripting language of Bro
lends itself well to creating tools on top of it that integrate with
external services that may help determine if a file seen on the network
is of concern.  One such example of this is the integration with `Team
Cymru's Malware Hash Registry
<https://www.team-cymru.org/Services/MHR/>`_ that's enabled simply by
loading the `frameworks/files/detect-MHR.bro
<http://bro.org/sphinx-git/scripts/policy/frameworks/files/detect-MHR.html>`_
script.  You shouldn't find anything that hits in the trace file used
for the previous exercises, but maybe you've got some other network
traffic of your own you'd like check for malware?
