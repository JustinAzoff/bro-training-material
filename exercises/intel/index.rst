
=============================
Bro Intel Framework Exercises
=============================

.. class:: opening

    Bro 2.2 includes an updated Intelligence framework
    for importing and matching intelligence data.  

For all of these exercises we'll be using the `exercise-traffic.pcap <http://www.bro.org/static/traces/exercise-traffic.pcap>`_ file.

.. exercise::

    First we are going to do an extremely simple case of loading some data and
    matching it. First we will create an intelligence file in Bro's
    intelligence format. Create a file named "intel-1.dat" with the following
    content. Keep in mind that **all** field separation is with literal tabs!
    Double check that you don't have spaces as separators.

    .. console::

      #fields	indicator	indicator_type	meta.source
      fetchback.com	Intel::DOMAIN	my_special_source
        
    The next step will obviously be to load this data into Bro which is done as
    a configuration option. Put the following script into the same directory as
    your "intel-1.dat" file and call it "intel-1.bro".
  
    .. code:: bro
  
        @load frameworks/intel/seen

        redef Intel::read_files += {
          fmt("%s/intel-1.dat", @DIR)
        };

    Now run.
    
    .. console::

        bro -r exercise-traffic.pcap intel-1.bro

    There should be no output in the terminal but there should be some content
    in a file named "intel.log".  Take a look at that file.

.. visible_solution::

    ::

        #separator \x09
        #set_separator  ,
        #empty_field    (empty)
        #unset_field    -
        #path   intel
        #open   2013-08-08-08-13-38
        #fields ts  uid id.orig_h   id.orig_p   id.resp_h   id.resp_p   seen.indicator  seen.indicator_type seen.where  sources
        #types  time    string  addr    port    addr    port    string  enum    enum    table[string]
        1258565309.806483   2sNYDGH3Ue  192.168.1.103   53856   192.168.1.1 53  fetchback.com   Intel::DOMAIN   DNS::IN_REQUEST my_special_source
        1258565310.094800   2xB5SpwV6f2 192.168.1.103   1788    69.71.52.52 80  fetchback.com   Intel::DOMAIN   HTTP::IN_HOST_HEADER    my_special_source
        #close  2013-08-08-08-13-41

    You can see that there were two hits on the fetchback.com domain name that we 
    listed as our intelligence.  Once in a DNS request and once in an HTTP Host header.

    That's the very basic functionality of the intel framework, now we can move on
    to an example (but still useful!) extension script that ships with Bro.

.. exercise::

    It's very possible that hits on intelligence could be something that you want
    turned into a notice even though the basic intel framework does not provide
    that functionality.  This is an example of data driven notice creation with 
    the "do_notice.bro" script that is included with Bro.  Create a new Bro script
    named "intel-2.bro" with the following script.

    .. code:: bro


        @load frameworks/intel/seen
        @load frameworks/intel/do_notice

        redef Intel::read_files += {
            fmt("%s/intel-2.dat", @DIR)
        };

    Now we need to create a paired intelligence file.  Create "intel-2.dat".

    .. code::

        #fields indicator   indicator_type  meta.source meta.do_notice
        fetchback.com   Intel::DOMAIN   my_special_source   T

    The only difference from the previous intelligence file is the do_notice
    column.  Now run.

    .. console::

        bro -r exercise-traffic.pcap intel-2.bro

.. visible_solution::

    The intel.log file will look exactly the same as before, but now there will
    be a notice in notice.log.

    ::

        #separator \x09
        #set_separator  ,
        #empty_field    (empty)
        #unset_field    -
        #path   notice
        #open   2013-08-08-08-27-58
        #fields ts  uid id.orig_h   id.orig_p   id.resp_h   id.resp_p   fuid    file_mime_type  file_desc   proto   note    msg sub src dst p   n   peer_descractions   suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude    remote_location.longitude
        #types  time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  table[enum] interval    bool    string  string  string  double  double
        1258565309.806483   Q4ab9p92mk4 192.168.1.103   53856   192.168.1.1 53  -   -   -   udp Intel::Notice   Intel hit on fetchback.com at DNS::IN_REQUEST   fetchback.com   192.168.1.103   192.168.1.1 53  -   bro Notice::ACTION_LOG  3600.000000 F   -   -   -   -   -
        1258565310.094800   Ej4iLLzwPy3 192.168.1.103   1788    69.71.52.52 80  -   -   -   tcp Intel::Notice   Intel hit on fetchback.com at HTTP::IN_HOST_HEADER  fetchback.com   192.168.1.103   69.71.52.52 80  -   bro Notice::ACTION_LOG  3600.000000 F   -   -   -   -   -
        #close  2013-08-08-08-28-02

.. exercise::

    Perhaps you decided though that seeing hits on your intelligence in certain
    locations is not actually what you wanted.  The same "do_notice" script
    has the ability to limit your notices by the location that the intelligence
    was seen.  Create a new "intel-3.dat" file that shows you are only interested
    in matching the intelligence if it was seen in the host header.

    .. code::

        #fields indicator   indicator_type  meta.source meta.do_notice  meta.if_in
        fetchback.com   Intel::DOMAIN   my_special_source   T   HTTP::IN_HOST_HEADER

    The only change that needs to happen in the script is to load the new intelligence
    file, but we will include the new script here.  Name it "intel-3.bro".

    .. code::

        @load frameworks/intel/seen
        @load frameworks/intel/do_notice

        redef Intel::read_files += {
            fmt("%s/intel-3.dat", @DIR)
        };

    Now run this script:

    .. console::

        bro -r exercise-traffic.pcap intel-3.bro

.. visible_solution::

    Again, this had no output in the console.  If you
    look at the notice.log now though you will see the difference.  The notice
    only happened when the name was seen in the HTTP host header.  Keep in mind
    though that the DNS lookup hit was still logged into intel.log.

    ::

        #separator \x09
        #set_separator  ,
        #empty_field    (empty)
        #unset_field    -
        #path   notice
        #open   2013-08-08-08-43-53
        #fields ts  uid id.orig_h   id.orig_p   id.resp_h   id.resp_p   fuid    file_mime_type  file_desc   proto   note    msg sub src dst p   n   peer_descractions   suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude    remote_location.longitude
        #types  time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  table[enum] interval    bool    string  string  string  double  double
        1258565310.094800   3nOXjDAi7w7 192.168.1.103   1788    69.71.52.52 80  -   -   -   tcp Intel::Notice   Intel hit on fetchback.com at HTTP::IN_HOST_HEADER  fetchback.com   192.168.1.103   69.71.52.52 80  -   bro Notice::ACTION_LOG  3600.000000 F   -   -   -   -   -
        #close  2013-08-08-08-43-56
