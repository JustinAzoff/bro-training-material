============================================
Exercise: Extending a Script’s Functionality
============================================

.. class:: opening

   TLS/SSL has been a hot topic lately and Bro's TLS/SSL analysis
   scripts offer a strong base for extending and customizing analysis
   to suit one's needs.  The following exercises all demonstrate the
   types of things Bro's ``base`` scripts can be extended to do.

Part 1: Customize Which Certificates to Trust
=============================================

By default, Bro only knows how to trust the same CA root certificates as
used by Mozilla.  In these exercises, we'll show how to add trust to
custom certificates.

.. exercise:: First figure out how to get Bro to perform certificate
   validation on the TLS exchange found in the `ssl-root-cert.pcap
   <http://www.bro.org/static/traces/ssl-root-cert.pcap>`_ packet capture file, by loading a script found
   in the ``scripts/policy/protocols/ssl`` directory (or if you're
   looking in the Bro installation directory, the ``scripts/`` root is
   actually ``$prefix/share/bro``).  After running Bro loaded with that
   file on the pcap trace, how does Bro indicate through the log files
   that the server's certificate is invalid?

.. visible_solution::
   .. console::

      bro -r ssl-root-cert.pcap protocols/ssl/validate-certs

   ``ssl.log`` and ``notice.log`` should report a self signed
   certificate.

Delete your logs at this point (``rm *.log``) so that we start fresh for
the next exercise.

.. exercise:: Now get Bro to trust the server's certificate, which can
   be found in a suitable format that Bro understands in `cert-hexesc.der
   <cert-hexesc.der>`_.  You'll have to redefine the same script
   variable that was originally used to define the Mozilla trust roots.

.. visible_solution::
   First, create a `mytrust.bro <mytrust.bro>`_, then run bro:

   .. console::

      bro -r ssl-root-cert.pcap protocols/ssl/validate-certs mytrust.bro

   And ``ssl.log`` should report ``ok`` for the validation status.

.. exercise:: As an optional task, try to figure out how to derive
   the hex-escaped version of the certificate in `cert-hexesc.der
   <cert-hexesc.der>`_ from a typical DER encoded certificate in
   `cert.der <cert.der>`_.  This will require use of the ``openssl``
   command-line client and maybe other command-line-fu (don't spend too
   long if you get stuck).

.. visible_solution::
   Here's one solution:

   .. console::

      openssl x509 -in cert.der -inform DER -outform DER | hexdump -v -e '1/1 "\\\x"' -e '1/1 "%02X"' > my-cert-hexesc.der

   Let us know if you have an easier way!

Part 2: Log More Than Just Server Cert. Subject
===============================================

Bro currently just logs the subject of SSL server certificates,
but in this exercise, we'll see how to extend what a script logs
to also include the issuer of certificates.

.. exercise:: Write a script that extends the SSL logging to include
   the issuer of the server's certificate offered in the exchange in the
   `ssl-nonroot-cert.pcap <http://www.bro.org/static/traces/ssl-nonroot-cert.pcap>`_ trace file.  You'll
   need to redefine the SSL logging unit (``SSL::Info``) and handle
   ``x509_certificate`` event for this exercise.  What are the subject
   and issuer of the server's certificate?

.. visible_solution::
   See `rootissuer.bro <rootissuer.bro>`_ for the code.

   After running it on the trace file like

   .. console::

      bro -r ssl-nonroot-cert.pcap rootissuer.bro

   and looking in the ``ssl.log``, the subject can be seen as
   ``CN=Brostradamus,OU=CSD,O=NCSA,ST=IL,C=US`` and the issuer as
   ``CN=Brometheus,OU=CSD,O=NCSA,ST=IL,C=US``.

Part 3: Using the Notice Framework
==================================

Most site policies will probably want to know a little about what
SSL/TLS clients/servers are on their network such as the version
and cipher suite they're negotiating so that they can detect weak
or old/outdated software.  Bro can help.

.. exercise:: Write a script that adds a notice type for SSLv2 clients
   and then proceeds to generate a notice of that type whenever Bro sees
   a client offering the ability to negotiate that protocol.  An example
   of such a transaction can be found in `sslv2.pcap <http://www.bro.org/static/traces/sslv2.pcap>`_.  By
   default, your generated notices should be observable in ``notice.log``.

.. visible_solution::
   See `ssl2_notice.bro <ssl2_notice.bro>`_ for an example, which
   should generate output in ``notice.log`` for any clients offering
   SSLv2 compatible hellos.  From here, the full functionality of the
   notice framework can be used to transform the logged notice into even
   more actions such as an email to the Bro administrator.
