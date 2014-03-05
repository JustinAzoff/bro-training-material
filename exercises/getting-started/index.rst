=========================
Exercise: Getting Started
=========================

Note: In this exercise, "<PREFIX>" represents the Bro install directory.  Also,
if you already have Bro compiled and installed on your machine, then
skip to step 5 below.

1. **Configure Bro source code.**

   In order to build Bro, there are some other packages that must first be
   installed on your system.
   For RPM/RedHat-based Linux, you need these packages:
   cmake, make, gcc, gcc-c++, flex, bison, libpcap-devel, openssl-devel,
   python-devel, and swig.  For DEB/Debian-based Linux you need:
   cmake, make, gcc, g++, flex, bison, libpcap-dev, libssl-dev, python-dev,
   and swig.  For FreeBSD you need: cmake, swig, bison, and python.
   For Mac OS X you need: cmake and swig.

   There are some optional dependencies (you can build Bro without these,
   but if available they provide additional functionality).  For 
   RPM/RedHat-based Linux, these are: zlib-devel, file-devel, GeoIP-devel,
   sendmail, and libcap.  For DEB/Debian-based Linux, these are: zlib1g-dev,
   libmagic-dev, libgeoip-dev, sendmail, and libcap2-bin.  For FreeBSD 
   these are: GeoIP.  For Mac OS X, these are: libmagic and libGeoIP.

   Next, you need to "cd" into the top-level Bro source directory where
   the "configure" script is located.

   By default, Bro will be installed into "/usr/local/bro", but this normally
   requires superuser privileges, so for this exercise we will choose
   our own install path (if you follow this example, then substitute "<PREFIX>"
   throughout the rest of this exercise with "~/install"):

   .. console::

      ./configure --prefix=~/install

   If the last line of output contains the text "Build files have
   been written to:", then configuration should be complete.  However,
   if you see an error, then check that you have all required dependencies
   and try again.

2. **Compile Bro.**

   Next, compile the Bro source:

   .. console::

      make

   After a few minutes, it should complete successfully.

3. **Install Bro.**

   Next, install Bro:

   .. console::

      make install

   Bro should now be installed.

4. **Set privileges on Bro (Linux only).**

   If you are not running Bro on Linux, or if you want to run Bro as the "root"
   user, then skip this step.

   Bro needs certain privileges to capture network traffic, but it
   does not need all privileges of the "root" user.  On Linux, you can
   run this command to set the necessary privileges (if you don't do
   this, then you would usually need to run Bro as the "root" user):

   .. console::

      sudo setcap cap_net_raw,cap_net_admin=eip <PREFIX>/bin/bro

5. **Update PATH.**

   To test that everything is setup correctly, the following command
   should report the installed version of Bro (should be "2.0-beta" or newer):

   .. console::

      bro -v

   If the correct version of Bro is not shown, then update your PATH
   environment variable and try again:

   .. console::

      export PATH=<PREFIX>/bin:$PATH
      bro -v

6. **Run BroControl.**

   BroControl is an interactive shell that is a convenient way to manage Bro.

   Before using BroControl, you must determine which network interface Bro
   should monitor.  If it is not "eth0", then you will need to edit
   the "<PREFIX>/etc/node.cfg" file, and change the line
   "interface=eth0" with the correct network interface for Bro to monitor.

   Also, normally you should edit the "<PREFIX>/etc/broctl.cfg" file and make
   any needed changes (such as changing the "MailTo" email address), but for
   this exercise this is not necessary.

   Start up BroControl:

   .. console::

      broctl

   The first time that you run BroControl, you must install the BroControl
   configuration::

   [BroControl] > install

   Next, start an instance of Bro::

   [BroControl] > start

   You can check the status of Bro (make sure you see the word "running" under
   the "Status" column)::

   [BroControl] > status

   If you want to stop Bro before exiting BroControl, you must issue the
   "stop" command::

   [BroControl] > stop

   Check to see that Bro is no longer running (you should see the word
   "stopped" under the "Status" column)::

   [BroControl] > status

   There are many more commands available in BroControl.  To see a list,
   use the "help" command::

   [BroControl] > help

   When done using BroControl, you can exit using the "exit" or "quit"
   commands::

   [BroControl] > exit

7. **Look at Bro log files.**

   If you look in the "<PREFIX>/logs" directory, you should see a subdirectory
   named with today's date (in the form YYYY-MM-DD).  In that subdirectory,
   you should see various log files (all of them are gzipped) that were copied
   to this directory when Bro was stopped.  To see what a log file looks
   like, choose one (here we use the "dns" log file) and run this command:

   .. console::

      gunzip -dc <PREFIX>/logs/2011-11-08/dns.* | less

8. **Run Bro directly.**

   If you don't want to use BroControl, then you can run Bro directly.
   When you run Bro directly, it creates its log files in the current
   working directory.  Therefore, it is a good idea to create a temporary
   directory so that you can more easily see which files
   are generated by Bro:

   .. console::

      mkdir brotmp
      cd brotmp

   Bro can capture live network traffic, or it can read a packet 
   capture (pcap) file.  In this exercise, we will read a pcap file
   `dns-session.pcap <http://www.bro.org/static/traces/dns-session.pcap>`_:

   .. console::

      bro -r dns-session.pcap

   You should see a variety of log files produced by Bro.  These
   logs are not gzipped, so you can look at them directly.

   You can delete these log files when you are done.

