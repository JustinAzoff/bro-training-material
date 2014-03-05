==========================
Exercise: Handling Notices
==========================

.. class:: opening

   So now that you've got a general sense of what logs look like and how
   Bro produces them, the typical inclination is for a person to want to
   find something interesting to look at in them.  The good thing is
   that Bro, by default, does some analysis on traffic and can suggest
   potentially interesting network activity for you to investigate.
   These suggestions are what are known as "notices".

Part 1: The Notice Log
======================

Here, let's just run Bro on a network trace and see if it suggests
anything interesting to look at.  You'll need `ssh.pcap <http://www.bro.org/static/traces/ssh.pcap>`_
for all the rest of the exercises.

.. exercise::

   Run the command:

   .. console::

      bro -r ssh.pcap local

   to run Bro with a predefined set of ``policy/`` scripts loaded that
   makes for a similar configuration as running ``BroControl``
   out-of-the-box.  What high-level activity is suggested as interesting
   in the ``notice.log``?

.. visible_solution::

   The command:

   .. console::

      bro-cut note < notice.log

   shows output::

      SSH::Password_Guessing

   There was someone trying to brute-force their way into an SSH server.

Part 2: Basic Filtering of the Notice Log
=========================================

Now, let's start making some policy decisions regarding the notices
Bro conveniently supplied.

.. exercise::

   Take the `my_basic_policy.bro <my_basic_policy.bro>`_ code,
   and run:

   .. console::

      bro -r ssh.pcap local my_basic_policy.bro

   Look at the code you just supplied to Bro and then look for
   an additional log that Bro has generated, what's in it and how
   does it relate to the code?

.. visible_solution::

   Bro created a ``notice_alarm.log`` that now contains the
   ``SSH::Password_Guessing`` notice because
   `my_basic_policy.bro <my_basic_policy.bro>`_ made the decision
   that that type of notice was alarm-worthy.

.. note::

   We're currently defining notice policy in an extra Bro script
   so as to avoid accidentally corrupting results of future exercises,
   but normally it's typical to take what's in these scripts and put
   them directly in your ``local.bro`` or other scripts inside your
   ``$PREFIX/share/bro/site/`` installation directory.

Of course, there are also other convenience actions that can be taken
with notices, such as sending an email, but those are not demonstrable
in such contrived exercises, however we're about to witness the full
power allowed by the notice framework.

Part 3: More Advanced Notice Policy
===================================

What if grouping all types of a given notice is too rigid for you?
The answer is to define the notice policy more flexibly around what
you exactly need.

.. exercise::

   Take the `my_advanced_policy.bro <my_advanced_policy.bro>`_ code,
   and run:

   .. console::

      bro -r ssh.pcap local my_advanced_policy.bro

   Find out the purpose of the code by inspecting it and the
   ``notice_alarm.log``.

.. visible_solution::

   The purpose of this bit of advanced policy is to only trigger an alarm
   action when a particular ``SSH::Login`` notice belongs to a particular
   group of servers (as seen in the ``watched_servers`` variable).

.. exercise::

   Modify `my_advanced_policy.bro <my_advanced_policy.bro>`_ to now
   alarm on the last remaining SSH server which Bro recognized as having
   been logged into.

.. visible_solution::

   The last remaining SSH service is ``172.16.238.129`` and can be
   appended to the ongoing list in ``watched_servers`` in
   `my_advanced_policy.bro <my_advanced_policy.bro>`_.

Part 4: Extra Credit
====================

So we've seen that the actions associated with any given Bro notice
are fully customizable since you can define arbitrary functions in
your notice policy.  And knowing that, you can do all sorts of neat
things.

.. exercise::

   The `my_extracredit_policy.bro <my_extracredit_policy.bro>`_
   contains some notice policy code.  Determine what it does by
   looking at its code, running it through bro on the ``ssh.pcap``
   trace and looking at the resulting logs.

.. visible_solution::

   The extra credit notice policy code accumulates IP addresses that
   have been attempting SSH brute-forcing over a 24 hour window and
   promotes an ``SSH::Login`` notice to an alarm if any such brute-
   forcer successfully logs in to a server.
