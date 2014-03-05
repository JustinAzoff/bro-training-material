================================
Exercise: Bro Programming Primer
================================

.. class:: opening

   Bro contains a programming language designed specifically to be able
   to represent network-related abstractions (e.g. addresses and ports)
   and as such offers a great deal of functionality and flexibility in
   terms of helping you accomplish your network-monitoring goals.  The
   following exercises all explore using Bro's scripting language.

Part 1: String Manipulation and Patterns
========================================

The ``string`` type holds character-string values that are used to
represent and manipulate text, so let's learn to do that since those
kinds of tasks are likely to show up later.

.. exercise::
   All the exercises for this part are described within the
   `part1.bro <part1.bro>`_ bro script, to which you'll add
   your own code.  It can be run using Bro at any time to check your
   progress:

   .. console:: bro part1.bro

.. visible_solution::
   A complete solution is found in `part1-solutions.bro
   <part1-solutions.bro>`_.  You can look at it for hints on how
   to solve a specific exercise, or run it to see the expected output:

   .. console:: bro part1-solutions.bro

Part 2: Tables and Sets and Vectors
===================================

There are several container/collection types that are commonly used
in Bro for accumulating/storing state information and this tutorial
will go over the basic usage of each: ``table``, ``set``, and ``vector``.

.. exercise::
   All exercises are described within `part2.bro
   <part2.bro>`_.  Follow the tasks that the comments set out and
   add your own code to it.  Run it using Bro at any time to check/test
   progress:

   .. console:: bro part2.bro

.. visible_solution::
   A completed solution is found in `part2-solutions.bro
   <part2-solutions.bro>`_.  Look at it for hints or run it to
   see the expected output:

   .. console:: bro part2-solutions.bro

Part 3: Records and Functions
=============================

A ``record`` is a collection of values, with each having a name (referred to
as the record's ``fields``), and a type.  There's no restriction on allowed
types, which means they can contain other, nested ``record`` fields or even
``function`` types which are just procedural abstractions most programmers
are already familiar with, but will be described in this exercise.

.. exercise::
   All exercises are described within `part3.bro
   <part3.bro>`_.  Follow the tasks that the comments set out and
   add your own code to it.  Run it using Bro at any time to check/test
   progress:

   .. console:: bro part3.bro

.. visible_solution::
   A completed solution is found in `part3-solutions.bro
   <part3-solutions.bro>`_.  Look at it for hints or run it to
   see the expected output:

   .. console:: bro part3-solutions.bro

Part 4: Events
==============

Bro provides an event engine as the primary facilitator of network
analysis.  And the way a Bro programmer (Brogrammer) can tap into
the engine is at the scripting-layer through event handlers, so this
part of the exercise looks at how to do that.

.. exercise::
   All exercises are described within `part4.bro
   <part4.bro>`_.  You'll also need `browse.pcap <http://www.bro.org/static/traces/browse.pcap>`_.
   Follow the tasks that the comments set out and
   add your own code to it.  Run it using Bro at any time to check/test
   progress:

   .. console:: bro -r browse.pcap part4.bro

.. visible_solution::
   A completed solution is found in `part4-solutions.bro
   <part4-solutions.bro>`_.  Look at it for hints or run it to
   see the expected output:

   .. console:: bro -r browse.pcap part4-solutions.bro
