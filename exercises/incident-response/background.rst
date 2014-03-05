===================
Exercise Background
===================

.. note::
    This story and accompanying incident response exercises originally appeared
    as a network forensics project in the context of the UC Berkeley
    `undergraduate security course`__ taught by Vern Paxson in Spring 2011. For
    this workshop, we reuse these materials with permission in a slightly
    modified form. Kudos to Vern Paxson and his teaching assistants Mobin Javed
    and Matthias Vallentin for doing the hard ground work in the first place.

__ http://inst.eecs.berkeley.edu/~cs161/sp11

Huge Big Dairy is a farming and poultry conglomerate run out of Madison,
Wisconsin.  They pride themselves on their yogurts, brie cheeses, and buffalo
wings (made out of |Real Buffalo (TM)|). However, Huge Big has many detractors
who allege that the company not only manifests incompetence when it comes to
dairy products, but also a propensity towards venal undertakings.

.. |Real Buffalo (TM)| unicode:: Real Buffalo U+2122

During an ill-advised television interview, Huge Big's CEO, Chuck "Mondo"
Cheeze, brashly trumpets his company's expertise, not only in all things dairy,
but their e-marketing prowess and home-grown Internet security savvy.  Mondo's
biggest gaffe, however, is to imply that he does not consider cows as bovines -
instantly incurring the wrath of the shadowy underground hacker group
*Synonymous*, whose members unite in their violent objection to any terminology
errors that confuse whether two words have the same meaning.

Synonymous decides to humiliate HBDairy, exposing their secrets and
incompetence, and disrupting the activity of their employees.  In a series of
Internet attacks that HBDairy finds itself powerless to counter, Synonymous
deeply embarrasses the company.  Eventually, HBDairy must admit they have been
outmatched, and in desperation they turn to expert outside help: **you**.  They
commission your team to analyze how Synonymous achieved their exploits.
Luckily, the one facet of computer security they managed not to screw up is
logging: they have full packet traces of all of the systems in question.

One gloomy morning as the end of the semester looms, you head out to Richmond
Field, board the HBDairy corporate jet and 5 hours later find yourself at
their offices in Madison, armed only with a trusty VM image that contains all
of your analysis tools.  You need to complete your forensic analysis, file your
report, hop back on their jet, and return to the Bro headquarters - with enough
time left to continue with your mundane job.
