# You've actually been using events this whole time as you completed
# previous exercises; let's see if you remember.  The ``bro_init()``
# event is generated when Bro first starts up and just before it
# begins to read packets from a given input source.  Handle the
# ``bro_init()`` event to print out "Hello, world!" and check your
# results by running this script through Bro.

# ADD CODE HERE

# And you're not limited to a single handler per-event.  So create
# another ``bro_init()`` handler to print out "Hello, Brogrammer!".
# Check your results by running this script through Bro.

# ADD CODE HERE

# Now, you might notice that the order in which Bro printed those
# strings is a bit off from what you expected.  We want to make sure
# that the "hello world" is printed first, so the way we do that is
# with event priorities (choosing an integer in "&priority=[-10,10]"
# and placing that string after the event handler declaration and
# before the body, e.g. "event bro_init() &priority=5 {}"). Revisit
# one of your event handlers above to enforce an ordering on the
# messages being printed.  Re-run the script through Bro to make sure.

# To make it more interesting, let's handle the ``http_request()``
# event and print out "responding host -> URI" strings. For this
# you should be supplying Bro the exercise input trace file with
# the -r option.  The ``browse.pcap`` trace contains a web browsing
# session in which I visited some pages of www.bro.org.
# (hint: ``c$id$resp_h`` refers to a connection's responding host)

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	# ADD CODE HERE
	}

# Now, after inspecting the results of the last handler,
# handle that ``http_request()`` event again, creating a
# set of originator addresses (c$id$orig_h) that had visited
# the "reporting-problems.html" web page.

# ADD CODE HERE

# Finally, use a ``bro_done()`` event handler (runs on termination of Bro)
# to print out the accumulated set of users that visited the problem
# reporting web page.

# ADD CODE HERE

# Good, there should only be one user experiencing Broblems, and that
# was me, so we can conclude the Bro Language Primer with confidence
# that you have a basic knowledge of Bro's scripting language and
# how it's used for network traffic analysis.
