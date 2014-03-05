
# A ``table`` is an associative array that maps one set of values to another.
# The value being mapped is the "index" (multi-valued indices are also allowed)
# and the result of the mapping is the "yield".  Here's a table initialization

global host_owners: table[addr] of string = {
	[192.168.1.100] = "George Brorwell",
	[192.168.1.101] = "Brorson Scott Card",
	[192.168.1.102] = "Albrous Huxley",
	[192.168.1.103] = "Broprah Winfrey",
};

event bro_init()
	{
	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 1 -------------------";
	print "----------------------------------------------------------";
	# Print out the contents of the ``host_owners`` table by
	# iterating over it and printing the contents in the format
	# "<person> owns <ip>".  The ``fmt`` function can be used for
	# this and know that accessing a table element at a given index
	# is done by using square brackets: e.g. "<table_name>[<index>]"

	for (h in host_owners)
		{
		print fmt("%s owns %s", host_owners[h], h);
		}

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 2 -------------------";
	print "----------------------------------------------------------";
	# Now use the ``delete`` keyword to remove a mapping from
	# the table.  e.g. "delete <table_name>[<index>]" Choose the
	# mapping that doesn't fit the theme (the last), and print the
	# new table in the same way you did before.

	delete host_owners[192.168.1.103];
	for (h in host_owners)
		{
		print fmt("%s owns %s", host_owners[h], h);
		}

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 3 -------------------";
	print "----------------------------------------------------------";
	# Now change the following conditional to check whether that
	# deleted ``addr`` index still maps to a person.	You can do
	# that test using the ``in`` operator.  E.g. "<index> in <table>"

	if (192.168.1.103 in host_owners)
		print "Is 192.168.1.103 still mapping to something?";
	else
		print "The mapping is gone.";

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 4 -------------------";
	print "----------------------------------------------------------";
	# Now add in your own mapping in place of the deleted one and
	# print the table contents for the final time.  You add you
	# own mappings simply by assigning (via the ``=`` operator)
	# to a table index.

	host_owners[192.168.1.103] = "Maybe Another Broauthor";
	for (h in host_owners)
		{
		print fmt("%s owns %s", host_owners[h], h);
		}

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 5 -------------------";
	print "----------------------------------------------------------";
	# A ``set`` is like a table, except that it's only a collection
	# of indices that don't map to any yield.  Here's an initialized
	# set that also shows off implicit typing, print the contents of
	# ``my_ports`` with a ``print`` statement (no need to iterate):

	local my_ports = set( 1984/tcp, 1985/tcp, 2540/udp, 632/udp );
	print my_ports;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 6 -------------------";
	print "----------------------------------------------------------";
	# Now use the ``delete`` keyword again to remove all UDP
	# ports from the set.  Then let's jump to adding your own
	# value of "2011/tcp" to the set by using the ``add`` keyword:
	# e.g. "add <set_name>[<index>]".  Finally, print the contents of
	# ``my_ports`` again to check.

	delete my_ports[2540/udp];
	delete my_ports[632/udp];
	add my_ports[2011/tcp];
	print my_ports;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 7 -------------------";
	print "----------------------------------------------------------";
	# Finally, vectors are again like tables in that it's a mapping
	# of index values to yield values, except the indices are always
	# 0-based positive integers. Here's a vector initialization,
	# print the contents of ``my_vector``:

	local my_vector = vector("Ego", "SuperEgo", "Id");
	print my_vector;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 8 -------------------";
	print "----------------------------------------------------------";
	# Now write a loop that takes all the yield values from
	# ``host_owners`` and adds them to ``my_vector``, printing
	# the contents in a loop afterwards.  For this, you'll need
	# to know that vector/table element assignment is done with the ``=``
	# operator and vector/table access is done with square brackets.
	# It's also helpful to know you can get the size of a vector/table
	# by putting the identifier within vertical pipe characters:
	# e.g. |<vector/table_name>|.

	for (h in host_owners)
		my_vector[|my_vector|] = host_owners[h];
	for (i in my_vector)
		print my_vector[i];
	}
