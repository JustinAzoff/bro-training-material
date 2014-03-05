event bro_init()
	{
	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 1 -------------------";
	print "----------------------------------------------------------";
	# Concatenate the following two strings ``s1`` and ``s2``
	# (inserting a space in between), store the result in
	# ``s3`` using the ``=`` operator, and ``print`` the result.
	# The easiest solution is probably exactly what you think, but
	# there's also functions that could be used for concatenation.

	local s1 = "The quick, brown Bro jumped";
	local s2 = "over the lazy scanner.";
	local s3 = " " + " " + " ";

	# ADD CODE HERE
	print s3;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 2 -------------------";
	print "----------------------------------------------------------";
	# The ``pattern`` type holds regular-expression patterns,
	# which can be used for fast text searching operations.
	# Pattern constants are created by enclosing pattern text within
	# forward slashes (/).  E.g. ``/[[:alpha:][:digit:]]+/``,
	# ``/foo|bar/``, ``/^rewt.*login/``, ``/[a-zA-Z0-9]+/``...
	# Check to see if either ``s1`` or ``s2`` matches the pattern
	# "scan", and print it out if it does.

	if (/CHANGE_THIS_CODE/ in s1)
		print s1;
	if (/CHANGE_THIS_CODE/ in s2)
		print s2;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 3 -------------------";
	print "----------------------------------------------------------";
	# Now ``split()`` ``s1`` by the case insensitive string, "bro",
	# store the resulting strings into the ``parts`` variable, and
	# print it.  For this, realize that patterns in Bro scripting
	# currently do not have a shorthand for case-insensitive
	# matching.

	local parts: string_array;

	parts = split(s1, /CHANGE_THIS_CODE/);
	if (|parts|>1)
		print parts;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 4 -------------------";
	print "----------------------------------------------------------";
	# Now iterate over ``parts`` using a ``for`` loop and ``print``
	# the contents.  For this, realize that the ``string_array``
	# type is an alias for ``table[count] of string`` and that
	# you can access elements of table using square brackets:
	# e.g. "<table_name>[<index>].

	for (i in parts)
		{
		# ADD CODE HERE
		}
	# Notice how the order in which the contents are printed is
	# not respective of the order of the table indices. This has
	# to do with the underlying storage scheme and that Bro is not
	# usually concerned with controlled loop iteration -- it's very
	# easy misuse loops in a way that's to the detriment of trying to
	# analyze packets coming in at real-time.  In this way, Bro makes
	# the programmer think more about the consequences of looping.

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 5 -------------------";
	print "----------------------------------------------------------";
	# Now iterate over ``parts`` again, this time using the ``fmt()``
	# function to print the index of items before the actual item.

	# ADD A FOR LOOP CONDITION HERE
		{
		if (|parts|>1)
			print fmt("%d %s", i, parts[i]);
		}
	# Notice how the ``parts`` table does actually contain the split
	# string indexed by the order in which "bro" was found in the
	# ``s1`` string.

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 6 -------------------";
	print "----------------------------------------------------------";
	# Now access and assign individual elements of ``parts`` in
	# order for the individual pieces to later be joined together
	# to form the correct part of the phrase, "The quick, brown
	# fox jumped".  Check correctness by another ``print``/``fmt``
	# loop over the table.

	# ADD CODE HERE

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 7 -------------------";
	print "----------------------------------------------------------";
	# Revise the ``s2`` string to substitute "dog" for "scanner" by
	# using the ``sub()`` function.  ``print`` the result to check.

	s2 = sub(s2, /CHANGE_THIS_CODE/, "dog");
	if ( /scanner/ !in s2 )
		print s2;

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 8 -------------------";
	print "----------------------------------------------------------";
	# Now join ``parts`` and ``s2`` to form the final, correct
	# pangram, "The quick, brown fox jumped over the lazy dog".
	# You'll might find the ``strip()`` and ``join_string_array()``
	# functions useful.  You can accumulate/store the results in
	# ``s3`` and print it to check correctness.

	# ADD CODE HERE
	}
