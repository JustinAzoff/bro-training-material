# A ``record`` is a collection of values, each with a type and name.
# Here's an example that groups together a required host-port combo with
# an optional name (this is specified as an attribute, which is a set
# of metadata imposed on a variable and characterized by the ampersand).

type Service: record {
	h: addr;
	p: port;
	name: string &optional;
};

# Pay no attention to that man behind the curtain... we'll revisit
# this ``redef`` later.

redef record Service += {
	is_priv: bool &optional;
};

# A ``function`` is just an abstraction of a set of more complicated
# (usually) procedures/statements.  Here's a simple one that defines
# a default way to format Service records for printing.  Notice that
# accessing record fields is done with the ``$`` operator and not a
# ``.`` operator as that's already used for parsing IP address types.
# Also, optional fields can be tested for with the ``?$`` operator
# prior to access.

function default_printer(s: Service): string
	{
	if ( s?$name )
		return fmt("%s:%s", s$h, s$name);
	else
		return fmt("%s:%s", s$h, s$p);
	}

# And here's a more complicated ``record`` type declaration in that
# it contains a nested record and also a function as field types.
# There's also a default attribute applied to the ``print_func``
# field to initialize it to a default value if none is given during
# the initialization of the ``ServicePrinter`` record instance.

type ServicePrinter: record {
	s: Service;
	print_func: function(s: Service): string &default=default_printer;
};

event bro_init()
	{
	local service_list: set[Service];
	add service_list[ [ $h=192.168.1.111, $p=22/tcp, $name="ssh" ] ];
	add service_list[ [ $h=192.168.1.111, $p=80/tcp, $name="http" ] ];
	add service_list[ [ $h=192.168.1.222, $p=22/tcp, $name="ssh" ] ];
	add service_list[ [ $h=192.168.1.222, $p=13131/tcp ] ];

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 1 -------------------";
	print "----------------------------------------------------------";
	# Loop over the ``service_list`` and print the contents using the
	# results of a call to the ``default_printer`` function.

	for ( serv in service_list )
		print default_printer(serv);

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 2 -------------------";
	print "----------------------------------------------------------";
	# Now make a set of ``ServicePrinter``'s, add all the services
	# to it, and print out all the ``Service`` records again,
	# this time using the ``ServicePrinter``'s ``print_func`` field.

	local service_printer_list: set[ServicePrinter];
	for ( serv in service_list )
		add service_printer_list[ [ $s = serv ] ];
	for ( sp in service_printer_list )
		print sp$print_func(sp$s);

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 3 -------------------";
	print "----------------------------------------------------------";
	# So the last exercise was just a more complicated way of doing
	# the first, but sets up the ability to dynamically change
	# the printing function.	Now change all the ``print_func``'s
	# of the ``ServicePrinter``'s in your list to something
	# different.  Make it a new function that uses the same
	# format as ``default_printer``, except that for services on a
	# privileged port (< 1024/tcp), precede the entire string with
	# an asterisk.  You can define a new function before/outside this
	# ``bro_init()`` event or attempt to do it inline.  The solution
	# will show the inline method.

	for ( sp in service_printer_list )
		{
		sp$print_func = function(s: Service): string
		 { return s$p < 1024/tcp ? "*" + default_printer(s) : default_printer(s); };
		print sp$print_func(sp$s);
		}

	print "----------------------------------------------------------";
	print "------------------- Subexercise Part 4 -------------------";
	print "----------------------------------------------------------";
	# And for fun (and to demonstrate record redefinition), let's
	# simplify the last exercise to now assign ``print_func``'s that
	# just check a new boolean value added to the ``Service`` record.
	# If you remember, there was an empty record redefinition template
	# near the top of this file.  Go back and add a field to the
	# ``Service`` record redefinition that will indicate whether it
	# is a privileged port (< 1024/tcp).  Then, iterating over
	# ``ServicePrinter``s in your list, assign the new record field
	# an appropriate value, assign a new printer function, and then
	# use the printer function to print the ``Service`` record
	# held within the ``ServicePrinter`` iterator.

	for ( sp in service_printer_list )
		{
		if ( sp$s$p < 1024/tcp )
			sp$s$is_priv = T;
		else
			sp$s$is_priv = F;

		sp$print_func = function(s: Service): string
		 { return s$is_priv ? "*" + default_printer(s) : default_printer(s); };

		print sp$print_func(sp$s);
		}
	}
