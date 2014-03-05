module HTTP;

export {
    redef record Info += {
        # Extend this record with an optional, logged field named "cookie".
        cookie: string &log &optional;
    };
}


# Track the cookie value inside HTTP.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;

    # Write the cookie value into the HTTP state of the connection.
    if ( name == "COOKIE" )
        c$http$cookie = value;
    }
