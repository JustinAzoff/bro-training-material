module HTTP;

export {
    redef record Info += {
        # TODO: Extend this record with an optional, logged field 
        # named "cookie".
    };
}


# Track the cookie value inside HTTP.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;

    # TODO: Write the cookie value into the HTTP state of the connection.
    }
