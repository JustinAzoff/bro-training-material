module HTTP;

export {
    redef enum Notice::Type += {
        ## Cookie reuse by a different user agent
        SessionCookieReuse
    };

    # We track the cookie inside the HTTP state of the connection.
    redef record Info += {
        cookie: string &log &optional;
    };
}

const twitter_cookie_keys = set("_twitter_sess", "auth_token");

# Map cookies to user agents.
global cookies: table[string] of string;

# Create a unique user session identifier based on the relevant cookie keys.
# Return the empty string if the sessionization does not succeed.
function sessionize(cookie: string, keys: set[string]) : string
    {
    local id = "";
    local fields = split(cookie, /; /);

    local matches: table[string] of string;
    for ( i in fields )
        {
        local s = split1(fields[i], /=/);
        if (s[1] in keys)
            matches[s[1]] = s[2];
        }

    if ( |matches| == |keys| )
        for ( key in keys )
        {
            if (id != "")
                id += "; ";
            id += key + "=" + matches[key];
        }

    return id;
    }


# Track the cookie value inside HTTP.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "COOKIE" )
        c$http$cookie = value;
    }

# We use this event as an indicator that all headers have been seen. That is,
# this event guarantees that the HTTP state inside the connection record
# has all fields populated.
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig || ! c$http?$cookie || c$http$cookie == "" )
        return;

    # Focus on Twitter requests only.
    if ( /twitter.com/ !in c$http$host )
        return;

    # Create the relevant cookie subset that makes up the user session.
    local session_cookie = sessionize(c$http$cookie, twitter_cookie_keys);

    # Start tracking the current session cookie if we don't do so already.
    if ( session_cookie !in cookies )
        {
        cookies[session_cookie] = c$http$user_agent;
        return;
        }

    # Everything's fine if the current user agent matches the previous one.
    if ( c$http$user_agent == cookies[session_cookie] )
        return;

    NOTICE([$note=SessionCookieReuse,
            $suppress_for=10min,
            $conn=c,
            $msg=fmt("Reused Twitter session via cookie %s", session_cookie),
            $identifier=session_cookie]);
    }
