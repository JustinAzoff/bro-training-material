@load bodies

redef HTTP::hook_reply_bodies = T;
redef HTTP::hook_host_pattern = /[0-9]+\.channel\.facebook\.com/;

module Facebook;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        timestamp: string   &log;
        chat_from: string   &log;
        chat_to: string     &log;
        chat_msg: string    &log;
    };

    ## A webchat message.
    type ChatMessage: record
    {
        timestamp: string;      ##< Message timestamp.
        from: string;           ##< Name of the sender
        to: string;             ##< Name of the recipient.
        text: string;           ##< The actual message.
    };

	global log_facebook: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(Facebook::LOG, [$columns=Info, $ev=log_facebook]);
	}

## Extract integer (or quoted string) value from a key:value (or key:"value").
function extract_value(str: string) : string
    {
    local s = split1(str, /:/)[2];
    s = sub(s, /^\"/, "");
    return sub(s, /\"$/, "");
    }

## Extract text between the last two two double quotes.
function extract_last_quoted(str: string) : string
    {
    local q = find_last(str, /\"([^\"]|\\\")*\"/);
    return split(q, /\"/)[2];
    }

## Create a webchat message from JSON data.
function parse_fb_message(data: string) : ChatMessage
    {
    local msg: ChatMessage;

    local array = split(data, /,\"/);
    for ( i in array )
        {
        local val = array[i];
        # TODO: fill out the fields of msg with the appropriate data from the
        # JSON objects
        }

    return msg;
    }

## Reassemble the HTTP body of replies and look for Facebook chat messages.
event http_body(c: connection, is_orig: bool, data: string, size: count)
    {
    #
    # Uncomment to see how the JSON data looks like.
    #
    #print data;
    #print "--------------------------------------------------------------";

    # Only consider chat messages for now.
    if (/^for \(;;\);\{\"t\":\"msg\".*text\":\"/ !in data)  #"
        return;

    local msg = parse_fb_message(data);

    local i: Info;
    i$timestamp = msg$timestamp;
    i$chat_from = msg$from;
    i$chat_to = msg$to;
    i$chat_msg = msg$text;

    Log::write(Facebook::LOG, i);
    }
