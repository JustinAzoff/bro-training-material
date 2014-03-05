@load base/frameworks/files

global file_count = 0;
global file_bytes = 0;
const target_server = 198.189.255.75 &redef;

event file_state_remove(f: fa_file)
    {
    if ( target_server !in f$info$tx_hosts )
        return;

    ++file_count;
    file_bytes += f$info$seen_bytes;
    }

event bro_done()
    {
    local avg = file_count > 0 ? file_bytes / file_count : 0;    print fmt("Avg. file size served by %s = %d bytes", target_server, avg);
    }
