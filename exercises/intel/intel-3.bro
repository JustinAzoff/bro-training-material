@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::read_files += {
    fmt("%s/intel-3.dat", @DIR)
};
