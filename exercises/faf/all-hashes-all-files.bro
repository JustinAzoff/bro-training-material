event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA1);
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }
