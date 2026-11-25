# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_rars_global_optspecs
    string join \n threads= progress= h/help V/version
end

function __fish_rars_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_rars_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_rars_using_subcommand
    set -l cmd (__fish_rars_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c rars -n "__fish_rars_needs_command" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_needs_command" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rars -n "__fish_rars_needs_command" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_needs_command" -f -a "info" -d 'Display archive metadata'
complete -c rars -n "__fish_rars_needs_command" -f -a "test" -d 'Verify archive integrity by extracting to a sink'
complete -c rars -n "__fish_rars_needs_command" -f -a "extract" -d 'Extract archive contents'
complete -c rars -n "__fish_rars_needs_command" -f -a "x" -d 'Extract archive contents'
complete -c rars -n "__fish_rars_needs_command" -f -a "repair" -d 'Repair a damaged archive using its recovery record'
complete -c rars -n "__fish_rars_needs_command" -f -a "add" -d 'Create a new archive'
complete -c rars -n "__fish_rars_needs_command" -f -a "a" -d 'Create a new archive'
complete -c rars -n "__fish_rars_using_subcommand info" -l legacy-name-encoding -d 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-buffered-decode-limit -d 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-decode-workers -d 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-dictionary-size-limit -d 'Maximum declared RAR5/7 dictionary size (not total memory)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l max-member-output-bytes -d 'Maximum decoded output per logical member or archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l max-total-output-bytes -d 'Maximum decoded output per extraction/test call, or per archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l max-reader-workspace-bytes -d 'Maximum aggregate reader workspace per call (not process RAM)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l max-header-count -d 'Maximum top-level headers per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l max-header-bytes -d 'Maximum plaintext header bytes per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-scratch-dir -d 'Directory for RAR5 filtered decoding above the buffering threshold' -r -F
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-scratch-bytes -d 'Maximum temporary bytes for RAR5 scratch decoding' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l rar50-filter-memory-limit -d 'Maximum workspace per RAR5 scratch filter' -r
complete -c rars -n "__fish_rars_using_subcommand info" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand info" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand info" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand info" -l allow-rar3-vm -d 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust'
complete -c rars -n "__fish_rars_using_subcommand info" -s v -l verbose -d 'Show all raw block/header fields (the developer-style dump)'
complete -c rars -n "__fish_rars_using_subcommand info" -s h -l help -d 'Print help'
complete -c rars -n "__fish_rars_using_subcommand info" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand test" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand test" -l legacy-name-encoding -d 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-buffered-decode-limit -d 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-decode-workers -d 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-dictionary-size-limit -d 'Maximum declared RAR5/7 dictionary size (not total memory)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l max-member-output-bytes -d 'Maximum decoded output per logical member or archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l max-total-output-bytes -d 'Maximum decoded output per extraction/test call, or per archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l max-reader-workspace-bytes -d 'Maximum aggregate reader workspace per call (not process RAM)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l max-header-count -d 'Maximum top-level headers per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l max-header-bytes -d 'Maximum plaintext header bytes per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-scratch-dir -d 'Directory for RAR5 filtered decoding above the buffering threshold' -r -F
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-scratch-bytes -d 'Maximum temporary bytes for RAR5 scratch decoding' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l rar50-filter-memory-limit -d 'Maximum workspace per RAR5 scratch filter' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand test" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand test" -l allow-rar3-vm -d 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust'
complete -c rars -n "__fish_rars_using_subcommand test" -s h -l help -d 'Print help'
complete -c rars -n "__fish_rars_using_subcommand test" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand extract" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand extract" -l legacy-name-encoding -d 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-buffered-decode-limit -d 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-decode-workers -d 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-dictionary-size-limit -d 'Maximum declared RAR5/7 dictionary size (not total memory)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l max-member-output-bytes -d 'Maximum decoded output per logical member or archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l max-total-output-bytes -d 'Maximum decoded output per extraction/test call, or per archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l max-reader-workspace-bytes -d 'Maximum aggregate reader workspace per call (not process RAM)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l max-header-count -d 'Maximum top-level headers per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l max-header-bytes -d 'Maximum plaintext header bytes per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-scratch-dir -d 'Directory for RAR5 filtered decoding above the buffering threshold' -r -F
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-scratch-bytes -d 'Maximum temporary bytes for RAR5 scratch decoding' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l rar50-filter-memory-limit -d 'Maximum workspace per RAR5 scratch filter' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l overwrite -d 'Behaviour when an extracted file already exists on disk' -r -f -a "never\t''
always\t''
rename\t'Write beside an existing file as name(N).ext'"
complete -c rars -n "__fish_rars_using_subcommand extract" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand extract" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand extract" -l allow-rar3-vm -d 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust'
complete -c rars -n "__fish_rars_using_subcommand extract" -l in-place -d 'Write each file at its destination instead of staging it; a failed member leaves a partial file'
complete -c rars -n "__fish_rars_using_subcommand extract" -l keep-broken -d 'Keep a damaged member\'s file with what could be read of it, like unrar -kb; implies --in-place'
complete -c rars -n "__fish_rars_using_subcommand extract" -l flatten -d 'Write every file straight into the output directory under its base name, creating no directories'
complete -c rars -n "__fish_rars_using_subcommand extract" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rars -n "__fish_rars_using_subcommand extract" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand x" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand x" -l legacy-name-encoding -d 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-buffered-decode-limit -d 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-decode-workers -d 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-dictionary-size-limit -d 'Maximum declared RAR5/7 dictionary size (not total memory)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l max-member-output-bytes -d 'Maximum decoded output per logical member or archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l max-total-output-bytes -d 'Maximum decoded output per extraction/test call, or per archive comment' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l max-reader-workspace-bytes -d 'Maximum aggregate reader workspace per call (not process RAM)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l max-header-count -d 'Maximum top-level headers per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l max-header-bytes -d 'Maximum plaintext header bytes per physical archive parse' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-scratch-dir -d 'Directory for RAR5 filtered decoding above the buffering threshold' -r -F
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-scratch-bytes -d 'Maximum temporary bytes for RAR5 scratch decoding' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l rar50-filter-memory-limit -d 'Maximum workspace per RAR5 scratch filter' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l overwrite -d 'Behaviour when an extracted file already exists on disk' -r -f -a "never\t''
always\t''
rename\t'Write beside an existing file as name(N).ext'"
complete -c rars -n "__fish_rars_using_subcommand x" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand x" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand x" -l allow-rar3-vm -d 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust'
complete -c rars -n "__fish_rars_using_subcommand x" -l in-place -d 'Write each file at its destination instead of staging it; a failed member leaves a partial file'
complete -c rars -n "__fish_rars_using_subcommand x" -l keep-broken -d 'Keep a damaged member\'s file with what could be read of it, like unrar -kb; implies --in-place'
complete -c rars -n "__fish_rars_using_subcommand x" -l flatten -d 'Write every file straight into the output directory under its base name, creating no directories'
complete -c rars -n "__fish_rars_using_subcommand x" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rars -n "__fish_rars_using_subcommand x" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand repair" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand repair" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand repair" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand repair" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand repair" -s h -l help -d 'Print help'
complete -c rars -n "__fish_rars_using_subcommand repair" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand add" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand add" -l format -d 'Target archive format (default: rar50, the modern widely-compatible format)' -r -f -a "rar14\t''
rar15\t''
rar20\t''
rar29\t''
rar30\t''
rar40\t''
rar50\t''
rar70\t''"
complete -c rars -n "__fish_rars_using_subcommand add" -l level -d 'Compression level (0..5; 0 implies --store)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l dict-size -d 'Dictionary size (e.g. 4m, 128k; RAR 1.5+)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l memory-limit -d 'Maximum total compression working memory (default: 283m, plus 160m per thread past the first, up to a quarter of RAM or the cgroup limit on Linux)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l max-memory -d 'Hard managed-allocation ceiling for RAR5/7, separate from estimated workspace' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l temp-dir -d 'Directory for temporary compressed payloads (RAR 5+)' -r -F
complete -c rars -n "__fish_rars_using_subcommand add" -l comment -d 'Archive-level comment' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l archive-name -d 'Archive name to embed in archive metadata service (RAR 5+)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l file-comment -d 'Per-file comment (not RAR 3.x/4.x)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l recovery-percent -d 'Add a recovery record at the given percentage (1..100; RAR 5+)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l volume-size -d 'Split archive into volumes of this size' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l delta-filter -d 'Delta filter with the given channel count (RAR 2.9+)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l rgb-filter -d 'RGB image filter with the given pixel width (RAR 2.9/3.x/4.x only)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l audio-filter -d 'Audio filter with the given channel count (RAR 2.9/3.x/4.x only)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -s C -l base-dir -d 'Read inputs from this directory and store names relative to it' -r -F
complete -c rars -n "__fish_rars_using_subcommand add" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand add" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand add" -l store -d 'Store files without compression (equivalent to --level 0)'
complete -c rars -n "__fish_rars_using_subcommand add" -l solid -d 'Use solid compression (treats inputs as one continuous stream)'
complete -c rars -n "__fish_rars_using_subcommand add" -l encrypt-headers -d 'Encrypt archive headers (RAR 3.x/4.x and RAR 5+) (requires --password)'
complete -c rars -n "__fish_rars_using_subcommand add" -l quick-open -d 'Emit a quick-open service block (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand add" -l blake2sp -d 'Store a BLAKE2sp hash of each file beside its CRC32 (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand add" -l e8-filter -d 'E8 x86 call filter (RAR 2.9+)'
complete -c rars -n "__fish_rars_using_subcommand add" -l e8e9-filter -d 'E8E9 x86 call/jump filter (RAR 2.9+)'
complete -c rars -n "__fish_rars_using_subcommand add" -l itanium-filter -d 'Itanium filter (RAR 2.9/3.x/4.x only)'
complete -c rars -n "__fish_rars_using_subcommand add" -l arm-filter -d 'ARM filter (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand add" -l auto-filter -d 'Auto-detect data filter (RAR 5+ does this by default)'
complete -c rars -n "__fish_rars_using_subcommand add" -l no-filter -d 'Skip filter detection, compressing the data as it is (RAR 2.9+; the older formats never look, so the flag passes without comment there)'
complete -c rars -n "__fish_rars_using_subcommand add" -l ppmd -d 'Use the PPMd compression algorithm (RAR 2.9/3.x/4.x only)'
complete -c rars -n "__fish_rars_using_subcommand add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rars -n "__fish_rars_using_subcommand add" -s V -l version -d 'Print version'
complete -c rars -n "__fish_rars_using_subcommand a" -s p -l password -d 'Archive password (visible in process list — prefer --password-file or the TTY prompt)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l password-file -d 'Read password from file ("-" for stdin); trailing newlines are stripped' -r -F
complete -c rars -n "__fish_rars_using_subcommand a" -l format -d 'Target archive format (default: rar50, the modern widely-compatible format)' -r -f -a "rar14\t''
rar15\t''
rar20\t''
rar29\t''
rar30\t''
rar40\t''
rar50\t''
rar70\t''"
complete -c rars -n "__fish_rars_using_subcommand a" -l level -d 'Compression level (0..5; 0 implies --store)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l dict-size -d 'Dictionary size (e.g. 4m, 128k; RAR 1.5+)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l memory-limit -d 'Maximum total compression working memory (default: 283m, plus 160m per thread past the first, up to a quarter of RAM or the cgroup limit on Linux)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l max-memory -d 'Hard managed-allocation ceiling for RAR5/7, separate from estimated workspace' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l temp-dir -d 'Directory for temporary compressed payloads (RAR 5+)' -r -F
complete -c rars -n "__fish_rars_using_subcommand a" -l comment -d 'Archive-level comment' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l archive-name -d 'Archive name to embed in archive metadata service (RAR 5+)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l file-comment -d 'Per-file comment (not RAR 3.x/4.x)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l recovery-percent -d 'Add a recovery record at the given percentage (1..100; RAR 5+)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l volume-size -d 'Split archive into volumes of this size' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l delta-filter -d 'Delta filter with the given channel count (RAR 2.9+)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l rgb-filter -d 'RGB image filter with the given pixel width (RAR 2.9/3.x/4.x only)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l audio-filter -d 'Audio filter with the given channel count (RAR 2.9/3.x/4.x only)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -s C -l base-dir -d 'Read inputs from this directory and store names relative to it' -r -F
complete -c rars -n "__fish_rars_using_subcommand a" -l threads -d 'Worker threads for parallel compression and extraction (default: all available cores)' -r
complete -c rars -n "__fish_rars_using_subcommand a" -l progress -d 'Progress reporting mode for long-running operations' -r -f -a "auto\t''
always\t''
never\t''"
complete -c rars -n "__fish_rars_using_subcommand a" -l store -d 'Store files without compression (equivalent to --level 0)'
complete -c rars -n "__fish_rars_using_subcommand a" -l solid -d 'Use solid compression (treats inputs as one continuous stream)'
complete -c rars -n "__fish_rars_using_subcommand a" -l encrypt-headers -d 'Encrypt archive headers (RAR 3.x/4.x and RAR 5+) (requires --password)'
complete -c rars -n "__fish_rars_using_subcommand a" -l quick-open -d 'Emit a quick-open service block (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand a" -l blake2sp -d 'Store a BLAKE2sp hash of each file beside its CRC32 (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand a" -l e8-filter -d 'E8 x86 call filter (RAR 2.9+)'
complete -c rars -n "__fish_rars_using_subcommand a" -l e8e9-filter -d 'E8E9 x86 call/jump filter (RAR 2.9+)'
complete -c rars -n "__fish_rars_using_subcommand a" -l itanium-filter -d 'Itanium filter (RAR 2.9/3.x/4.x only)'
complete -c rars -n "__fish_rars_using_subcommand a" -l arm-filter -d 'ARM filter (RAR 5+ only)'
complete -c rars -n "__fish_rars_using_subcommand a" -l auto-filter -d 'Auto-detect data filter (RAR 5+ does this by default)'
complete -c rars -n "__fish_rars_using_subcommand a" -l no-filter -d 'Skip filter detection, compressing the data as it is (RAR 2.9+; the older formats never look, so the flag passes without comment there)'
complete -c rars -n "__fish_rars_using_subcommand a" -l ppmd -d 'Use the PPMd compression algorithm (RAR 2.9/3.x/4.x only)'
complete -c rars -n "__fish_rars_using_subcommand a" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rars -n "__fish_rars_using_subcommand a" -s V -l version -d 'Print version'
