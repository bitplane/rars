
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'rars' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'rars'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'rars' {
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('info', 'info', [CompletionResultType]::ParameterValue, 'Display archive metadata')
            [CompletionResult]::new('test', 'test', [CompletionResultType]::ParameterValue, 'Verify archive integrity by extracting to a sink')
            [CompletionResult]::new('extract', 'extract', [CompletionResultType]::ParameterValue, 'Extract archive contents')
            [CompletionResult]::new('x', 'x', [CompletionResultType]::ParameterValue, 'Extract archive contents')
            [CompletionResult]::new('repair', 'repair', [CompletionResultType]::ParameterValue, 'Repair a damaged archive using its recovery record')
            [CompletionResult]::new('add', 'add', [CompletionResultType]::ParameterValue, 'Create a new archive')
            [CompletionResult]::new('a', 'a', [CompletionResultType]::ParameterValue, 'Create a new archive')
            break
        }
        'rars;info' {
            [CompletionResult]::new('--legacy-name-encoding', '--legacy-name-encoding', [CompletionResultType]::ParameterName, 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)')
            [CompletionResult]::new('--rar50-buffered-decode-limit', '--rar50-buffered-decode-limit', [CompletionResultType]::ParameterName, 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)')
            [CompletionResult]::new('--rar50-decode-workers', '--rar50-decode-workers', [CompletionResultType]::ParameterName, 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)')
            [CompletionResult]::new('--rar50-dictionary-size-limit', '--rar50-dictionary-size-limit', [CompletionResultType]::ParameterName, 'Maximum declared RAR5/7 dictionary size (not total memory)')
            [CompletionResult]::new('--max-member-output-bytes', '--max-member-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per logical member or archive comment')
            [CompletionResult]::new('--max-total-output-bytes', '--max-total-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per extraction/test call, or per archive comment')
            [CompletionResult]::new('--max-reader-workspace-bytes', '--max-reader-workspace-bytes', [CompletionResultType]::ParameterName, 'Maximum aggregate reader workspace per call (not process RAM)')
            [CompletionResult]::new('--max-header-count', '--max-header-count', [CompletionResultType]::ParameterName, 'Maximum top-level headers per physical archive parse')
            [CompletionResult]::new('--max-header-bytes', '--max-header-bytes', [CompletionResultType]::ParameterName, 'Maximum plaintext header bytes per physical archive parse')
            [CompletionResult]::new('--rar50-scratch-dir', '--rar50-scratch-dir', [CompletionResultType]::ParameterName, 'Directory for RAR5 filtered decoding above the buffering threshold')
            [CompletionResult]::new('--rar50-scratch-bytes', '--rar50-scratch-bytes', [CompletionResultType]::ParameterName, 'Maximum temporary bytes for RAR5 scratch decoding')
            [CompletionResult]::new('--rar50-filter-memory-limit', '--rar50-filter-memory-limit', [CompletionResultType]::ParameterName, 'Maximum workspace per RAR5 scratch filter')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--allow-rar3-vm', '--allow-rar3-vm', [CompletionResultType]::ParameterName, 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Show all raw block/header fields (the developer-style dump)')
            [CompletionResult]::new('--verbose', '--verbose', [CompletionResultType]::ParameterName, 'Show all raw block/header fields (the developer-style dump)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;test' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--legacy-name-encoding', '--legacy-name-encoding', [CompletionResultType]::ParameterName, 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)')
            [CompletionResult]::new('--rar50-buffered-decode-limit', '--rar50-buffered-decode-limit', [CompletionResultType]::ParameterName, 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)')
            [CompletionResult]::new('--rar50-decode-workers', '--rar50-decode-workers', [CompletionResultType]::ParameterName, 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)')
            [CompletionResult]::new('--rar50-dictionary-size-limit', '--rar50-dictionary-size-limit', [CompletionResultType]::ParameterName, 'Maximum declared RAR5/7 dictionary size (not total memory)')
            [CompletionResult]::new('--max-member-output-bytes', '--max-member-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per logical member or archive comment')
            [CompletionResult]::new('--max-total-output-bytes', '--max-total-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per extraction/test call, or per archive comment')
            [CompletionResult]::new('--max-reader-workspace-bytes', '--max-reader-workspace-bytes', [CompletionResultType]::ParameterName, 'Maximum aggregate reader workspace per call (not process RAM)')
            [CompletionResult]::new('--max-header-count', '--max-header-count', [CompletionResultType]::ParameterName, 'Maximum top-level headers per physical archive parse')
            [CompletionResult]::new('--max-header-bytes', '--max-header-bytes', [CompletionResultType]::ParameterName, 'Maximum plaintext header bytes per physical archive parse')
            [CompletionResult]::new('--rar50-scratch-dir', '--rar50-scratch-dir', [CompletionResultType]::ParameterName, 'Directory for RAR5 filtered decoding above the buffering threshold')
            [CompletionResult]::new('--rar50-scratch-bytes', '--rar50-scratch-bytes', [CompletionResultType]::ParameterName, 'Maximum temporary bytes for RAR5 scratch decoding')
            [CompletionResult]::new('--rar50-filter-memory-limit', '--rar50-filter-memory-limit', [CompletionResultType]::ParameterName, 'Maximum workspace per RAR5 scratch filter')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--allow-rar3-vm', '--allow-rar3-vm', [CompletionResultType]::ParameterName, 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;extract' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--legacy-name-encoding', '--legacy-name-encoding', [CompletionResultType]::ParameterName, 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)')
            [CompletionResult]::new('--rar50-buffered-decode-limit', '--rar50-buffered-decode-limit', [CompletionResultType]::ParameterName, 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)')
            [CompletionResult]::new('--rar50-decode-workers', '--rar50-decode-workers', [CompletionResultType]::ParameterName, 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)')
            [CompletionResult]::new('--rar50-dictionary-size-limit', '--rar50-dictionary-size-limit', [CompletionResultType]::ParameterName, 'Maximum declared RAR5/7 dictionary size (not total memory)')
            [CompletionResult]::new('--max-member-output-bytes', '--max-member-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per logical member or archive comment')
            [CompletionResult]::new('--max-total-output-bytes', '--max-total-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per extraction/test call, or per archive comment')
            [CompletionResult]::new('--max-reader-workspace-bytes', '--max-reader-workspace-bytes', [CompletionResultType]::ParameterName, 'Maximum aggregate reader workspace per call (not process RAM)')
            [CompletionResult]::new('--max-header-count', '--max-header-count', [CompletionResultType]::ParameterName, 'Maximum top-level headers per physical archive parse')
            [CompletionResult]::new('--max-header-bytes', '--max-header-bytes', [CompletionResultType]::ParameterName, 'Maximum plaintext header bytes per physical archive parse')
            [CompletionResult]::new('--rar50-scratch-dir', '--rar50-scratch-dir', [CompletionResultType]::ParameterName, 'Directory for RAR5 filtered decoding above the buffering threshold')
            [CompletionResult]::new('--rar50-scratch-bytes', '--rar50-scratch-bytes', [CompletionResultType]::ParameterName, 'Maximum temporary bytes for RAR5 scratch decoding')
            [CompletionResult]::new('--rar50-filter-memory-limit', '--rar50-filter-memory-limit', [CompletionResultType]::ParameterName, 'Maximum workspace per RAR5 scratch filter')
            [CompletionResult]::new('--overwrite', '--overwrite', [CompletionResultType]::ParameterName, 'Behaviour when an extracted file already exists on disk')
            [CompletionResult]::new('--symlinks', '--symlinks', [CompletionResultType]::ParameterName, 'Which symbolic links and junctions to make, like unrar -ol, -ola and -ol-; hard links and file copies are always made')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--allow-rar3-vm', '--allow-rar3-vm', [CompletionResultType]::ParameterName, 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust')
            [CompletionResult]::new('--in-place', '--in-place', [CompletionResultType]::ParameterName, 'Write each file at its destination instead of staging it; a failed member leaves a partial file')
            [CompletionResult]::new('--keep-broken', '--keep-broken', [CompletionResultType]::ParameterName, 'Keep a damaged member''s file with what could be read of it, like unrar -kb; implies --in-place')
            [CompletionResult]::new('--flatten', '--flatten', [CompletionResultType]::ParameterName, 'Write every file straight into the output directory under its base name, creating no directories')
            [CompletionResult]::new('--ignore-attributes', '--ignore-attributes', [CompletionResultType]::ParameterName, 'Set no file or directory modes, like unrar -ai: files are created 0666 and directories 0777, less the umask; times are still restored')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;x' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--legacy-name-encoding', '--legacy-name-encoding', [CompletionResultType]::ParameterName, 'Source encoding for legacy names without Unicode (e.g. cp850 or detect)')
            [CompletionResult]::new('--rar50-buffered-decode-limit', '--rar50-buffered-decode-limit', [CompletionResultType]::ParameterName, 'Maximum RAR 5 member size to decode in memory; larger ones stream (default 16m)')
            [CompletionResult]::new('--rar50-decode-workers', '--rar50-decode-workers', [CompletionResultType]::ParameterName, 'Threads decoding RAR5/7 blocks ahead of the output; 0 decodes serially (default: up to 8)')
            [CompletionResult]::new('--rar50-dictionary-size-limit', '--rar50-dictionary-size-limit', [CompletionResultType]::ParameterName, 'Maximum declared RAR5/7 dictionary size (not total memory)')
            [CompletionResult]::new('--max-member-output-bytes', '--max-member-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per logical member or archive comment')
            [CompletionResult]::new('--max-total-output-bytes', '--max-total-output-bytes', [CompletionResultType]::ParameterName, 'Maximum decoded output per extraction/test call, or per archive comment')
            [CompletionResult]::new('--max-reader-workspace-bytes', '--max-reader-workspace-bytes', [CompletionResultType]::ParameterName, 'Maximum aggregate reader workspace per call (not process RAM)')
            [CompletionResult]::new('--max-header-count', '--max-header-count', [CompletionResultType]::ParameterName, 'Maximum top-level headers per physical archive parse')
            [CompletionResult]::new('--max-header-bytes', '--max-header-bytes', [CompletionResultType]::ParameterName, 'Maximum plaintext header bytes per physical archive parse')
            [CompletionResult]::new('--rar50-scratch-dir', '--rar50-scratch-dir', [CompletionResultType]::ParameterName, 'Directory for RAR5 filtered decoding above the buffering threshold')
            [CompletionResult]::new('--rar50-scratch-bytes', '--rar50-scratch-bytes', [CompletionResultType]::ParameterName, 'Maximum temporary bytes for RAR5 scratch decoding')
            [CompletionResult]::new('--rar50-filter-memory-limit', '--rar50-filter-memory-limit', [CompletionResultType]::ParameterName, 'Maximum workspace per RAR5 scratch filter')
            [CompletionResult]::new('--overwrite', '--overwrite', [CompletionResultType]::ParameterName, 'Behaviour when an extracted file already exists on disk')
            [CompletionResult]::new('--symlinks', '--symlinks', [CompletionResultType]::ParameterName, 'Which symbolic links and junctions to make, like unrar -ol, -ola and -ol-; hard links and file copies are always made')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--allow-rar3-vm', '--allow-rar3-vm', [CompletionResultType]::ParameterName, 'Run RAR 3 VM filter programs other than the six standard ones. Off by default: they are arbitrary bytecode from the archive and can use a lot of CPU time. Enable only for archives you trust')
            [CompletionResult]::new('--in-place', '--in-place', [CompletionResultType]::ParameterName, 'Write each file at its destination instead of staging it; a failed member leaves a partial file')
            [CompletionResult]::new('--keep-broken', '--keep-broken', [CompletionResultType]::ParameterName, 'Keep a damaged member''s file with what could be read of it, like unrar -kb; implies --in-place')
            [CompletionResult]::new('--flatten', '--flatten', [CompletionResultType]::ParameterName, 'Write every file straight into the output directory under its base name, creating no directories')
            [CompletionResult]::new('--ignore-attributes', '--ignore-attributes', [CompletionResultType]::ParameterName, 'Set no file or directory modes, like unrar -ai: files are created 0666 and directories 0777, less the umask; times are still restored')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;repair' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;add' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Target archive format (default: rar50, the modern widely-compatible format)')
            [CompletionResult]::new('--level', '--level', [CompletionResultType]::ParameterName, 'Compression level (0..5; 0 implies --store)')
            [CompletionResult]::new('--dict-size', '--dict-size', [CompletionResultType]::ParameterName, 'Dictionary size (e.g. 4m, 128k; RAR 1.5+)')
            [CompletionResult]::new('--memory-limit', '--memory-limit', [CompletionResultType]::ParameterName, 'Maximum total compression working memory (default: 256m, plus 160m per thread past the first, up to a quarter of RAM or the cgroup limit on Linux)')
            [CompletionResult]::new('--max-memory', '--max-memory', [CompletionResultType]::ParameterName, 'Hard managed-allocation ceiling for RAR5/7, separate from estimated workspace')
            [CompletionResult]::new('--temp-dir', '--temp-dir', [CompletionResultType]::ParameterName, 'Directory for temporary compressed payloads (RAR 5+)')
            [CompletionResult]::new('--comment', '--comment', [CompletionResultType]::ParameterName, 'Archive-level comment')
            [CompletionResult]::new('--archive-name', '--archive-name', [CompletionResultType]::ParameterName, 'Archive name to embed in archive metadata service (RAR 5+)')
            [CompletionResult]::new('--file-comment', '--file-comment', [CompletionResultType]::ParameterName, 'Per-file comment (not RAR 3.x/4.x)')
            [CompletionResult]::new('--recovery-percent', '--recovery-percent', [CompletionResultType]::ParameterName, 'Add a recovery record at the given percentage (1..100; RAR 5+)')
            [CompletionResult]::new('--volume-size', '--volume-size', [CompletionResultType]::ParameterName, 'Split archive into volumes of this size')
            [CompletionResult]::new('--delta-filter', '--delta-filter', [CompletionResultType]::ParameterName, 'Delta filter with the given channel count (RAR 2.9+)')
            [CompletionResult]::new('--rgb-filter', '--rgb-filter', [CompletionResultType]::ParameterName, 'RGB image filter with the given pixel width (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('--audio-filter', '--audio-filter', [CompletionResultType]::ParameterName, 'Audio filter with the given channel count (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('-C', '-C ', [CompletionResultType]::ParameterName, 'Read inputs from this directory and store names relative to it')
            [CompletionResult]::new('--base-dir', '--base-dir', [CompletionResultType]::ParameterName, 'Read inputs from this directory and store names relative to it')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--store', '--store', [CompletionResultType]::ParameterName, 'Store files without compression (equivalent to --level 0)')
            [CompletionResult]::new('--solid', '--solid', [CompletionResultType]::ParameterName, 'Use solid compression (treats inputs as one continuous stream)')
            [CompletionResult]::new('--encrypt-headers', '--encrypt-headers', [CompletionResultType]::ParameterName, 'Encrypt archive headers (RAR 3.x/4.x and RAR 5+) (requires --password)')
            [CompletionResult]::new('--quick-open', '--quick-open', [CompletionResultType]::ParameterName, 'Emit a quick-open service block (RAR 5+ only)')
            [CompletionResult]::new('--blake2sp', '--blake2sp', [CompletionResultType]::ParameterName, 'Store a BLAKE2sp hash of each file beside its CRC32 (RAR 5+ only)')
            [CompletionResult]::new('--e8-filter', '--e8-filter', [CompletionResultType]::ParameterName, 'E8 x86 call filter (RAR 2.9+)')
            [CompletionResult]::new('--e8e9-filter', '--e8e9-filter', [CompletionResultType]::ParameterName, 'E8E9 x86 call/jump filter (RAR 2.9+)')
            [CompletionResult]::new('--itanium-filter', '--itanium-filter', [CompletionResultType]::ParameterName, 'Itanium filter (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('--arm-filter', '--arm-filter', [CompletionResultType]::ParameterName, 'ARM filter (RAR 5+ only)')
            [CompletionResult]::new('--auto-filter', '--auto-filter', [CompletionResultType]::ParameterName, 'Auto-detect data filter (RAR 5+ does this by default)')
            [CompletionResult]::new('--no-filter', '--no-filter', [CompletionResultType]::ParameterName, 'Skip filter detection, compressing the data as it is (RAR 2.9+; the older formats never look, so the flag passes without comment there)')
            [CompletionResult]::new('--ppmd', '--ppmd', [CompletionResultType]::ParameterName, 'Use the PPMd compression algorithm (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
        'rars;a' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password', '--password', [CompletionResultType]::ParameterName, 'Archive password (visible in process list — prefer --password-file or the TTY prompt)')
            [CompletionResult]::new('--password-file', '--password-file', [CompletionResultType]::ParameterName, 'Read password from file ("-" for stdin); trailing newlines are stripped')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Target archive format (default: rar50, the modern widely-compatible format)')
            [CompletionResult]::new('--level', '--level', [CompletionResultType]::ParameterName, 'Compression level (0..5; 0 implies --store)')
            [CompletionResult]::new('--dict-size', '--dict-size', [CompletionResultType]::ParameterName, 'Dictionary size (e.g. 4m, 128k; RAR 1.5+)')
            [CompletionResult]::new('--memory-limit', '--memory-limit', [CompletionResultType]::ParameterName, 'Maximum total compression working memory (default: 256m, plus 160m per thread past the first, up to a quarter of RAM or the cgroup limit on Linux)')
            [CompletionResult]::new('--max-memory', '--max-memory', [CompletionResultType]::ParameterName, 'Hard managed-allocation ceiling for RAR5/7, separate from estimated workspace')
            [CompletionResult]::new('--temp-dir', '--temp-dir', [CompletionResultType]::ParameterName, 'Directory for temporary compressed payloads (RAR 5+)')
            [CompletionResult]::new('--comment', '--comment', [CompletionResultType]::ParameterName, 'Archive-level comment')
            [CompletionResult]::new('--archive-name', '--archive-name', [CompletionResultType]::ParameterName, 'Archive name to embed in archive metadata service (RAR 5+)')
            [CompletionResult]::new('--file-comment', '--file-comment', [CompletionResultType]::ParameterName, 'Per-file comment (not RAR 3.x/4.x)')
            [CompletionResult]::new('--recovery-percent', '--recovery-percent', [CompletionResultType]::ParameterName, 'Add a recovery record at the given percentage (1..100; RAR 5+)')
            [CompletionResult]::new('--volume-size', '--volume-size', [CompletionResultType]::ParameterName, 'Split archive into volumes of this size')
            [CompletionResult]::new('--delta-filter', '--delta-filter', [CompletionResultType]::ParameterName, 'Delta filter with the given channel count (RAR 2.9+)')
            [CompletionResult]::new('--rgb-filter', '--rgb-filter', [CompletionResultType]::ParameterName, 'RGB image filter with the given pixel width (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('--audio-filter', '--audio-filter', [CompletionResultType]::ParameterName, 'Audio filter with the given channel count (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('-C', '-C ', [CompletionResultType]::ParameterName, 'Read inputs from this directory and store names relative to it')
            [CompletionResult]::new('--base-dir', '--base-dir', [CompletionResultType]::ParameterName, 'Read inputs from this directory and store names relative to it')
            [CompletionResult]::new('--threads', '--threads', [CompletionResultType]::ParameterName, 'Worker threads for parallel compression and extraction (default: all available cores)')
            [CompletionResult]::new('--progress', '--progress', [CompletionResultType]::ParameterName, 'Progress reporting mode for long-running operations')
            [CompletionResult]::new('--store', '--store', [CompletionResultType]::ParameterName, 'Store files without compression (equivalent to --level 0)')
            [CompletionResult]::new('--solid', '--solid', [CompletionResultType]::ParameterName, 'Use solid compression (treats inputs as one continuous stream)')
            [CompletionResult]::new('--encrypt-headers', '--encrypt-headers', [CompletionResultType]::ParameterName, 'Encrypt archive headers (RAR 3.x/4.x and RAR 5+) (requires --password)')
            [CompletionResult]::new('--quick-open', '--quick-open', [CompletionResultType]::ParameterName, 'Emit a quick-open service block (RAR 5+ only)')
            [CompletionResult]::new('--blake2sp', '--blake2sp', [CompletionResultType]::ParameterName, 'Store a BLAKE2sp hash of each file beside its CRC32 (RAR 5+ only)')
            [CompletionResult]::new('--e8-filter', '--e8-filter', [CompletionResultType]::ParameterName, 'E8 x86 call filter (RAR 2.9+)')
            [CompletionResult]::new('--e8e9-filter', '--e8e9-filter', [CompletionResultType]::ParameterName, 'E8E9 x86 call/jump filter (RAR 2.9+)')
            [CompletionResult]::new('--itanium-filter', '--itanium-filter', [CompletionResultType]::ParameterName, 'Itanium filter (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('--arm-filter', '--arm-filter', [CompletionResultType]::ParameterName, 'ARM filter (RAR 5+ only)')
            [CompletionResult]::new('--auto-filter', '--auto-filter', [CompletionResultType]::ParameterName, 'Auto-detect data filter (RAR 5+ does this by default)')
            [CompletionResult]::new('--no-filter', '--no-filter', [CompletionResultType]::ParameterName, 'Skip filter detection, compressing the data as it is (RAR 2.9+; the older formats never look, so the flag passes without comment there)')
            [CompletionResult]::new('--ppmd', '--ppmd', [CompletionResultType]::ParameterName, 'Use the PPMd compression algorithm (RAR 2.9/3.x/4.x only)')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
