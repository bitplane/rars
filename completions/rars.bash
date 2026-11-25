_rars() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="rars"
                ;;
            rars,a)
                cmd="rars__subcmd__add"
                ;;
            rars,add)
                cmd="rars__subcmd__add"
                ;;
            rars,extract)
                cmd="rars__subcmd__extract"
                ;;
            rars,info)
                cmd="rars__subcmd__info"
                ;;
            rars,repair)
                cmd="rars__subcmd__repair"
                ;;
            rars,test)
                cmd="rars__subcmd__test"
                ;;
            rars,x)
                cmd="rars__subcmd__extract"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        rars)
            opts="-h -V --threads --progress --help --version info test extract x repair add a"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rars__subcmd__add)
            opts="-p -C -h -V --password --password-file --format --store --level --dict-size --memory-limit --max-memory --temp-dir --solid --encrypt-headers --quick-open --blake2sp --comment --archive-name --file-comment --recovery-percent --volume-size --delta-filter --e8-filter --e8e9-filter --itanium-filter --rgb-filter --audio-filter --arm-filter --auto-filter --no-filter --ppmd --base-dir --threads --progress --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --password)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "rar14 rar15 rar20 rar29 rar30 rar40 rar50 rar70" -- "${cur}"))
                    return 0
                    ;;
                --level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dict-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --memory-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-memory)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --temp-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --comment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --archive-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file-comment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --recovery-percent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --volume-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --delta-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rgb-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --audio-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --base-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -C)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rars__subcmd__extract)
            opts="-p -h -V --password --password-file --legacy-name-encoding --rar50-buffered-decode-limit --rar50-decode-workers --rar50-dictionary-size-limit --max-member-output-bytes --max-total-output-bytes --max-reader-workspace-bytes --max-header-count --max-header-bytes --rar50-scratch-dir --rar50-scratch-bytes --rar50-filter-memory-limit --allow-rar3-vm --overwrite --in-place --keep-broken --flatten --threads --progress --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --password)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --legacy-name-encoding)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-buffered-decode-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-decode-workers)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-dictionary-size-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-member-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-total-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-reader-workspace-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-count)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-filter-memory-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --overwrite)
                    COMPREPLY=($(compgen -W "never always rename" -- "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rars__subcmd__info)
            opts="-p -v -h -V --legacy-name-encoding --rar50-buffered-decode-limit --rar50-decode-workers --rar50-dictionary-size-limit --max-member-output-bytes --max-total-output-bytes --max-reader-workspace-bytes --max-header-count --max-header-bytes --rar50-scratch-dir --rar50-scratch-bytes --rar50-filter-memory-limit --allow-rar3-vm --password --password-file --verbose --threads --progress --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --legacy-name-encoding)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-buffered-decode-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-decode-workers)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-dictionary-size-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-member-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-total-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-reader-workspace-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-count)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-filter-memory-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rars__subcmd__repair)
            opts="-p -h -V --password --password-file --threads --progress --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --password)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rars__subcmd__test)
            opts="-p -h -V --password --password-file --legacy-name-encoding --rar50-buffered-decode-limit --rar50-decode-workers --rar50-dictionary-size-limit --max-member-output-bytes --max-total-output-bytes --max-reader-workspace-bytes --max-header-count --max-header-bytes --rar50-scratch-dir --rar50-scratch-bytes --rar50-filter-memory-limit --allow-rar3-vm --threads --progress --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --password)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --legacy-name-encoding)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-buffered-decode-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-decode-workers)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-dictionary-size-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-member-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-total-output-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-reader-workspace-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-count)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-header-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-scratch-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rar50-filter-memory-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --progress)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _rars -o nosort -o bashdefault -o default rars
else
    complete -F _rars -o bashdefault -o default rars
fi
