# flat_links.rar

Every RAR 5 link kind in nested directories, for flat extraction. Stored, no
extended times.

| member | kind | target |
|---|---|---|
| `c/target.txt` | file, `target\n` | |
| `local.txt` | file, `local\n` | |
| `b/hard.txt` | hard link | `c/target.txt` |
| `b/copy.txt` | file copy | `c/target.txt` |
| `a/abs.txt` | Unix symlink | `/etc/hosts` |
| `a/sym.txt` | Unix symlink | `../c/target.txt` |
| `a/near.txt` | Unix symlink | `local.txt` |

Plus the directories `a`, `b` and `c`. Made with RAR 7 on macOS:

    rar a -r -oh -ol -oi:1 -m0 -tsm- -tsc- -tsa- flat_links.rar c local.txt b a
