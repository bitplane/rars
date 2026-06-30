# RAR 4.20 Container Fixtures

RAR 4.20 cross-version fixtures copied from the spec repository's
`fixtures/1.5-4.x/rar420/` set.

| Fixture | Purpose |
|---|---|
| `ext_time_rar420.rar` | Extended-time (`LHD_EXTTIME`) nibble groups for mtime/ctime/atime. |

The RAR 4.20 header-encrypted fixture is stored in the sibling `encrypted/`
directory as `header_rar420_password.rar`, because the tests group all
password-protected fixtures together.
