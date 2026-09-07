# Repair cancellation

`repair`, `repair_detailed` and `repair_to_path` accept a keyword-only
`cancellation=rars.CancellationToken()` argument. Omitting it retains the default
repair behaviour and password handling.

```python
from concurrent.futures import ThreadPoolExecutor
import rars

token = rars.CancellationToken()
with ThreadPoolExecutor(max_workers=1) as pool:
    work = pool.submit(
        rars.repair_to_path, "damaged.rar", "repaired.rar", cancellation=token
    )
    # Another thread can request cancellation while repair runs.
    # token.cancel()
    work.result()
```

Cancellation raises `InterruptedError`, including when requested before reading
the input. Path input is read in bounded chunks. Parsing, recovery decoding,
sector checks, RAR5 chunk scanning, reconstruction and record rebuilding observe
the token. Cancellation during parsing does not start the raw damaged-header
fallback, and cancellation during recovery-record rebuilding is not treated as
an optional rebuild failure. Repair releases the GIL during this work and needs
no progress callback.

Cancellation is cooperative. Blocked I/O, allocation, copies, key derivation and
individual library operations cannot be preempted. These APIs still retain input
and repaired bytes in memory; cancellation is not a memory or output quota.
`ReadOptions` is not accepted by Python repair methods.

`repair` and `repair_detailed` return complete results or raise. Tokens are
reusable after success or unrelated failure, but a cancelled token cannot be
reset. Use a fresh token for another repair after cancelling.

`repair_to_path` writes and syncs a temporary file beside the destination, then
checks cancellation before replacing the destination. Failure before replacement
cleans up the temporary file and leaves an existing destination intact. The input
and output may be the same path. Cancellation after the final check cannot stop
the rename; a completed publication is not rolled back. This replaces the old
direct-write behaviour and requires space beside the output for the staged file.
