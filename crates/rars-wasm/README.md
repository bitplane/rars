# @bitplane/rars

Read, write and repair RAR archives in browsers and Node.

```sh
npm install @bitplane/rars
```

## Read

```js
import { RarArchive } from "@bitplane/rars";

const archive = await RarArchive.open(file, { password: "optional" });

for (const entry of archive.entries) {
  console.log(entry.name, entry.size, entry.isEncrypted);
}

const bytes = await archive.get("docs/readme.txt").bytes();
await archive.test();
archive.close(); // optional; releases retained input eagerly
```

`open()` accepts a `Blob`, `ArrayBuffer` or typed array. Pass an ordered array
to open a volume set. Entry objects use archive-order indices internally, so
duplicate names and non-UTF-8 names remain unambiguous; `nameBytes` contains
the exact header bytes.

Node also accepts paths and file URLs. Passing the first path of a conventional
volume set discovers its siblings automatically.

`open()`, `entry.bytes()`, `test()` and `readComment()` accept `ReadOptions`:

```js
const limits = { maxHeaderCount: 10000, maxMemberOutputBytes: 256 * 1024 * 1024 };
const archive = await RarArchive.open(file, limits);
const bytes = await archive.entries[0].bytes(limits);
const comment = await archive.readComment(limits); // undefined if absent
```

The optional fields are `maxHeaderCount`, `maxHeaderBytes`,
`maxMemberOutputBytes`, `maxTotalOutputBytes`, `rar50DictionarySizeLimit` and
`rar50BufferedDecodeLimit`. Values must be nonnegative safe integer numbers or
`bigint` values through `2n ** 64n - 1n`. Zero is a real limit. Omission retains
the library default. Options apply to one call and are not retained by `open()`.
Each operation reparses its input; header limits apply per archive/volume.
The cached `archive.comment` is decoded under the options passed to `open()`;
`readComment()` decodes it again with fresh options and an optional password.

Output limits count logical decoded bytes, including discarded solid-prefix
output. Reading a volume entry currently decodes the whole volume set, so its
total-output limit includes other members. Limits are not an aggregate RAM
ceiling: inputs and returned outputs are materialised, and decoder workspace
has separate costs. RAR5/7 dictionary and buffered-decoding limits affect those
formats only. Filesystem scratch decoding is unavailable in the WASM backend.
Unknown-size RAR5 members are refused under a member-output limit; decode-to-end
support remains separate work.

## Write

```js
import { RarWriter } from "@bitplane/rars";

const writer = new RarWriter({ format: "rar50", level: 5 });
writer
  .add("hello.txt", "hello")
  .add("data.bin", payload, { mode: 0o644, modifiedAt: new Date() });

const bytes = await writer.bytes();
const parts = await writer.volumes(5 * 1024 * 1024);
```

`level` runs from 0 (stored) to 5. Other options are `solid`, `password`,
`encryptHeaders`, `comment` and `recoveryPercent`. Node additionally provides
`addFile()`, `writeTo()` and `writeVolumesTo()`.

Long operations accept an `AbortSignal` and progress callback:

```js
const bytes = await writer.bytes({
  signal: controller.signal,
  onProgress: ({ phase, completed, total }) => {
    console.log(phase, completed, total);
  },
});
```

Errors are `RarError` instances with a stable `code`; client `AbortSignal`
cancellation uses the standard `AbortError`. Core errors carry their code through
WASM and the worker without parsing message text. `details.contexts` retains
entry names as raw byte arrays, operations, archive offsets and volume numbers.
Resource-limit details use decimal strings for byte counts, preserving values
beyond JavaScript’s exact integer range. Node filesystem errors use `IO` with
the original system code, errno and syscall in `details`.

## Loading

ES modules, Node `require`, Vite, webpack, Rollup and direct browser imports use
the same API and require no explicit Wasm initialisation:

```html
<script type="module">
  import { RarArchive } from "https://esm.sh/@bitplane/rars";
</script>
```

Direct cross-origin imports use a small blob worker bootstrap. A restrictive
Content Security Policy must therefore allow `blob:` in `worker-src`, or the
package assets should be bundled or served from the page's origin.

The current API materialises input and output bytes. True backpressured stream
input/output will be added separately rather than presenting a stream that
secretly buffers an entire archive.

The same library is available as a [Rust crate][crate], [Python package][pypi]
and [command-line tool][repo].

[crate]: https://crates.io/crates/rars
[pypi]: https://pypi.org/project/rars/
[repo]: https://github.com/bitplane/rars
