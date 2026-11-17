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

`get(name)` selects the last matching entry; `getAll(name)` returns every match
in archive order, and `has(name)` says whether there is one. Each returned entry
reads its own payload by index. In a volume set, `entry.volumeIndex` is the
volume the entry starts in, counting the first as 0. The archive says where it
sits in its set: `isVolume`, `volumeIndex` (from 0), `isFirstVolume` and
`volumeNaming` (`"part"` or `"old"`), the last three read from the headers.
`entry.readComment()` returns the comment attached to an entry, or undefined.
`entry.isLink` says whether it is a link, and `entry.readLink()` returns its raw
target from the headers without following it.

Node also accepts paths and file URLs. Opening the first volume of a set by path
finds the later volumes beside it, by the names RAR gives them, and stops at the
first that isn't there; `archive.volumePaths` lists the files it opened.

For legacy byte names, pass `legacyNameEncoding: "cp850"` to `open()`.
Supported encodings are `cp437`, `cp850`, `cp852`, `cp866`, `windows-1251`,
`windows-1252` and `utf-8` (`cp1251`, `cp1252` and `utf8` are aliases).
Names are case insensitive. Unicode names take precedence; unspecified legacy
encodings are never guessed. Invalid or undefined input fails conversion.
`entry.name` is the selected view and `entry.nameBytes` retains its original
identity. Reopen to select another encoding. `get()` refuses ambiguous decoded
names with `AMBIGUOUS_ENTRY`; use `getAll()` or archive-order entry indices.
This setting does not affect comments, passwords, payloads or writer names.

`open()`, `entry.bytes()`, `readMany()`, `test()` and `readComment()` accept `ReadOptions`:

```js
const limits = { maxHeaderCount: 10000, maxMemberOutputBytes: 256 * 1024 * 1024 };
const archive = await RarArchive.open(file, limits);
const bytes = await archive.entries[0].bytes(limits);
const selected = await archive.readMany([archive.entries[1], archive.entries[0]], limits);
const comment = await archive.readComment(limits); // undefined if absent
```

The optional fields are `maxHeaderCount`, `maxHeaderBytes`,
`maxMemberOutputBytes`, `maxTotalOutputBytes`, `maxReaderWorkspaceBytes`, `maxRar50DictionaryBytes` and
`maxRar50BufferedMemberBytes`. Values must be nonnegative safe integer numbers or
`bigint` values through `2n ** 64n - 1n`. Zero is a real limit. Omission retains
the library default. Options given to `open()` are the defaults for every later call
on that archive, and a call's own fields override them one by one.
Each operation reparses its input; header limits apply per archive/volume.
`readMany()` accepts an iterable of entries or names and performs one parse and
decoder traversal for the batch. Results retain request order and duplicates;
prefer entry objects for duplicate identity and direct index selection. Entries
from another archive are rejected. Solid predecessors are decoded once, and
output limits apply to the whole batch. Repeated results have independent byte
buffers but do not consume logical decode quota again. Failures return no partial
list. Directories are rejected; RAR5 redirections have no readable file payload.
The cached `archive.comment` is decoded under the options passed to `open()`;
`readComment()` decodes it again with fresh options and an optional password.

`allowRar3VmPrograms: true` lets RAR 2.9-4.x members run filter programs other
than the six standard ones (E8, E8E9, Itanium, Delta, RGB and Audio). It is off
by default because such programs are arbitrary bytecode from the archive and can
use a lot of CPU time; a member that needs one fails with `UNSUPPORTED_FEATURE`.
Current WinRAR does not run them either. Enable it only for archives you trust.

Output limits count logical decoded bytes, including discarded solid-prefix
output. Reading a volume entry currently decodes the whole volume set, so its
total-output limit includes other members. Limits are not an aggregate RAM
ceiling: inputs and returned outputs are materialised, and decoder workspace
has separate costs. RAR5/7 dictionary and buffered-decoding limits affect those
formats only. Filesystem scratch decoding is unavailable in the WASM backend.
Unknown-size RAR5 members are refused under a member-output limit; decode-to-end
support remains separate work.

`maxReaderWorkspaceBytes` limits aggregate reader allocation capacity per call,
including decoder state and queued parallel payloads. Source buffers, JavaScript
objects and returned bytes are outside the quota. Capacity replacement overlap
counts; this is not a process RAM limit. Refusals retain the resource error code
and byte details.

`isRarFile(input)` says whether the input starts with a RAR signature, and
`isRarFileSfx(input)` whether an archive starts in it, behind a self-extractor
stub or not. Only the bytes those need are read, and a path that can't be read
is not RAR.

`checkPassword(input, candidates)` tries passwords in order against one volume and
stops at the first proved correct. It returns `{ correct, undetermined,
needsPassword, archive }`: `undetermined` holds candidates a RAR 4 archive can't
prove without decoding data, and `archive` is opened with the correct one, or
without a password when the headers aren't encrypted.

## Write

```js
import { RarWriter } from "@bitplane/rars";

const writer = new RarWriter({ version: "rar50", level: 5 });
writer
  .add("hello.txt", "hello")
  .add("data.bin", payload, { mode: 0o644, mtime: new Date() });

const bytes = await writer.bytes();

const split = new RarWriter({ volumeSize: 5 * 1024 * 1024 }).add("big.bin", payload);
const parts = await split.volumes();
```

`add()` takes `mode`, `mtime` and a `comment` for the member, and for RAR 5
`atime` and `birthtime`. `addDirectory(name)` queues an explicit directory and
`addSymlink(name, target)` a Unix symbolic link, stored as given. `level` runs
from 0 (stored) to 5. Other writer options are `solid`, `password`,
`encryptHeaders`, `comment`, `recoveryPercent` and `volumeSize`. With
`volumeSize` set, `volumes()` returns the parts and `bytes()` refuses. Node
additionally provides `addFile()` and `writeTo(path)`, which writes the archive,
or every part of a set, and returns the paths written. It refuses an existing
file unless given `{ overwrite: true }`; a set checks every
part before writing any.
For legacy formats, `writeTo()` keeps the first path of a set and names later
volumes `.r00` through `.r99`, then `.s00` on up to `.z99` as RAR 4 does, in the
same directory. Sets exceeding 901 volumes or containing overlapping output
paths are rejected before any file is written.

`RarWriter.fromArchive(archive)` starts a writer holding every member of an
open archive, or of its whole volume set, with names, times, attributes,
comments and links carried over, to edit with `add()`, `remove()` and
`rename()` and write again:

```js
const writer = await RarWriter.fromArchive(await RarArchive.open("old.rar"));
const bytes = await writer.remove("draft.txt").add("final.txt", text).bytes();
```

By default it keeps the source's format, settings and encryption, and refuses
an archive whose settings it can't keep; `{ preserve: false }` writes RAR 5 at
level 3 instead. Members' data is decoded and verified, in memory, when the
archive is written, so the source must still be readable then;
`maxStagedBytes` caps how much is held at once.

Long operations accept an `AbortSignal` and a progress callback, called with the
phase (`reading`, `testing`, `compressing`, `protecting`, `writing` or
`repairing`) and bytes `completed` of `total`, which is absent until known.
Writing, testing and reading from one archive report as the engine goes; reading
selected entries of a volume set, and repairing, report only start and end:

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
entry names as raw byte arrays, operations, archive offsets and volume indices,
counting the first volume as 0.
Resource-limit details use decimal strings for byte counts, preserving values
beyond JavaScript’s exact integer range. Node filesystem errors use `IO` with
the original system code, errno and syscall in `details`.

Aborting queued work rejects it immediately without interrupting the active
operation. Aborting active work terminates its worker; later operations start
a fresh worker. This is worker termination, so it does not run cooperative Rust
cleanup or undo completed filesystem writes. Interrupted Node writes may leave
staged temporary files. No separate cancellation-token object is needed in JS.

`RarWriter` accepts `maxMemoryBytes` as a nonnegative safe integer or a `bigint`
through `2n ** 64n - 1n`. It caps managed RAR5/7 execution allocation capacity,
including retained WASM spools, archive/volume output and the final JavaScript
payload copy. The default is unlimited; zero admits no managed allocation.
A refusal has code `RESOURCE_LIMIT`; the constructor refuses it for older
versions with `INVALID_OPTION`, as it does any setting the version can't write.
Caller inputs, returned caller-owned bytes, JavaScript
runtime objects, allocator overhead, stacks and OS memory are excluded. This is
not a process-memory ceiling and does not bound reading or rewrite staging.

## Extract (Node)

```js
const written = await archive.extractAll("out", { overwrite: "rename" });
const one = await archive.get("docs/readme.txt").extract("out");
```

`extractAll()` decodes in one pass and writes each file only once it has been
verified, under paths the core checks stay inside the directory. An existing
file is refused unless `overwrite` is `true`, or kept with the new one written
beside it as `name(N).ext` under `"rename"`. `members` selects entries,
`flatten: true` drops stored directories, and `restoreTimes` (on by default)
sets modification times. Symbolic links, hard links and file copies are written
too, under the same overwrite rules. A symbolic link that could lead outside the
directory, directly or through a link already there, is skipped with an
`UnsafeLinkWarning` process warning. It returns the files and links written.

In Node, `test()` and `extractAll()` also take `volumes`, an iterable or async
iterable of a set's later parts, paths or bytes, to read a set while it is still
arriving, as Python's `volumes=`. The archive is opened with its first volume
alone, and each later part is pulled only when extraction reaches it:

```js
const archive = await RarArchive.open(firstPart);
await archive.extractAll("out", { volumes: downloads() }); // an async generator
```

A part the iterator never yields fails with `MISSING_VOLUME`, and an error it
throws is raised as it was. Browsers take every volume up front instead.

## Repair

```js
import { repair } from "@bitplane/rars";

const { data, report } = await repair(damaged, { password: "optional" });
console.log(report.dataRepaired, report.recoveryRecordRebuilt);
```

`repair()` rebuilds a RAR 5 archive from its recovery record. In Node,
`{ output: path }` writes the result there instead and leaves `data` undefined;
an existing file is refused unless `overwrite: true`.

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

## Development validation

Run `CARGO_BUILD_JOBS=1 scripts/build-npm.sh --debug` and then
`node scripts/test-npm-package.js` for focused engine and worker checks.
The debug build skips LTO and `wasm-opt`. Build release artifacts with
`scripts/build-npm.sh` without `--debug`. Both modes require a `wasm-bindgen`
CLI matching `Cargo.lock`.

## Development coverage

From the repository root, run `python3 scripts/coverage-wasm.py` to measure
Rust engine coverage under Node. It requires Node, `wasm-bindgen` matching
`Cargo.lock`, and a Rust nightly using LLVM 23 with `wasm32-unknown-unknown`
and `llvm-tools-preview` installed. The command uses one build job and at most
two available CPUs, and saves reports under the ignored
`target/coverage-wasm-focused` directory.

An independent two-branch probe checks the measurement before testing the
engine. Private error conversion tests are compiled with `cfg(test)`;
their exports and the profiling runtime stub are absent from release builds.
This measures Rust WASM source, separately from JavaScript facade coverage.

[crate]: https://crates.io/crates/rars
[pypi]: https://pypi.org/project/rars/
[repo]: https://github.com/bitplane/rars
