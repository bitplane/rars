# @bitplane/rars

Read, write and repair RAR archives in browsers and Node.

```sh
npm install @bitplane/rars
```

Every option is documented in the package's TypeScript declarations.

## Read

```js
import { RarArchive } from "@bitplane/rars";

const archive = await RarArchive.open(file, { password: "optional" });

for (const entry of archive.entries) {
  console.log(entry.name, entry.size, entry.isEncrypted);
}

const bytes = await archive.get("docs/readme.txt").bytes();
await archive.test();
```

`open()` accepts a `Blob`, `ArrayBuffer` or typed array, or an ordered array of
them for a volume set. Node also accepts paths and file URLs, and finds a set's
later volumes beside the first.

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

To edit an existing archive:

```js
const writer = await RarWriter.fromArchive(await RarArchive.open("old.rar"));
const bytes = await writer.remove("draft.txt").add("final.txt", text).bytes();
```

## Extract (Node)

```js
const written = await archive.extractAll("out", { overwrite: "rename" });
const one = await archive.get("docs/readme.txt").extract("out");
```

## Repair

```js
import { repair } from "@bitplane/rars";

const { data, report } = await repair(damaged, { password: "optional" });
```

## Loading

ES modules, Node `require`, bundlers and direct browser imports use the same
API, with no explicit Wasm initialisation:

```html
<script type="module">
  import { RarArchive } from "https://esm.sh/@bitplane/rars";
</script>
```

Direct cross-origin imports start a blob worker, so a Content Security Policy
must allow `blob:` in `worker-src`, or the package should be bundled or served
from the page's origin.

The same library is available as a [Rust crate][crate], [Python package][pypi]
and [command-line tool][repo].

## Development

`CARGO_BUILD_JOBS=1 scripts/build-npm.sh --debug` then
`node scripts/test-npm-package.js` builds and tests quickly (no LTO or
`wasm-opt`); drop `--debug` for release artifacts. Both need a `wasm-bindgen`
CLI matching `Cargo.lock`.

[crate]: https://crates.io/crates/rars
[pypi]: https://pypi.org/project/rars/
[repo]: https://github.com/bitplane/rars
