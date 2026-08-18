# @bitplane/rars

Read, write and repair RAR archives in the browser or Node using [rars][repo]
via WebAssembly. `rars` reads and writes every RAR version from 1.3 to 7.0 and
compresses reasonably well at a sensible speed.

[repo]: https://github.com/bitplane/rars

```
npm install @bitplane/rars
```

## Reading

```js
import { RarFile } from "@bitplane/rars";

const rar = new RarFile(new Uint8Array(await file.arrayBuffer()));

for (const entry of rar.entries()) {
  console.log(entry.name, entry.size, entry.isEncrypted);
}

const bytes = rar.read("docs/readme.txt");
rar.test();          // throws on the first bad checksum
rar.free();          // archive stays in memory otherwise
```

Passwords go in as a string or a `Uint8Array`. Encrypted headers blocks listing
without a password, but many archives just have encrypted members:

```js
const locked = new RarFile(bytes, "hunter2");   // encrypted headers
const data = rar.read("secret.txt", "hunter2"); // encrypted data
```

## Writing

```js
import { RarBuilder } from "@bitplane/rars";

const builder = new RarBuilder({ format: "rar50", compression: 5 });
builder.addBytes("hello.txt", new TextEncoder().encode("hello"));
builder.addBytes("data.bin", payload, { mode: 0o100644 });

const archive = builder.toBytes();
```

`format` takes any of `rar13`, `rar14`, `rar15`, `rar20`, `rar29`, `rar30`,
`rar40`, `rar50` or `rar70`. The rest of the options are `compression` (0 to
5), `store`, `solid`, `password`, `encryptHeaders`, `comment`,
`recoveryPercent` and `volumeSize`.

Volume sets come back as an array:

```js
const builder = new RarBuilder({ volumeSize: 5 * 1024 * 1024 });
builder.addBytes("big.iso", payload);
const parts = builder.toVolumes();
```

## Loading

The package ships three builds, auto chosen:

| Importer                     | Gets      | Needs          |
| ---------------------------- | --------- | -------------- |
| Vite, webpack, Rollup, Next  | `bundler` | nothing        |
| Node, `require` or `import`  | `node`    | nothing        |
| A browser with no build step | `web`     | `await init()` |

Only the browser build has to be initialised, because it fetches the
`.wasm`:

```html
<script type="module">
  import init, { RarFile } from "https://esm.sh/@bitplane/rars/web";
  await init();
</script>
```

## Caveats

Compression is synchronous and single-threaded - you'll need to run it in a
Worker until I sort that out. Progress updates aren't yet included either.

There is no filesystem, so read the file yourself and pass the bytes.

## Elsewhere

The same library is a [Rust crate][crate], a [Python package][pypi] and a
[command-line tool][repo]. Published together from CI so version numbers match
up.

[crate]: https://crates.io/crates/rars
[pypi]: https://pypi.org/project/rars/
