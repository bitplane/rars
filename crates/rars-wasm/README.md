# @bitplane/rars

Read, write and repair RAR archives in the browser and in Node. No native
module, no `unrar` binary, no download step. It is the [rars][repo] Rust
toolkit compiled to WebAssembly, and it writes every RAR version from 1.3 to
7.0 as well as reading them.

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
rar.free();          // the archive stays in wasm memory until you say so
```

Passwords go in as a string or a `Uint8Array`. An archive with encrypted
headers needs one to open at all; an archive with encrypted data in plain
headers needs one only to read:

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

Volume sets come back as an array, and naming the parts is yours to do because
the two families number them differently:

```js
const builder = new RarBuilder({ volumeSize: 5 * 1024 * 1024 });
builder.addBytes("big.iso", payload);
const parts = builder.toVolumes();
```

## Loading

The package ships three builds and the right one is picked for you.

| Importer | Gets | Needs |
| --- | --- | --- |
| Vite, webpack, Rollup, Next | `bundler` | nothing |
| Node, `require` or `import` | `node` | nothing |
| A browser with no build step | `web` | `await init()` |

Only the browser-direct build has to be initialised, because it fetches the
`.wasm` itself:

```html
<script type="module">
  import init, { RarFile } from "https://esm.sh/@bitplane/rars/web";
  await init();
</script>
```

## What is not here

Compression is synchronous and single-threaded. A large input at level 5 is
seconds of work with nothing yielding, so run it in a Worker if the page has to
stay responsive. There are no progress callbacks yet for the same reason: the
writer reports progress from inside that call, and a JavaScript function cannot
be handed across it.

There is no filesystem, so nothing takes or returns a path. Read the file
yourself and pass the bytes.

## Elsewhere

The same library is a [Rust crate][crate], a [Python package][pypi] and a
[command-line tool][repo]. All four are built from one tag and share a version
number, so `@bitplane/rars@0.7.2` on npm is the same encoder as `rars==0.7.2`
on PyPI. The npm name is scoped only because npm's typo-squat filter refuses
the bare one.

[crate]: https://crates.io/crates/rars
[pypi]: https://pypi.org/project/rars/
