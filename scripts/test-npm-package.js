// Exercise the built npm package under Node.
//
// This is the only place the JavaScript API is executed rather than compiled,
// so it checks the boundary rather than the codec: that a builder writes an
// archive the reader reads back, that every format reaches the same bytes, and
// that the errors arrive as thrown `Error`s rather than as panics. The codec
// itself is covered by the Rust suite.
//
// Run it after scripts/build-npm.sh:  node scripts/test-npm-package.js

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const rars = require(path.join(here, "..", "npm", "node", "rars_wasm.js"));
const { RarFile, RarBuilder, repair, version, formats } = rars;

let passed = 0;
function check(name, body) {
  body();
  passed += 1;
  console.log(`  ok  ${name}`);
}

const text = new TextEncoder();
const decode = (bytes) => new TextDecoder().decode(bytes);
const HELLO = text.encode("hello from rars ".repeat(64));
const SECOND = text.encode("a second member");

console.log(`rars ${version()}`);

check("every format writes an archive this reader reads back", () => {
  for (const format of formats()) {
    const builder = new RarBuilder({ format });
    builder.addBytes("hello.txt", HELLO);
    builder.addBytes("dir/second.txt", SECOND);

    const archive = new RarFile(builder.toBytes());
    assert.deepEqual(archive.names(), ["hello.txt", "dir/second.txt"], format);
    assert.deepEqual(archive.read("hello.txt"), HELLO, format);
    assert.deepEqual(archive.read("dir/second.txt"), SECOND, format);
    archive.test();
    archive.free();
    builder.free();
  }
});

check("compression actually compresses", () => {
  const builder = new RarBuilder({ format: "rar50", compression: 5 });
  builder.addBytes("repeated.txt", text.encode("x".repeat(100000)));
  const compressed = builder.toBytes();

  const stored = new RarBuilder({ format: "rar50", store: true });
  stored.addBytes("repeated.txt", text.encode("x".repeat(100000)));

  assert.ok(
    compressed.length < stored.toBytes().length / 10,
    `expected a big win, got ${compressed.length} vs ${stored.toBytes().length}`,
  );
});

check("entry metadata comes through", () => {
  const builder = new RarBuilder({ format: "rar50" });
  builder.addBytes("hello.txt", HELLO, { mode: 0o100644 });
  const archive = new RarFile(builder.toBytes());

  const [info] = archive.entries();
  assert.equal(info.name, "hello.txt");
  assert.equal(info.size, HELLO.length);
  assert.equal(info.isDirectory, false);
  assert.equal(info.isEncrypted, false);
  assert.ok(info.packedSize > 0);
  assert.deepEqual(info.nameBytes, text.encode("hello.txt"));

  assert.equal(archive.getInfo("nope"), undefined);
  assert.equal(archive.getInfo("hello.txt").size, HELLO.length);
});

check("a password round-trips as a string and as bytes", () => {
  for (const password of ["hunter2", text.encode("hunter2")]) {
    const builder = new RarBuilder({ format: "rar50", password });
    builder.addBytes("secret.txt", HELLO);
    const archive = new RarFile(builder.toBytes());

    assert.equal(archive.needsPassword, true);
    assert.deepEqual(archive.read("secret.txt", "hunter2"), HELLO);
    assert.throws(() => archive.read("secret.txt", "wrong"));
  }
});

check("encrypted headers hide the names until unlocked", () => {
  const builder = new RarBuilder({
    format: "rar50",
    password: "hunter2",
    encryptHeaders: true,
  });
  builder.addBytes("secret.txt", HELLO);
  const bytes = builder.toBytes();

  assert.throws(() => new RarFile(bytes));
  const archive = new RarFile(bytes, "hunter2");
  assert.deepEqual(archive.read("secret.txt"), HELLO);
});

check("an archive comment survives", () => {
  const builder = new RarBuilder({ format: "rar50", comment: "written by rars" });
  builder.addBytes("hello.txt", HELLO);
  const archive = new RarFile(builder.toBytes());
  assert.equal(decode(archive.comment), "written by rars");
});

check("a volume set splits and the parts are readable", () => {
  const builder = new RarBuilder({
    format: "rar50",
    store: true,
    volumeSize: 64 * 1024,
  });
  builder.addBytes("big.bin", new Uint8Array(300000).fill(7));

  const volumes = builder.toVolumes();
  assert.ok(volumes.length > 1, `expected a split, got ${volumes.length}`);
  assert.ok(volumes.every((volume) => volume instanceof Uint8Array));
  // The first volume opens on its own; the rest are continuations of it.
  assert.deepEqual(new RarFile(volumes[0]).names(), ["big.bin"]);
});

check("a recovery record repairs a damaged archive", () => {
  // Stored and large, so the midpoint of the file is certainly inside the
  // payload. Repair reads the headers to find the recovery record, so damage
  // to a header is past what it can fix and is not what this checks.
  const payload = new Uint8Array(200000);
  for (let i = 0; i < payload.length; i += 1) {
    payload[i] = (i * 7 + (i >> 5)) & 0xff;
  }
  const builder = new RarBuilder({ format: "rar50", store: true, recoveryPercent: 10 });
  builder.addBytes("payload.bin", payload);

  const damaged = Uint8Array.from(builder.toBytes());
  for (let i = 0; i < 64; i += 1) {
    damaged[Math.floor(damaged.length / 2) + i] ^= 0xff;
  }
  assert.throws(() => new RarFile(damaged).test(), "damage should be detected");

  const fixed = repair(damaged);
  assert.deepEqual(new RarFile(fixed).read("payload.bin"), payload);
});

check("builder edits apply before writing", () => {
  const builder = new RarBuilder({ format: "rar50" });
  builder.addBytes("a.txt", HELLO);
  builder.addBytes("b.txt", SECOND);
  builder.rename("a.txt", "renamed.txt");
  builder.remove("b.txt");

  assert.deepEqual(builder.names(), ["renamed.txt"]);
  assert.equal(builder.length, 1);
  assert.deepEqual(new RarFile(builder.toBytes()).names(), ["renamed.txt"]);
});

check("bad input throws instead of trapping", () => {
  assert.throws(() => new RarFile(text.encode("not a rar at all")));
  assert.throws(() => new RarBuilder({ format: "zip" }), /unsupported RAR format/);
  assert.throws(() => new RarBuilder({ compression: "loads" }), /must be a number/);

  const builder = new RarBuilder({ format: "rar50" });
  builder.addBytes("a.txt", HELLO);
  assert.throws(() => builder.addBytes("a.txt", HELLO), /duplicate/);
  assert.throws(() => builder.addBytes("../escape", HELLO), /unsafe/);
  assert.throws(() => builder.addBytes("/absolute", HELLO), /unsafe/);
  assert.throws(() => builder.remove("nothing"), /no such/);

  // Nothing queued is not an archive, and neither is a volume set asked for
  // without a size.
  assert.throws(() => new RarBuilder({}).toBytes(), /no entries/);
  assert.throws(() => builder.toVolumes(), /volume_size is required/);
});

check("the bundler and web builds ship the same module", () => {
  const { readFileSync } = require("node:fs");
  const node = readFileSync(path.join(here, "..", "npm", "node", "rars_wasm_bg.wasm"));
  for (const target of ["bundler", "web"]) {
    const other = readFileSync(path.join(here, "..", "npm", target, "rars_wasm_bg.wasm"));
    assert.deepEqual(other, node, `${target} differs from node`);
  }
});

console.log(`\n${passed} checks passed`);
