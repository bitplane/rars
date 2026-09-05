// Exercise the packed-shape async JavaScript API under Node.
import "./test-npm-api.mjs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const commonjs = require(path.join(here, "..", "npm"));
const esm = await import(pathToFileURL(path.join(here, "..", "npm", "node", "index.js")));
const { RarArchive, RarWriter, RarError, repair, repairDetailed, version, formats } = esm;

let passed = 0;
async function check(name, body) {
  await body();
  passed += 1;
  console.log(`  ok  ${name}`);
}

const text = new TextEncoder();
const decode = (bytes) => new TextDecoder().decode(bytes);
const HELLO = text.encode("hello from rars ".repeat(64));
const SECOND = text.encode("a second member");

console.log(`rars ${version}`);

await check("CommonJS and ESM expose the same async API", async () => {
  assert.equal(typeof commonjs.RarArchive.open, "function");
  assert.equal(commonjs.version, version);
  assert.deepEqual(commonjs.formats, formats);
});

await check("every format round-trips without blocking API calls", async () => {
  for (const format of formats) {
    const writer = new RarWriter({ format });
    writer.add("hello.txt", HELLO).add("dir/second.txt", SECOND);
    const input = HELLO.buffer;
    const bytes = await writer.bytes();
    assert.equal(input.byteLength, HELLO.byteLength, "input must not be detached");
    const archive = await RarArchive.open(bytes);
    assert.deepEqual(archive.entries.map((entry) => entry.name), ["hello.txt", "dir/second.txt"]);
    assert.deepEqual(await archive.get("hello.txt").bytes(), HELLO, format);
    await archive.test();
    archive.close();
    writer.close();
  }
});

await check("metadata and immutable entry objects are friendly JavaScript", async () => {
  const writer = new RarWriter({ format: "rar50" });
  writer.add("hello.txt", HELLO, {
    mode: 0o100644,
    modifiedAt: new Date("2025-02-03T04:05:06Z"),
  });
  const archive = await RarArchive.open(await writer.bytes());
  const [entry] = archive.entries;
  assert.equal(entry.name, "hello.txt");
  assert.equal(entry.size, HELLO.length);
  assert.equal(entry.isDirectory, false);
  assert.ok(entry.compressedSize > 0);
  assert.ok(Object.isFrozen(entry));
  assert.deepEqual(archive.get(entry.nameBytes), entry);
  assert.deepEqual(archive.getAll("hello.txt"), [entry]);
});

await check("passwords, comments and structured errors work", async () => {
  const writer = new RarWriter({
    format: "rar50",
    password: "hunter2",
    encryptHeaders: true,
    comment: "written by rars",
  });
  writer.add("secret.txt", HELLO);
  const bytes = await writer.bytes();
  await assert.rejects(RarArchive.open(bytes), (error) =>
    error instanceof RarError && error.code === "PASSWORD_REQUIRED");
  const archive = await RarArchive.open(bytes, { password: "hunter2" });
  assert.equal(decode(archive.comment), "written by rars");
  assert.deepEqual(await archive.get("secret.txt").bytes(), HELLO);
});

await check("volume sets are logical archives", async () => {
  const payload = new Uint8Array(300000).fill(7);
  const writer = new RarWriter({ format: "rar50", level: 0 });
  writer.add("big.bin", payload);
  const volumes = await writer.volumes(64 * 1024);
  assert.ok(volumes.length > 1);
  const archive = await RarArchive.open(volumes);
  assert.deepEqual(archive.entries.map((entry) => entry.name), ["big.bin"]);
  assert.deepEqual(await archive.entries[0].bytes(), payload);
});

await check("repair restores damaged bytes", async () => {
  const payload = Uint8Array.from({ length: 200000 }, (_, index) => (index * 7 + (index >> 5)) & 0xff);
  const writer = new RarWriter({ format: "rar50", level: 0, recoveryPercent: 10 });
  writer.add("payload.bin", payload);
  const damaged = Uint8Array.from(await writer.bytes());
  for (let i = 0; i < 64; i += 1) damaged[Math.floor(damaged.length / 2) + i] ^= 0xff;
  const fixed = await repair(damaged);
  const archive = await RarArchive.open(fixed);
  assert.deepEqual(await archive.entries[0].bytes(), payload);

  const detailed = await repairDetailed(damaged);
  assert.equal(detailed.report.changed, true);
  assert.equal(detailed.report.dataRepaired, true);
  assert.ok(detailed.report.expectedRecoveryShards >= 1);
  const detailedArchive = await RarArchive.open(detailed.data);
  assert.deepEqual(await detailedArchive.entries[0].bytes(), payload);
});

await check("codec work leaves the Node event loop responsive", async () => {
  const writer = new RarWriter({ format: "rar50", level: 5 });
  writer.add("large.txt", new Uint8Array(4_000_000).fill(120));
  let ticks = 0;
  const timer = setInterval(() => { ticks += 1; }, 1);
  await writer.bytes();
  clearInterval(timer);
  assert.ok(ticks > 0, `expected timer ticks during compression, got ${ticks}`);
});

await check("AbortSignal cancels active work and the runtime recovers", async () => {
  const writer = new RarWriter({ format: "rar50", level: 5 });
  const noisy = Uint8Array.from({ length: 8_000_000 }, (_, index) => (index * 131) & 0xff);
  writer.add("large.bin", noisy);
  const controller = new AbortController();
  const pending = writer.bytes({ signal: controller.signal });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(pending, (error) => error.name === "AbortError");

  const small = new RarWriter().add("ok.txt", "ok");
  const archive = await RarArchive.open(await small.bytes());
  assert.equal(decode(await archive.entries[0].bytes()), "ok");
});

await check("Node path input and atomic file output work", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "rars-js-"));
  try {
    const source = path.join(directory, "source.txt");
    const output = path.join(directory, "output.rar");
    await writeFile(source, HELLO);
    const writer = new RarWriter().addFile("source.txt", source);
    await writer.writeTo(output);
    const archive = await RarArchive.open(output);
    assert.deepEqual(await archive.entries[0].bytes(), new Uint8Array(await readFile(source)));

    const split = new RarWriter({ format: "rar50", level: 0 })
      .add("large.bin", new Uint8Array(180000).fill(9));
    const paths = await split.writeVolumesTo(path.join(directory, "split.rar"), 64 * 1024);
    assert.ok(paths.length > 1);
    const volumeArchive = await RarArchive.open(paths[0]);
    assert.equal((await volumeArchive.entries[0].bytes()).length, 180000);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await check("invalid options fail before starting a worker", async () => {
  assert.throws(() => new RarWriter({ level: 6 }), /level/);
  assert.throws(() => new RarWriter({ solid: "yes" }), /boolean/);
  assert.throws(() => new RarWriter().add("../escape", HELLO), /unsafe/);
  const writer = new RarWriter();
  writer.add("a.txt", HELLO);
  assert.throws(() => writer.add("a.txt", HELLO), (error) => error.code === "DUPLICATE_ENTRY");
  writer.close();
  assert.throws(() => writer.add("b.txt", HELLO), (error) => error.code === "CLOSED");
});

console.log(`\n${passed} checks passed`);
