// Exercise the packed-shape async JavaScript API under Node.
import "./test-wasm-bindings.cjs";
import "./test-npm-api.mjs";
import "./test-npm-errors.mjs";
import "./test-npm-client.mjs";
import "./test-npm-node.mjs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lstat, mkdtemp, readdir, readFile, readlink, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const commonjs = require(path.join(here, "..", "npm"));
const esm = await import(pathToFileURL(path.join(here, "..", "npm", "node", "index.js")));
const { RarArchive, RarWriter, RarError, repair, isRarFile, isRarFileSfx, checkPassword, version, archiveVersions } = esm;

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
// Volume sizes include headers, so split tests need a payload several times
// the size of one volume's headers.
const LARGE = text.encode("hello from rars ".repeat(512));

console.log(`rars ${version}`);

await check("CommonJS and ESM expose the same async API", async () => {
  assert.equal(typeof commonjs.RarArchive.open, "function");
  assert.equal(commonjs.version, version);
  assert.deepEqual(commonjs.archiveVersions, archiveVersions);
  assert.throws(() => new RarWriter({ format: "rar29" }), /now called version/);
  assert.throws(() => new RarWriter({ version: "RAR50" }), /unknown RAR version/);
  for (const settings of [
    { level: -1 }, { level: 6 }, { recoveryPercent: 0 }, { recoveryPercent: 101 },
    { version: "rar29", recoveryPercent: 5 }, { encryptHeaders: true },
    { version: "rar20", password: "pw", encryptHeaders: true }, { volumeSize: 0 },
    { comment: "note", volumeSize: 4096 },
  ]) {
    assert.throws(() => new RarWriter(settings),
      (error) => error instanceof RarError && error.code === "INVALID_OPTION", JSON.stringify(settings));
  }
  assert.throws(() => new RarWriter({ level: "3" }), TypeError);
});

await check("every format round-trips without blocking API calls", async () => {
  for (const format of archiveVersions) {
    const writer = new RarWriter({ version: format });
    writer.add("hello.txt", HELLO).add("dir/second.txt", SECOND);
    const input = HELLO.buffer;
    const bytes = await writer.bytes();
    assert.equal(input.byteLength, HELLO.byteLength, "input must not be detached");
    const archive = await RarArchive.open(bytes);
    assert.deepEqual(archive.entries.map((entry) => entry.name), ["hello.txt", "dir/second.txt"]);
    assert.deepEqual(await archive.get("hello.txt").bytes(), HELLO, format);
    assert.deepEqual(await archive.readMany([archive.entries[1], "hello.txt", archive.entries[1]]), [SECOND, HELLO, SECOND]);
    await archive.test();
    archive.close();
    writer.close();
  }
});

await check("metadata and immutable entry objects are friendly JavaScript", async () => {
  const writer = new RarWriter({ version: "rar50" });
  writer.add("hello.txt", HELLO, {
    mode: 0o100644,
    mtime: new Date("2025-02-03T04:05:06Z"),
  });
  const archive = await RarArchive.open(await writer.bytes());
  const [entry] = archive.entries;
  assert.equal(entry.name, "hello.txt");
  assert.equal(entry.atime, undefined);
  assert.equal(entry.birthtime, undefined);
  assert.equal(entry.size, HELLO.length);
  assert.equal(entry.isDirectory, false);
  assert.ok(entry.compressedSize > 0);
  assert.ok(Object.isFrozen(entry));
  assert.deepEqual(archive.get(entry.nameBytes), entry);
  assert.deepEqual(archive.getAll("hello.txt"), [entry]);
});

await check("modification times read back as written in every family", async () => {
  // An even second: RAR 1.5-4.x store DOS times in 2-second steps.
  const mtime = new Date("2025-02-03T04:05:06Z");
  for (const format of ["rar50", "rar29"]) {
    const writer = new RarWriter({ version: format });
    writer.add("hello.txt", HELLO, { mtime });
    writer.add("seconds.txt", HELLO, { mtime: mtime.valueOf() / 1000 });
    const archive = await RarArchive.open(await writer.bytes());
    assert.equal(archive.entries[0].mtime.valueOf(), mtime.valueOf(), format);
    assert.equal(archive.entries[1].mtime.valueOf(), mtime.valueOf(), format);
    archive.close();
    writer.close();
  }
});

await check("passwords, comments and structured errors work", async () => {
  const writer = new RarWriter({
    version: "rar50",
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
  const writer = new RarWriter({ version: "rar50", level: 0, volumeSize: 64 * 1024 });
  writer.add("big.bin", payload);
  await assert.rejects(writer.bytes(), (error) => error.code === "INVALID_OPTION" && /volumes\(\)/.test(error.message));
  await assert.rejects(new RarWriter().add("a", "a").volumes(), (error) => error.code === "INVALID_OPTION");
  const volumes = await writer.volumes();
  assert.ok(volumes.length > 1);
  await assert.rejects((async () => {
    const partial = await RarArchive.open(volumes.slice(0, -1));
    await partial.entries[0].bytes();
  })(), (error) => error instanceof RarError && error.code === "MISSING_VOLUME");
  const archive = await RarArchive.open(volumes);
  assert.deepEqual(archive.entries.map((entry) => entry.name), ["big.bin"]);
  assert.equal(archive.entries[0].volumeIndex, 0);
  assert.equal(archive.isVolume, true);
  assert.equal(archive.volumeIndex, 0);
  assert.equal(archive.isFirstVolume, true);
  assert.equal(archive.volumeNaming, "part");
  const second = await RarArchive.open(volumes[1]);
  assert.equal(second.volumeIndex, 1);
  assert.equal(second.isFirstVolume, false);
  second.close();
  const plain = await RarArchive.open(await new RarWriter().add("a", "a").bytes());
  assert.deepEqual([plain.isVolume, plain.volumeIndex, plain.isFirstVolume], [false, 0, true]);
  plain.close();
  assert.ok(archive.has("big.bin"));
  assert.ok(!archive.has("missing"));
  assert.deepEqual(await archive.entries[0].bytes(), payload);
});

await check("repair restores damaged bytes", async () => {
  const payload = Uint8Array.from({ length: 200000 }, (_, index) => (index * 7 + (index >> 5)) & 0xff);
  const writer = new RarWriter({ version: "rar50", level: 0, recoveryPercent: 10 });
  writer.add("payload.bin", payload);
  const damaged = Uint8Array.from(await writer.bytes());
  for (let i = 0; i < 64; i += 1) damaged[Math.floor(damaged.length / 2) + i] ^= 0xff;
  const repaired = await repair(damaged);
  assert.equal(repaired.report.changed, true);
  assert.equal(repaired.report.dataRepaired, true);
  assert.ok(repaired.report.expectedRecoveryShards >= 1);
  const archive = await RarArchive.open(repaired.data);
  assert.deepEqual(await archive.entries[0].bytes(), payload);

  const directory = await mkdtemp(path.join(os.tmpdir(), "rars-repair-"));
  try {
    const output = path.join(directory, "fixed.rar");
    const written = await repair(damaged, { output });
    assert.equal(written.data, undefined);
    assert.equal(written.report.dataRepaired, true);
    assert.deepEqual(await (await RarArchive.open(output)).entries[0].bytes(), payload);
    await assert.rejects(repair(damaged, { output }),
      (error) => error.code === "IO" && error.details.systemCode === "EEXIST");
    assert.equal((await repair(damaged, { output, overwrite: true })).data, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await check("checkPassword finds the right candidate and opens the archive", async () => {
  for (const encryptHeaders of [false, true]) {
    const bytes = await new RarWriter({ password: "right", encryptHeaders }).add("a.txt", HELLO).bytes();
    const found = await checkPassword(bytes, ["wrong", text.encode("also wrong"), "right", "later"]);
    assert.equal(found.correct, "right");
    assert.equal(found.needsPassword, true);
    assert.deepEqual(await found.archive.get("a.txt").bytes(), HELLO);
    const none = await checkPassword(bytes, ["wrong"]);
    assert.equal(none.correct, undefined);
    assert.equal(none.archive === undefined, encryptHeaders);
  }
  const plain = await checkPassword(await new RarWriter().add("a.txt", "a").bytes(), ["unused"]);
  assert.equal(plain.needsPassword, false);
  assert.equal(plain.correct, undefined);
  assert.deepEqual(plain.archive.entries.map((entry) => entry.name), ["a.txt"]);
  await assert.rejects(checkPassword(new Uint8Array(1), [1]), TypeError);
});

await check("RarWriter.fromArchive carries members over, and edits before writing", async () => {
  const source = await new RarWriter({ level: 3, comment: "set comment" })
    .add("keep.txt", HELLO, { mtime: new Date("2020-01-02T03:04:05Z"), comment: "member comment" })
    .add("drop.txt", "gone")
    .addDirectory("dir")
    .addSymlink("dir/link", "../keep.txt")
    .bytes();
  const archive = await RarArchive.open(source);
  const writer = await RarWriter.fromArchive(archive);
  assert.deepEqual(writer.names, ["keep.txt", "drop.txt", "dir", "dir/link"]);
  const bytes = await writer.remove("drop.txt").rename("keep.txt", "kept.txt").add("new.txt", "new").bytes();
  const result = await RarArchive.open(bytes);
  assert.deepEqual(result.entries.map((entry) => entry.name), ["kept.txt", "dir", "dir/link", "new.txt"]);
  assert.deepEqual(await result.get("kept.txt").bytes(), HELLO);
  assert.equal(result.get("kept.txt").mtime.toISOString(), "2020-01-02T03:04:05.000Z");
  assert.equal(new TextDecoder().decode(await result.readComment()), "set comment");
  assert.equal(new TextDecoder().decode(await result.get("kept.txt").readComment()), "member comment");
  assert.equal(new TextDecoder().decode(await result.get("dir/link").readLink()), "../keep.txt");
  // An encrypted source is written encrypted again with the same password.
  const secret = await new RarWriter({ password: "pw" }).add("s.txt", HELLO).bytes();
  const again = await (await RarWriter.fromArchive(await RarArchive.open(secret, { password: "pw" }))).bytes();
  await assert.rejects((await RarArchive.open(again)).get("s.txt").bytes());
  assert.deepEqual(await (await RarArchive.open(again, { password: "pw" })).get("s.txt").bytes(), HELLO);
  // A volume set is read whole, a member split across volumes included, and written as one archive.
  const big = new Uint8Array(200 * 1024).map((_, index) => (index * 7919) % 251);
  const parts = await new RarWriter({ level: 0, volumeSize: 64 * 1024 }).add("big.bin", big).add("small.txt", HELLO).volumes();
  assert.ok(parts.length > 2);
  const joined = await (await RarWriter.fromArchive(await RarArchive.open(parts), { preserve: false })).bytes();
  const whole = await RarArchive.open(joined);
  assert.deepEqual(whole.entries.map((entry) => entry.name), ["big.bin", "small.txt"]);
  assert.deepEqual(await whole.get("big.bin").bytes(), big);
  // Too small a staging limit refuses the write.
  const capped = await RarWriter.fromArchive(archive, { maxStagedBytes: 1 });
  await assert.rejects(capped.bytes(), (error) => error.code === "RESOURCE_LIMIT");
});

await check("Node extraction writes links, and skips one that could leave the directory", async () => {
  const bytes = await new RarWriter({ level: 0 })
    .add("data/file.txt", HELLO)
    .addSymlink("data/near", "file.txt")
    .addSymlink("data/far", "../../outside")
    .bytes();
  const directory = await mkdtemp(path.join(os.tmpdir(), "rars-links-"));
  const warnings = [];
  const listen = (warning) => { if (warning.name === "UnsafeLinkWarning") warnings.push(warning.message); };
  process.on("warning", listen);
  try {
    const archive = await RarArchive.open(bytes);
    const written = await archive.extractAll(directory);
    assert.deepEqual(written.map((file) => path.relative(directory, file)).sort(),
      [path.join("data", "file.txt"), path.join("data", "near")].sort());
    assert.equal(await readlink(path.join(directory, "data", "near")), "file.txt");
    assert.deepEqual(new Uint8Array(await readFile(path.join(directory, "data", "near"))), HELLO);
    await assert.rejects(lstat(path.join(directory, "data", "far")));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /data\/far/);
    // A hard link names an earlier member, which is written first and linked to.
    const hard = path.join(directory, "hard");
    const fixture = await RarArchive.open(path.join(here, "..", "crates/rars/tests/fixtures/rar50/wild/hardlink.rar"));
    const files = await fixture.extractAll(hard);
    assert.equal(files.length, fixture.entries.length);
    const [first, second] = await Promise.all(files.map((file) => stat(file)));
    assert.equal(first.ino, second.ino);
  } finally {
    process.off("warning", listen);
    await rm(directory, { recursive: true, force: true });
  }
});

await check("Node extracts entries once verified, refusing to overwrite by default", async () => {
  const mtime = new Date("2024-05-06T07:08:10Z");
  const bytes = await new RarWriter({ level: 0 })
    .add("top.txt", HELLO, { mtime })
    .add("nested/deep/inner.txt", SECOND, { mtime })
    .add("nested/other.txt", "other").bytes();
  const archive = await RarArchive.open(bytes);
  const directory = await mkdtemp(path.join(os.tmpdir(), "rars-extract-"));
  try {
    const out = path.join(directory, "out");
    const written = await archive.extractAll(out);
    assert.deepEqual(written, ["top.txt", "nested/deep/inner.txt", "nested/other.txt"]
      .map((name) => path.join(out, ...name.split("/"))));
    assert.deepEqual(new Uint8Array(await readFile(path.join(out, "top.txt"))), HELLO);
    assert.equal(await readFile(path.join(out, "nested", "deep", "inner.txt"), "utf8"), decode(SECOND));
    assert.equal((await stat(path.join(out, "top.txt"))).mtime.valueOf(), mtime.valueOf());
    const existing = (error) => error instanceof RarError && error.code === "IO"
      && error.details.systemCode === "EEXIST";
    await writeFile(path.join(out, "top.txt"), "precious");
    await assert.rejects(archive.extractAll(out), existing);
    assert.equal(await readFile(path.join(out, "top.txt"), "utf8"), "precious");
    const renamed = await archive.extractAll(out, { overwrite: "rename", members: ["top.txt"] });
    assert.deepEqual(renamed, [path.join(out, "top(1).txt")]);
    assert.deepEqual(await archive.extractAll(out, { overwrite: true, members: ["top.txt"] }),
      [path.join(out, "top.txt")]);
    assert.deepEqual(new Uint8Array(await readFile(path.join(out, "top.txt"))), HELLO);
    const flat = path.join(directory, "flat");
    assert.deepEqual(await archive.get("nested/deep/inner.txt").extract(flat, { flatten: true }),
      path.join(flat, "inner.txt"));
    // A member that fails verification is never written.
    const damaged = Uint8Array.from(bytes);
    const at = Buffer.from(bytes).indexOf(Buffer.from(SECOND));
    assert.ok(at > 0);
    damaged[at + 2] ^= 0xff;
    const broken = path.join(directory, "broken");
    await assert.rejects((await RarArchive.open(damaged)).extractAll(broken));
    assert.equal(await stat(path.join(broken, "nested", "deep", "inner.txt")).catch(() => undefined), undefined);
    // Entries before it verified and were written.
    assert.deepEqual(new Uint8Array(await readFile(path.join(broken, "top.txt"))), HELLO);
  } finally {
    archive.close();
    await rm(directory, { recursive: true, force: true });
  }
});

await check("directories, links and every time round-trip", async () => {
  const mtime = new Date("2024-01-02T03:04:06Z");
  const atime = new Date("2024-02-03T04:05:06Z");
  const birthtime = new Date("2023-12-01T00:00:00Z");
  for (const format of ["rar29", "rar50"]) {
    const modern = format === "rar50";
    const writer = new RarWriter({ version: format, level: 0 })
      .addDirectory("empty", { mtime })
      .add("file.txt", HELLO, modern ? { mtime, atime, birthtime } : { mtime })
      .addSymlink("link", "file.txt");
    const archive = await RarArchive.open(await writer.bytes());
    const empty = archive.get("empty");
    assert.equal(empty.isDirectory, true, format);
    assert.equal(empty.mtime.valueOf(), mtime.valueOf(), format);
    const link = archive.get("link");
    assert.equal(link.isLink, true, format);
    assert.equal(decode(await link.readLink()), "file.txt", format);
    const file = archive.get("file.txt");
    assert.equal(file.isLink, false);
    await assert.rejects(file.readLink(), (error) => error.code === "INVALID_OPTION");
    if (modern) {
      assert.equal(file.atime.valueOf(), atime.valueOf());
      assert.equal(file.birthtime.valueOf(), birthtime.valueOf());
    }
    archive.close();
  }
  await assert.rejects(new RarWriter({ version: "rar29" }).add("a", "a", { atime: 1 }).bytes(),
    (error) => error instanceof RarError);
  assert.throws(() => new RarWriter().addSymlink("link", ""), TypeError);
  assert.throws(() => new RarWriter().addDirectory("a").addDirectory("a"), (error) => error.code === "DUPLICATE_ENTRY");
});

await check("member comments round-trip", async () => {
  for (const format of ["rar15", "rar29", "rar50"]) {
    const bytes = await new RarWriter({ version: format, level: 0 })
      .add("noted.txt", HELLO, { comment: "a note" })
      .add("raw.txt", HELLO, { comment: text.encode("raw note") })
      .add("plain.txt", HELLO).bytes();
    const archive = await RarArchive.open(bytes);
    assert.equal(decode(await archive.get("noted.txt").readComment()), "a note", format);
    assert.equal(decode(await archive.get("raw.txt").readComment()), "raw note", format);
    assert.equal(await archive.get("plain.txt").readComment(), undefined, format);
    archive.close();
  }
  assert.throws(() => new RarWriter().add("a", "a", { comment: 1 }), TypeError);
});

await check("isRarFile and isRarFileSfx answer for bytes, Blobs and paths", async () => {
  const bytes = await new RarWriter().add("a.txt", "a").bytes();
  const sfx = new Uint8Array(4096 + bytes.length);
  sfx.set(text.encode("MZ"));
  sfx.set(bytes, 4096);
  assert.equal(await isRarFile(bytes), true);
  assert.equal(await isRarFile(new Blob([bytes])), true);
  assert.equal(await isRarFile(text.encode("PK\x03\x04 not a rar")), false);
  assert.equal(await isRarFile(sfx), false);
  assert.equal(await isRarFileSfx(sfx), true);
  assert.equal(await isRarFileSfx(text.encode("no archive here")), false);
  const directory = await mkdtemp(path.join(os.tmpdir(), "rars-probe-"));
  try {
    const file = path.join(directory, "a.rar");
    await writeFile(file, bytes);
    assert.equal(await isRarFile(file), true);
    // An unreadable source is not RAR, as Python's is_rarfile has it.
    assert.equal(await isRarFile(path.join(directory, "missing.rar")), false);
    assert.equal(await isRarFile(directory), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await check("progress reports the engine's stages in bytes", async () => {
  const events = [];
  const bytes = await new RarWriter({ recoveryPercent: 5 }).add("hello.txt", LARGE)
    .bytes({ onProgress: (event) => events.push(event) });
  assert.equal(events[0].total, undefined);
  assert.ok(events.length > 2);
  const phases = new Set(events.map((event) => event.phase));
  assert.ok(phases.has("compressing") && phases.has("protecting"), [...phases].join());
  for (const phase of phases) assert.ok(["compressing", "protecting", "writing"].includes(phase), phase);
  assert.equal(events.at(-1).completed, bytes.length);
  assert.equal(events.at(-1).total, bytes.length);
  const archive = await RarArchive.open(bytes);
  for (const [run, phase] of [
    [(onProgress) => archive.entries[0].bytes({ onProgress }), "reading"],
    [(onProgress) => archive.readMany([archive.entries[0]], { onProgress }), "reading"],
    [(onProgress) => archive.test({ onProgress }), "testing"],
  ]) {
    const seen = [];
    await run((event) => seen.push(event));
    assert.ok(seen.every((event) => event.phase === phase), phase);
    // The engine's events count the member's decoded bytes.
    assert.ok(seen.some((event) => event.total === LARGE.length && event.completed === LARGE.length), phase);
  }
});

await check("codec work leaves the Node event loop responsive", async () => {
  const writer = new RarWriter({ version: "rar50", level: 5 });
  writer.add("large.txt", new Uint8Array(4_000_000).fill(120));
  let ticks = 0;
  const timer = setInterval(() => { ticks += 1; }, 1);
  await writer.bytes();
  clearInterval(timer);
  assert.ok(ticks > 0, `expected timer ticks during compression, got ${ticks}`);
});

await check("AbortSignal cancels active work and the runtime recovers", async () => {
  const writer = new RarWriter({ version: "rar50", level: 5 });
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
    assert.deepEqual(await writer.writeTo(output), [output]);
    const existing = (error) => error instanceof RarError && error.code === "IO"
      && error.details.systemCode === "EEXIST" && /overwrite: true/.test(error.message);
    await writeFile(output, "precious");
    await assert.rejects(writer.writeTo(output), existing);
    assert.equal(await readFile(output, "utf8"), "precious");
    assert.deepEqual(await writer.writeTo(output, { overwrite: true }), [output]);
    assert.ok((await RarArchive.open(output)).entries.length === 1);
    const archive = await RarArchive.open(output);
    assert.deepEqual(await archive.entries[0].bytes(), new Uint8Array(await readFile(source)));

    const split = new RarWriter({ version: "rar50", level: 0, volumeSize: 64 * 1024 })
      .add("large.bin", new Uint8Array(180000).fill(9));
    const paths = await split.writeTo(path.join(directory, "split.rar"));
    assert.ok(paths.length > 1);
    // One existing part refuses the whole set before anything is written.
    for (const part of paths.slice(0, -1)) await rm(part);
    await writeFile(paths.at(-1), "precious");
    await assert.rejects(split.writeTo(path.join(directory, "split.rar")), existing);
    assert.equal(await readFile(paths.at(-1), "utf8"), "precious");
    assert.equal((await readdir(directory)).filter((name) => name.startsWith("split.")).length, 1);
    assert.deepEqual(await split.writeTo(path.join(directory, "split.rar"), { overwrite: true }), paths);
    const volumeArchive = await RarArchive.open(paths[0]);
    assert.equal((await volumeArchive.entries[0].bytes()).length, 180000);
    // The later volumes are found by the names the core gives them.
    assert.deepEqual(volumeArchive.volumePaths, paths);
    const [extracted] = await volumeArchive.extractAll(path.join(directory, "from-set"));
    assert.equal((await readFile(extracted)).length, 180000);
    const later = await RarArchive.open(paths[1]);
    assert.deepEqual(later.volumePaths, [paths[1]]);
    later.close();
    const legacy = await new RarWriter({ version: "rar29", level: 0, volumeSize: 64 * 1024 })
      .add("large.bin", new Uint8Array(180000).fill(9)).writeTo(path.join(directory, "old.rar"));
    assert.deepEqual(legacy.map((file) => path.basename(file)), ["old.rar", "old.r00", "old.r01"]);
    const legacyArchive = await RarArchive.open(legacy[0]);
    assert.deepEqual(legacyArchive.volumePaths, legacy);
    assert.equal((await legacyArchive.entries[0].bytes()).length, 180000);
    assert.equal(await isRarFile(paths[0]), true);
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

await check("read limits cover every format, and open()'s become later calls' defaults", async () => {
  const limited = (error) => error instanceof RarError && error.code === "RESOURCE_LIMIT";
  for (const format of archiveVersions) {
    const bytes = await new RarWriter({ version: format, comment: "comment", level: 0 })
      .add("a.txt", HELLO).add("b.txt", SECOND).bytes();
    for (const key of ["maxHeaderCount", "maxHeaderBytes", "maxMemberOutputBytes", "maxTotalOutputBytes"]) {
      await assert.rejects(RarArchive.open(bytes, { [key]: 0 }), limited, `${format}: ${key}`);
    }
    const archive = await RarArchive.open(bytes, { maxTotalOutputBytes: 7n });
    assert.equal(decode(archive.comment), "comment");
    await assert.rejects(archive.readComment({ maxMemberOutputBytes: 6n }), limited);
    assert.equal(decode(await archive.readComment({ maxTotalOutputBytes: 7 })), "comment");
    await assert.rejects(archive.entries[0].bytes({ maxMemberOutputBytes: HELLO.length - 1 }), limited);
    await assert.rejects(archive.test({ maxTotalOutputBytes: HELLO.length }), limited);
    await assert.rejects(archive.entries[0].bytes({ maxHeaderCount: 0 }), limited);
    // open()'s 7-byte output limit still applies until a call overrides it.
    await assert.rejects(archive.entries[0].bytes(), limited);
    assert.deepEqual(await archive.entries[0].bytes({ maxTotalOutputBytes: HELLO.length }), HELLO);
    await archive.test({ maxTotalOutputBytes: BigInt(HELLO.length + SECOND.length) });
  }
});

await check("read options preserve integer precision and reject invalid limits", async () => {
  const bytes = await new RarWriter().add("a.txt", HELLO).bytes();
  for (const key of ["maxHeaderCount", "maxHeaderBytes", "maxMemberOutputBytes", "maxTotalOutputBytes", "maxRar50DictionaryBytes", "maxRar50BufferedMemberBytes"]) {
    for (const value of [-1, 0.5, Infinity, NaN, 2 ** 53, -1n, 2n ** 64n, "1"]) {
      await assert.rejects(RarArchive.open(bytes, { [key]: value }), (error) => error.code === "INVALID_OPTION");
    }
  }
  const archive = await RarArchive.open(bytes, { maxHeaderBytes: 2n ** 64n - 1n });
  assert.deepEqual(await archive.entries[0].bytes({ maxTotalOutputBytes: 9007199254740993n }), HELLO);
  assert.equal(await archive.readComment(), undefined);
});

await check("custom RAR 3 VM programs run only when allowed", async () => {
  const archive = await RarArchive.open(await readFile(new URL(
    "../crates/rars/tests/fixtures/rar15_40/rarvm/generic_delta_padding_mutation.rar", import.meta.url)));
  await assert.rejects(archive.entries[0].bytes(), (error) => error.code === "UNSUPPORTED_FEATURE");
  assert.equal((await archive.entries[0].bytes({ allowRar3VmPrograms: true })).length, 1048576);
  await assert.rejects(archive.entries[0].bytes({ allowRar3VmPrograms: "yes" }),
    (error) => error.code === "INVALID_OPTION");
});

await check("RAR5 decoder and volume budgets reach WASM", async () => {
  const limited = (error) => error.code === "RESOURCE_LIMIT";
  const compressed = await new RarWriter({ version: "rar50", level: 5 }).add("a.txt", HELLO).bytes();
  const archive = await RarArchive.open(compressed);
  await assert.rejects(archive.entries[0].bytes({ maxRar50DictionaryBytes: 0 }), limited);
  const filtered = await RarArchive.open(await readFile(new URL(
    "../crates/rars/tests/fixtures/rar50/filter_e8.rar", import.meta.url)));
  const expected = await filtered.entries[0].bytes();
  assert.ok(expected.length > 0);
  assert.deepEqual(await filtered.entries[0].bytes({ maxRar50BufferedMemberBytes: 0 }), expected);
  const payload = new Uint8Array(180000).fill(9);
  for (const format of ["rar14", "rar29", "rar50", "rar70"]) {
    const writer = new RarWriter({ version: format, level: 0, volumeSize: 64 * 1024 }).add("a.bin", payload);
    const modern = format === "rar50" || format === "rar70";
    if (modern) writer.add("b.txt", SECOND);
    const parts = await writer.volumes();
    const volumes = await RarArchive.open(parts);
    await assert.rejects(volumes.entries[0].bytes({ maxTotalOutputBytes: payload.length - (modern ? 0 : 1) }), limited);
    await assert.rejects(volumes.test({ maxMemberOutputBytes: payload.length - 1 }), limited);
    assert.deepEqual(await volumes.entries[0].bytes({ maxTotalOutputBytes: payload.length + SECOND.length }), payload);
    // b.txt starts after a.bin has filled the first volumes.
    if (modern) assert.equal(volumes.get("b.txt").volumeIndex, parts.length - 1);
  }
});

await check("legacy filename views preserve bytes and Unicode names", async () => {
  const raw = new Uint8Array([99, 97, 102, 130, 46, 116, 120, 116]);
  for (const format of archiveVersions) {
    const modern = format === "rar50" || format === "rar70";
    const name = modern ? "café.txt" : raw;
    const bytes = await new RarWriter({ version: format, level: 0 }).add(name, HELLO).bytes();
    const archive = await RarArchive.open(bytes, { legacyNameEncoding: "cp850" });
    assert.equal(archive.entries[0].name, "café.txt");
    assert.deepEqual(archive.entries[0].nameBytes, modern ? text.encode(name) : raw);
    assert.deepEqual(await archive.get("café.txt").bytes(), HELLO);
    assert.deepEqual(await archive.get(archive.entries[0].nameBytes).bytes(), HELLO);
  }
  const bytes = await new RarWriter({ version: "rar29", level: 0 })
    .add(new Uint8Array([129]), HELLO).bytes();
  await assert.rejects(RarArchive.open(bytes, { legacyNameEncoding: "windows-1252" }),
    (error) => error.code === "INVALID_OPTION");
  await assert.rejects(RarArchive.open(bytes, { legacyNameEncoding: "auto" }),
    (error) => error.code === "INVALID_OPTION");
  const parts = await new RarWriter({ version: "rar29", level: 0, volumeSize: 64000 })
    .add(raw, new Uint8Array(180000).fill(9)).volumes();
  const archive = await RarArchive.open(parts, { legacyNameEncoding: "cp850" });
  assert.equal(archive.entries[0].name, "café.txt");
  assert.equal((await archive.get("café.txt").bytes()).length, 180000);
});


await check("aggregate writer memory policy crosses the worker boundary", async () => {
  for (const format of ["rar50", "rar70"]) {
    const expected = await new RarWriter({ version: format, level: 0 }).add("member", LARGE).bytes();
    const writer = new RarWriter({ version: format, level: 0, maxMemoryBytes: 16n << 20n }).add("member", LARGE);
    assert.deepEqual(await writer.bytes(), expected);
    assert.deepEqual(await writer.bytes(), expected);
    const denied = new RarWriter({ version: format, level: 0, maxMemoryBytes: 0 }).add("member", HELLO);
    for (let i = 0; i < 2; i++) {
      await assert.rejects(denied.bytes(), (error) => {
        assert.equal(error.code, "RESOURCE_LIMIT");
        assert.equal(error.details.limitBytes, "0");
        assert.ok(BigInt(error.details.requiredBytes) > 0n);
        return true;
      });
    }
    const volumes = await new RarWriter({ version: format, level: 0, maxMemoryBytes: 16n << 20n, volumeSize: 2048 })
      .add("member", LARGE).volumes();
    assert.ok(volumes.length > 1);
  }
  for (const format of ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"]) {
    assert.throws(() => new RarWriter({ version: format, level: 0, maxMemoryBytes: 0 }),
      (error) => error instanceof RarError && error.code === "INVALID_OPTION");
  }
});

await check("bounded WASM encryption and recovery retain readable output", async () => {
  for (const encryptHeaders of [false, true]) {
    const writer = new RarWriter({ version: "rar50", level: 0, password: "secret",
      encryptHeaders, recoveryPercent: 10, maxMemoryBytes: 32 * 1024 * 1024 })
      .add("member", LARGE);
    const bytes = await writer.bytes();
    const archive = await RarArchive.open(bytes, { password: "secret" });
    assert.deepEqual(await archive.get("member").bytes(), LARGE);
    archive.close();
    const volumes = await new RarWriter({ version: "rar50", level: 0, password: "secret",
      encryptHeaders, recoveryPercent: 10, maxMemoryBytes: 32 * 1024 * 1024, volumeSize: 2048 })
      .add("member", LARGE).volumes();
    assert.ok(volumes.length > 1);
    const set = await RarArchive.open(volumes, { password: "secret" });
    assert.deepEqual(await set.get("member").bytes(), LARGE);
    set.close();
  }
});

await check("bounded WASM compressed solid and filtered output preserves bytes", async () => {
  const numeric = new Uint8Array(32768 * 4);
  const view = new DataView(numeric.buffer);
  for (let n = 0; n < 32768; n++) view.setUint32(n * 4, (n * 71) % 32749, true);
  for (const solid of [false, true]) {
    const options = { version: "rar50", level: 3, solid };
    const expected = await new RarWriter(options).add("member-0", numeric).bytes();
    const actual = await new RarWriter({ ...options, maxMemoryBytes: 256 * 1024 * 1024 })
      .add("member-0", numeric).bytes();
    assert.deepEqual(actual, expected);
    const archive = await RarArchive.open(actual);
    assert.deepEqual(await archive.get("member-0").bytes(), numeric);
    archive.close();
  }
});

console.log(`\n${passed} checks passed`);
