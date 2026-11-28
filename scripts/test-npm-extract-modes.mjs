import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { RarArchive, RarWriter } = await import(
  pathToFileURL(path.join(here, "..", "npm", "node", "index.js")));

let passed = 0;
async function check(name, body) {
  if (process.platform === "win32") {
    console.log(`  skip ${name}: modes and symlinks are Unix only`);
    return;
  }
  await body();
  passed += 1;
  console.log(`  ok  ${name}`);
}

const temporary = await mkdtemp(path.join(os.tmpdir(), "rars-modes-"));
let directories = 0;
const fresh = () => path.join(temporary, `out-${directories++}`);
const modeOf = async (file) => (await lstat(file)).mode & 0o777;
const exists = (file) => lstat(file).then(() => true, () => false);

async function modesArchive() {
  return RarArchive.open(await new RarWriter({ level: 0 })
    .add("run.sh", "run", { mode: 0o100750 })
    .add("secret.txt", "secret", { mode: 0o100400 })
    .addDirectory("private", { mode: 0o040700 })
    .add("private/inner.txt", "inner", { mode: 0o100604 })
    .bytes());
}

const HARD_LINK = 4;
const FILE_COPY = 5;

function redirect(bytes, name, kind) {
  const data = Uint8Array.from(bytes);
  const vint = (at) => {
    let value = 0;
    for (let shift = 0; ; shift += 7) {
      const byte = data[at++];
      value += (byte & 0x7f) * 2 ** shift;
      if (!(byte & 0x80)) return [value, at];
    }
  };
  const wanted = new TextEncoder().encode(name);
  const holds = (start, end) => Buffer.from(data.subarray(start, end)).includes(wanted);
  for (let at = 8; at + 4 < data.length;) {
    const body = at + 4;
    const [size, afterSize] = vint(body);
    const end = afterSize + size;
    const [type, afterType] = vint(afterSize);
    let [flags, cursor] = vint(afterType);
    let extraSize = 0;
    let dataSize = 0;
    if (flags & 1) [extraSize, cursor] = vint(cursor);
    if (flags & 2) [dataSize, cursor] = vint(cursor);
    if (type === 2 && extraSize && holds(body, end)) {
      for (let record = end - extraSize; record < end;) {
        const [recordSize, recordStart] = vint(record);
        const [tag, payload] = vint(recordStart);
        if (tag === 5) data[payload] = kind;
        record = recordStart + recordSize;
      }
      new DataView(data.buffer).setUint32(at, crc32(data.subarray(body, end)), true);
    }
    if (type === 5) break;
    at = end + dataSize;
  }
  return data;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

try {
  await check("Node extraction restores Unix modes", async () => {
    const archive = await modesArchive();
    const out = fresh();
    await archive.extractAll(out);
    assert.equal(await modeOf(path.join(out, "run.sh")), 0o750);
    assert.equal(await modeOf(path.join(out, "secret.txt")), 0o400);
    assert.equal(await modeOf(path.join(out, "private")), 0o700);
    assert.equal(await modeOf(path.join(out, "private", "inner.txt")), 0o604);
    const one = fresh();
    await archive.get("run.sh").extract(one);
    assert.equal(await modeOf(path.join(one, "run.sh")), 0o750);
  });

  await check("restoreModes: false keeps the umask defaults", async () => {
    const archive = await modesArchive();
    const umask = process.umask(0o022);
    const out = fresh();
    const one = fresh();
    try {
      await archive.extractAll(out, { restoreModes: false });
      await archive.get("secret.txt").extract(one, { restoreModes: false });
    } finally {
      process.umask(umask);
    }
    for (const name of ["run.sh", "secret.txt", "private/inner.txt"]) {
      assert.equal(await modeOf(path.join(out, ...name.split("/"))), 0o644, name);
    }
    assert.equal(await modeOf(path.join(one, "secret.txt")), 0o644);
    assert.equal(await modeOf(path.join(out, "private")), 0o755);
  });

  await check("a hard link and a copy of an unreadable file keep their modes", async () => {
    for (const [kind, nlink, mode] of [[HARD_LINK, 2, 0o200], [FILE_COPY, 1, 0o640]]) {
      const bytes = redirect(await new RarWriter({ level: 0 })
        .add("source.txt", "source", { mode: 0o100200 })
        .addSymlink("linked.txt", "source.txt", { mode: 0o100640 })
        .bytes(), "linked.txt", kind);
      const out = fresh();
      await (await RarArchive.open(bytes)).extractAll(out);
      assert.equal(await modeOf(path.join(out, "source.txt")), 0o200, kind);
      assert.equal(await modeOf(path.join(out, "linked.txt")), mode, kind);
      assert.equal((await lstat(path.join(out, "linked.txt"))).nlink, nlink, kind);
    }
  });

  await check("symlinks: \"skip\" leaves symlinks out, without a warning, and keeps hard links", async () => {
    const warnings = [];
    const listen = (warning) => { if (warning.name === "UnsafeLinkWarning") warnings.push(warning); };
    process.on("warning", listen);
    try {
      for (const version of ["rar50", "rar29"]) {
        const archive = await RarArchive.open(await new RarWriter({ version, level: 0 })
          .add("data/file.txt", "data")
          .addSymlink("data/near", "file.txt")
          .addSymlink("data/far", "../../outside")
          .bytes());
        const out = fresh();
        const written = await archive.extractAll(out, { symlinks: "skip" });
        assert.deepEqual(written, [path.join(out, "data", "file.txt")], version);
        assert.equal(await exists(path.join(out, "data", "near")), false, version);
        assert.equal(await exists(path.join(out, "data", "far")), false, version);
        await assert.rejects(archive.get("data/near").extract(fresh(), { symlinks: "skip" }),
          (error) => error.code === "ENTRY_NOT_FOUND", version);
      }
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(warnings, []);
    } finally {
      process.off("warning", listen);
    }
    const fixture = await RarArchive.open(path.join(here, "..", "crates/rars/tests/fixtures/rar50/wild/hardlink.rar"));
    const files = await fixture.extractAll(fresh(), { symlinks: "skip" });
    const [first, second] = await Promise.all(files.map((file) => stat(file)));
    assert.equal(first.ino, second.ino);
  });

  await check("a hard link to a symlink left out fails as its own member", async () => {
    const bytes = redirect(await new RarWriter({ level: 0 })
      .add("target.txt", "target")
      .addSymlink("sym", "target.txt")
      .addSymlink("hard", "sym")
      .add("after.txt", "after")
      .bytes(), "hard", HARD_LINK);
    const out = fresh();
    const failed = [];
    const written = await (await RarArchive.open(bytes))
      .extractAll(out, { symlinks: "skip", onMemberError: (error) => failed.push(error) });
    assert.equal(failed.length, 1);
    assert.match(failed[0].message, /'hard'.*symbolic link left out/);
    assert.equal(await exists(path.join(out, "hard")), false);
    assert.ok(written.includes(path.join(out, "after.txt")));
    assert.equal(await readFile(path.join(out, "after.txt"), "utf8"), "after");
  });

  async function linksArchive(victim) {
    return RarArchive.open(await new RarWriter({ level: 0 })
      .add("file.txt", "file")
      .addSymlink("inside", "file.txt")
      .addSymlink("up", "../outside")
      .addSymlink("lone", victim)
      .addSymlink("abs", victim, { targetIsDirectory: true })
      .add("up/file.txt", "under")
      .add("abs/file.txt", "under")
      .bytes());
  }

  async function watchingWarnings(body) {
    const warnings = [];
    const listen = (warning) => { if (warning.name === "UnsafeLinkWarning") warnings.push(warning); };
    process.on("warning", listen);
    try {
      await body();
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      process.off("warning", listen);
    }
    return warnings;
  }

  const { mkdir, readdir, readlink } = await import("node:fs/promises");
  const isDirectory = async (file) => (await lstat(file)).isDirectory();

  await check("inside links are made, the rest warn, and a member under a made link replaces it", async () => {
    const victim = fresh();
    await mkdir(victim);
    const out = fresh();
    const warnings = await watchingWarnings(async () => {
      await (await linksArchive(victim)).extractAll(out);
    });
    assert.equal(warnings.length, 3);
    assert.equal(await readlink(path.join(out, "inside")), "file.txt");
    assert.equal(await exists(path.join(out, "lone")), false);
    for (const name of ["up", "abs"]) {
      assert.ok(await isDirectory(path.join(out, name)), name);
      assert.equal(await readFile(path.join(out, name, "file.txt"), "utf8"), "under");
    }
    assert.deepEqual(await readdir(victim), []);
  });

  await check("symlinks: \"all\" makes every link as stored and writes through none", async () => {
    const victim = fresh();
    await mkdir(victim);
    const out = fresh();
    const warnings = await watchingWarnings(async () => {
      await (await linksArchive(victim)).extractAll(out, { symlinks: "all" });
    });
    assert.deepEqual(warnings, []);
    assert.equal(await readlink(path.join(out, "inside")), "file.txt");
    assert.equal(await readlink(path.join(out, "lone")), victim);
    for (const name of ["up", "abs"]) {
      assert.ok(await isDirectory(path.join(out, name)), name);
      assert.equal(await readFile(path.join(out, name, "file.txt"), "utf8"), "under");
    }
    assert.deepEqual(await readdir(victim), []);
    assert.equal(await exists(path.join(out, "..", "outside")), false);
  });

  await check("symlinks takes only its three values", async () => {
    const archive = await linksArchive(fresh());
    await assert.rejects(archive.extractAll(fresh(), { symlinks: "none" }), TypeError);
    await assert.rejects(archive.extractAll(fresh(), { symlinks: true }), TypeError);
  });
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log(`${passed} extraction mode checks passed`);
