// Reading past damage through the built Node package: opt-in, with every intact member
// delivered and each failure reported. The package's own writer makes each archive, and
// the test damages it by editing bytes.
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { RarArchive, RarWriter, RarError } = await import(
  pathToFileURL(path.join(here, "..", "npm", "node", "index.js")));

let passed = 0;
async function check(name, body) {
  await body();
  passed += 1;
  console.log(`  ok  ${name}`);
}

// RAR 1.5 to 4.x, and 5 or later.
const FORMATS = ["rar20", "rar29", "rar50"];

function random(seed, length) {
  // mulberry32: the same bytes on every run.
  let state = seed >>> 0;
  return Uint8Array.from({ length }, () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) & 0xff;
  });
}

const MEMBERS = Object.fromEntries([0, 1, 2].map((index) => [`m${index}.bin`, random(446 + index, 3000)]));
const NAMES = Object.keys(MEMBERS);

function indexOf(haystack, needle) {
  outer: for (let start = 0; start + needle.length <= haystack.length; start++) {
    for (let offset = 0; offset < needle.length; offset++) {
      if (haystack[start + offset] !== needle[offset]) continue outer;
    }
    return start;
  }
  throw new Error("not found");
}

/** Stored, so each member's data is in the file as it is and can be found there. */
async function build(version, options = {}) {
  const writer = new RarWriter({ version, level: 0, ...options });
  for (const [name, data] of Object.entries(MEMBERS)) writer.add(name, data);
  return writer.bytes();
}

/** The archive with one byte of `name`'s data flipped. */
function flipped(archive, name) {
  const data = Uint8Array.from(archive);
  data[indexOf(archive, MEMBERS[name]) + 1000] ^= 0xff;
  return data;
}

/** The archive cut short halfway through `name`'s data. */
function cutThrough(archive, name) {
  return archive.slice(0, indexOf(archive, MEMBERS[name]) + 1500);
}

function damagedCopy(name) {
  const data = Uint8Array.from(MEMBERS[name]);
  data[1000] ^= 0xff;
  return data;
}

async function extracted(directory) {
  const files = {};
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) {
      files[entry.name] = new Uint8Array(await readFile(path.join(entry.parentPath ?? entry.path, entry.name)));
    }
  }
  return files;
}

const coded = (code) => (error) => error instanceof RarError && error.code === code;
const summary = (failed) => failed.map((error) => [error.code, error.member]);
const temporary = await mkdtemp(path.join(os.tmpdir(), "rars-salvage-"));
let directories = 0;
const fresh = () => path.join(temporary, `out-${directories++}`);

try {
  await check("a member that fails its checksum is reported, and delivered whole under salvage", async () => {
    for (const version of FORMATS) {
      const data = flipped(await build(version), "m1.bin");
      const damaged = damagedCopy("m1.bin");

      // Strict, the default: the failure fails the call, and its bytes are never handed over.
      const strict = await RarArchive.open(data);
      await assert.rejects(strict.test(), coded("CHECKSUM_MISMATCH"), version);
      await assert.rejects(strict.get("m1.bin").bytes(), coded("CHECKSUM_MISMATCH"), version);
      await assert.rejects(strict.extractAll(fresh()), coded("CHECKSUM_MISMATCH"), version);
      let failed = [];
      assert.deepEqual(await strict.readMany(NAMES, { onMemberError: (error) => failed.push(error) }),
        [MEMBERS["m0.bin"], new Uint8Array(), MEMBERS["m2.bin"]], version);
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
      assert.ok(failed[0] instanceof RarError);
      failed = [];
      await strict.test({ onMemberError: (error) => failed.push(error) });
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
      failed = [];
      let out = fresh();
      let written = await strict.extractAll(out, { onMemberError: (error) => failed.push(error) });
      assert.deepEqual(written.map((file) => path.basename(file)).sort(), ["m0.bin", "m2.bin"], version);
      assert.deepEqual(await extracted(out), { "m0.bin": MEMBERS["m0.bin"], "m2.bin": MEMBERS["m2.bin"] });
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);

      // Salvage: the damaged bytes, then the report.
      const archive = await RarArchive.open(data, { salvage: true });
      assert.deepEqual(archive.headerDamage, []);
      assert.equal(archive.truncation, undefined);
      failed = [];
      assert.deepEqual(await archive.readMany(NAMES, { onMemberError: (error) => failed.push(error) }),
        [MEMBERS["m0.bin"], damaged, MEMBERS["m2.bin"]], version);
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
      failed = [];
      assert.deepEqual(await archive.get("m1.bin").bytes({ onMemberError: (error) => failed.push(error) }), damaged);
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
      // With nowhere to report to, reading still fails.
      await assert.rejects(archive.get("m1.bin").bytes(), coded("CHECKSUM_MISMATCH"), version);
      failed = [];
      await archive.test({ onMemberError: (error) => failed.push(error) });
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);

      failed = [];
      out = fresh();
      written = await archive.extractAll(out, { onMemberError: (error) => failed.push(error) });
      assert.deepEqual(written.map((file) => path.basename(file)).sort(), ["m0.bin", "m2.bin"], version);
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
      failed = [];
      out = fresh();
      written = await archive.extractAll(out, { onMemberError: (error) => failed.push(error), keepBroken: true });
      assert.deepEqual(written.map((file) => path.basename(file)).sort(), NAMES, version);
      assert.deepEqual(await extracted(out), { ...MEMBERS, "m1.bin": damaged }, version);
      assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]], version);
    }
  });

  // Word-like text, which compresses, so damage lands partway through a stream.
  function text(seed, size = 60_000) {
    const bytes = random(seed, size * 2);
    let cursor = 0;
    const next = (limit) => bytes[cursor++ % bytes.length] % limit;
    const words = Array.from({ length: 400 }, () =>
      Array.from({ length: 2 + next(8) }, () => String.fromCharCode(97 + next(26))).join(""));
    const out = [];
    let length = 0;
    while (length < size) {
      const word = words[(next(256) << 8 | next(256)) % words.length];
      out.push(word);
      length += word.length + 1;
    }
    return new TextEncoder().encode(out.join(" ")).slice(0, size);
  }
  const TEXTS = { "a.txt": text(1), "b.txt": text(2) };

  function commonPrefix(left, right) {
    const limit = Math.min(left.length, right.length);
    let index = 0;
    while (index < limit && left[index] === right[index]) index++;
    return index;
  }

  await check("a member damaged partway delivers what decoded before the damage under salvage", async () => {
    for (const version of FORMATS) {
      const writer = new RarWriter({ version });
      for (const [name, data] of Object.entries(TEXTS)) writer.add(name, data);
      const whole = await writer.bytes();
      // 16 bytes flipped halfway through b.txt's packed data, the last in the file.
      const packed = (await RarArchive.open(whole)).get("b.txt").compressedSize;
      const middle = whole.length - Math.floor(packed / 2);
      const data = Uint8Array.from(whole);
      for (let offset = middle; offset < middle + 16; offset++) data[offset] ^= 0x55;
      const original = TEXTS["b.txt"];

      const strict = await RarArchive.open(data);
      await assert.rejects(strict.get("b.txt").bytes(), (error) => error instanceof RarError, version);
      let failed = [];
      assert.deepEqual(await strict.readMany(["a.txt", "b.txt"], { onMemberError: (error) => failed.push(error) }),
        [TEXTS["a.txt"], new Uint8Array()], version);
      assert.deepEqual(failed.map((error) => error.member), ["b.txt"], version);

      const archive = await RarArchive.open(data, { salvage: true });
      failed = [];
      const got = await archive.get("b.txt").bytes({ onMemberError: (error) => failed.push(error) });
      assert.deepEqual(failed.map((error) => error.member), ["b.txt"], version);
      // Up to the damage the bytes are the member's own; past it, what the decoder made of it.
      assert.notDeepEqual(got, original, version);
      assert.ok(got.length <= original.length, version);
      assert.ok(commonPrefix(got, original) > original.length / 8, `${version}: ${commonPrefix(got, original)}`);

      const reported = [];
      await archive.test({ onMemberError: (error) => reported.push(error) });
      assert.deepEqual(summary(reported), summary(failed), version);

      const out = fresh();
      failed = [];
      await archive.extractAll(out, { onMemberError: (error) => failed.push(error), keepBroken: true });
      assert.deepEqual(await extracted(out), { "a.txt": TEXTS["a.txt"], "b.txt": got }, version);
      assert.deepEqual(failed.map((error) => error.member), ["b.txt"], version);
    }
  });

  await check("an archive cut through a member opens only under salvage, which delivers what is there", async () => {
    for (const version of FORMATS) {
      const data = cutThrough(await build(version), "m1.bin");
      await assert.rejects(RarArchive.open(data), coded("INVALID_ARCHIVE"), version);

      const archive = await RarArchive.open(data, { salvage: true });
      // The cut member is listed, and gets the bytes the file still holds.
      assert.deepEqual(archive.entries.map((entry) => entry.name), ["m0.bin", "m1.bin"], version);
      const { truncation } = archive;
      assert.equal(truncation.block, "member", version);
      assert.deepEqual(truncation.name, new TextEncoder().encode("m1.bin"), version);
      assert.equal(truncation.started, true);
      assert.equal(truncation.membersComplete, false);
      assert.equal(truncation.volumeIndex, 0);
      assert.ok(truncation.offset < data.length);
      assert.match(truncation.message, /m1\.bin/);
      assert.ok(Object.isFrozen(truncation));
      assert.deepEqual(archive.headerDamage, []);

      let failed = [];
      assert.deepEqual(await archive.readMany(["m0.bin", "m1.bin"], { onMemberError: (error) => failed.push(error) }),
        [MEMBERS["m0.bin"], MEMBERS["m1.bin"].slice(0, 1500)], version);
      assert.deepEqual(summary(failed), [["MEMBER_CUT_SHORT", "m1.bin"]], version);
      assert.equal(failed[0].details.packedBytes, "3000", version);
      assert.equal(failed[0].details.presentBytes, "1500", version);
      await assert.rejects(archive.get("m1.bin").bytes(), coded("MEMBER_CUT_SHORT"), version);

      failed = [];
      await archive.test({ onMemberError: (error) => failed.push(error) });
      assert.deepEqual(summary(failed), [["MEMBER_CUT_SHORT", "m1.bin"]], version);
      await assert.rejects(archive.test(), coded("MEMBER_CUT_SHORT"), version);

      let out = fresh();
      await archive.extractAll(out, { onMemberError: (error) => failed.push(error) });
      assert.deepEqual(await extracted(out), { "m0.bin": MEMBERS["m0.bin"] }, version);
      out = fresh();
      await archive.extractAll(out, { onMemberError: (error) => failed.push(error), keepBroken: true });
      assert.deepEqual(await extracted(out),
        { "m0.bin": MEMBERS["m0.bin"], "m1.bin": MEMBERS["m1.bin"].slice(0, 1500) }, version);
    }
  });

  await check("an archive cut in its recovery record reads every member, salvage or not", async () => {
    for (const version of ["rar50", "rar70"]) {
      const whole = await build(version, { recoveryPercent: 10 });
      // Past the last member's data, and short of the few bytes of end block after the record.
      const cut = whole.slice(0, indexOf(whole, MEMBERS["m2.bin"]) + 3000 + 100);
      assert.ok(cut.length < whole.length - 100);
      for (const salvage of [false, true]) {
        const archive = await RarArchive.open(cut, { salvage });
        assert.deepEqual(archive.entries.map((entry) => entry.name), NAMES);
        assert.equal(archive.truncation.block, "recoveryRecord", version);
        assert.equal(archive.truncation.name, undefined);
        assert.equal(archive.truncation.membersComplete, true);
        assert.match(archive.truncation.message, /recovery record/);
        await archive.test();
        const out = fresh();
        await archive.extractAll(out);
        assert.deepEqual(await extracted(out), MEMBERS);
      }
      assert.equal((await RarArchive.open(whole)).truncation, undefined);
    }
  });

  await check("a damaged header is read past and listed only under salvage", async () => {
    for (const version of FORMATS) {
      const whole = await build(version);
      const data = Uint8Array.from(whole);
      // M1.bin now, and the header fails its checksum.
      data[indexOf(whole, new TextEncoder().encode("m1.bin"))] ^= 0x20;
      await assert.rejects(RarArchive.open(data), (error) => error instanceof RarError, version);

      const archive = await RarArchive.open(data, { salvage: true });
      assert.deepEqual(archive.entries.map((entry) => entry.name), ["m0.bin", "M1.bin", "m2.bin"], version);
      assert.equal(archive.headerDamage.length, 1, version);
      const [damage] = archive.headerDamage;
      assert.equal(damage.kind, "checksum", version);
      assert.equal(damage.offset, indexOf(whole, MEMBERS["m0.bin"]) + 3000, version);
      assert.equal(damage.volumeIndex, 0);
      assert.match(damage.message, /checksum/);
      assert.ok(Object.isFrozen(archive.headerDamage) && Object.isFrozen(damage));

      // The member's data is whole, so it reads and verifies.
      const failed = [];
      assert.deepEqual(await archive.readMany(archive.entries, { onMemberError: (error) => failed.push(error) }),
        Object.values(MEMBERS), version);
      assert.deepEqual(failed, []);
      await archive.test();
      const out = fresh();
      await archive.extractAll(out);
      assert.deepEqual(await extracted(out),
        { "m0.bin": MEMBERS["m0.bin"], "M1.bin": MEMBERS["m1.bin"], "m2.bin": MEMBERS["m2.bin"] }, version);
    }
  });

  await check("a volume set with a volume missing reads both sides of the gap under salvage", async () => {
    // Three volumes, the middle one missing; then more, so both sides of the gap are sets.
    for (const extra of [{}, { "big.bin": random(9, 12_000) }]) {
      const directory = fresh();
      const writer = new RarWriter({ version: "rar50", level: 0, volumeSize: 4096 });
      const everything = { ...MEMBERS, ...extra, "tail.txt": new TextEncoder().encode("tail") };
      for (const [name, data] of Object.entries(everything)) writer.add(name, data);
      await mkdir(directory);
      const paths = await writer.writeTo(path.join(directory, "set.part1.rar"));
      assert.ok(paths.length >= 3);
      const missing = Math.floor(paths.length / 2);
      await unlink(paths[missing]);
      const label = `${paths.length} volumes, ${missing} missing`;

      // Strict: the set is refused where it runs out, naming the missing volume.
      const strict = await RarArchive.open(paths[0]).catch((error) => error);
      const refused = (error) => error instanceof RarError && error.code === "MISSING_VOLUME"
        && error.details.volumeIndex === missing && error.details.path === paths[missing];
      if (strict instanceof RarArchive) {
        assert.deepEqual(strict.incompleteMembers, []);
        await assert.rejects(strict.extractAll(fresh()), refused, label);
        await assert.rejects(strict.test(), refused, label);
      } else {
        assert.ok(refused(strict), `${label}: ${strict}`);
      }

      // The run before the gap, its later volumes found by name until the missing one.
      const before = await RarArchive.open(paths[0], { salvage: true });
      assert.deepEqual(before.volumePaths, paths.slice(0, missing), label);
      assert.ok(before.incompleteMembers.length > 0, label);
      assert.deepEqual(new Set(before.incompleteMembers.map((member) => member.missing)), new Set(["end"]), label);
      await before.test();
      const beforeOut = fresh();
      await before.extractAll(beforeOut);
      // Volumes as they arrive would bypass what opening left out.
      await assert.rejects(before.test({ volumes: [] }), coded("INVALID_OPTION"));

      // The run after it, starting with a volume other than the first, given as bytes.
      const later = await Promise.all(paths.slice(missing + 1).map(async (file) => new Uint8Array(await readFile(file))));
      const after = await RarArchive.open(later, { salvage: true });
      const [first] = after.incompleteMembers;
      assert.equal(first.volumeIndex, 0, label);
      assert.ok(["start", "both"].includes(first.missing), first.missing);
      assert.ok(first.nameBytes instanceof Uint8Array);
      await after.test();
      const afterOut = fresh();
      await after.extractAll(afterOut);

      const got = { ...await extracted(beforeOut), ...await extracted(afterOut) };
      assert.ok(Object.keys(got).length > 0, `${label}: every member was left out`);
      for (const [name, data] of Object.entries(got)) assert.deepEqual(data, everything[name], name);
      const leftOut = new Set([...before.incompleteMembers, ...after.incompleteMembers].map((member) => member.name));
      for (const name of leftOut) {
        assert.ok(name in everything, name);
        assert.ok(!(name in got), name);
      }
      assert.deepEqual(new Set([...before.entries, ...after.entries].map((entry) => entry.name)),
        new Set(Object.keys(got)), label);
      // Every member is either delivered or listed as left out.
      assert.deepEqual(new Set([...Object.keys(got), ...leftOut]), new Set(Object.keys(everything)), label);
    }
  });

  await check("a member that runs past its declared size gets its declared bytes under salvage", async () => {
    const writer = new RarWriter({ version: "rar29" });
    for (const [name, data] of Object.entries(TEXTS)) writer.add(name, data);
    const data = Uint8Array.from(await writer.bytes());
    // A RAR 2.9 file header: 32 fixed bytes, then the name.
    const head = indexOf(data, new TextEncoder().encode("b.txt")) - 32;
    assert.equal(data[head + 2], 0x74);
    const view = new DataView(data.buffer);
    view.setUint32(head + 11, 1000, true);
    const size = view.getUint16(head + 5, true);
    view.setUint16(head, crc32(data.subarray(head + 2, head + size)) & 0xffff, true);

    await assert.rejects((await RarArchive.open(data)).get("b.txt").bytes(),
      (error) => error instanceof RarError && error.code !== "MEMBER_RAN_PAST_DECLARED_SIZE");
    const archive = await RarArchive.open(data, { salvage: true });
    assert.deepEqual(archive.headerDamage, []);
    const failed = [];
    assert.deepEqual(await archive.get("b.txt").bytes({ onMemberError: (error) => failed.push(error) }),
      TEXTS["b.txt"].slice(0, 1000));
    assert.deepEqual(summary(failed), [["MEMBER_RAN_PAST_DECLARED_SIZE", "b.txt"]]);
    assert.equal(failed[0].details.declaredBytes, "1000");
  });

  await check("a member without its password is reported, and keeps nothing", async () => {
    const data = await build("rar50", { password: "secret" });
    for (const salvage of [false, true]) {
      const archive = await RarArchive.open(data, { salvage });
      const failed = [];
      const out = fresh();
      assert.deepEqual(await archive.extractAll(out, {
        onMemberError: (error) => failed.push(error), keepBroken: salvage,
      }), []);
      assert.deepEqual(summary(failed), NAMES.map((name) => ["PASSWORD_REQUIRED", name]));
    }
    // A wrong password still fails the call.
    const archive = await RarArchive.open(data);
    const reported = [];
    await assert.rejects(archive.test({ password: "wrong", onMemberError: (error) => reported.push(error) }),
      coded("BAD_PASSWORD"));
    assert.deepEqual(reported, []);
  });

  await check("salvage options are checked before any work", async () => {
    const data = flipped(await build("rar50"), "m1.bin");
    const strict = await RarArchive.open(data);
    const salvaged = await RarArchive.open(data, { salvage: true });
    const out = fresh();
    await assert.rejects(strict.extractAll(out, { onMemberError: () => {}, keepBroken: true }),
      (error) => coded("INVALID_OPTION")(error) && /salvage/.test(error.message));
    await assert.rejects(salvaged.extractAll(out, { keepBroken: true }),
      (error) => coded("INVALID_OPTION")(error) && /onMemberError/.test(error.message));
    await assert.rejects(salvaged.extractAll(out, { onMemberError: () => {}, keepBroken: "yes" }), TypeError);
    await assert.rejects(strict.extractAll(out, { members: ["m0.bin"], onMemberError: () => {} }),
      (error) => coded("INVALID_OPTION")(error) && /members/.test(error.message));
    await assert.rejects(strict.get("m0.bin").extract(out, { onMemberError: () => {} }), coded("INVALID_OPTION"));
    await assert.rejects(strict.test({ onMemberError: 1 }), TypeError);
    await assert.rejects(strict.get("m0.bin").bytes({ onMemberError: "no" }), TypeError);
    await assert.rejects(strict.readMany(NAMES, { onMemberError: {} }), TypeError);
    await assert.rejects(RarArchive.open(data, { salvage: 1 }), coded("INVALID_OPTION"));
    // Salvage belongs to the archive.
    await assert.rejects(strict.test({ salvage: true }), coded("INVALID_OPTION"));
    await assert.rejects(salvaged.test({ salvage: false }), coded("INVALID_OPTION"));
    await assert.rejects(readdir(out), (error) => error.code === "ENOENT");
    // Matching the archive's own setting is no change.
    await salvaged.test({ salvage: true, onMemberError: () => {} });
  });

  await check("onMemberError leaves progress and cancellation working", async () => {
    const data = flipped(await build("rar50"), "m1.bin");
    const archive = await RarArchive.open(data, { salvage: true });

    // Progress and reports interleave, and the call ends with the total.
    const events = [];
    const failed = [];
    await archive.test({
      onProgress: (event) => events.push(event),
      onMemberError: (error) => failed.push(error),
    });
    assert.deepEqual(summary(failed), [["CHECKSUM_MISMATCH", "m1.bin"]]);
    assert.ok(events.length > 1);
    assert.equal(events.at(-1).completed, events.at(-1).total);

    // What the callback throws fails the call, and the runtime recovers.
    const stop = new Error("stop here");
    await assert.rejects(archive.test({ onMemberError: () => { throw stop; } }), (error) => error === stop);
    await assert.rejects(archive.extractAll(fresh(), { onMemberError: (error) => { throw error; } }),
      coded("CHECKSUM_MISMATCH"));
    assert.deepEqual(await archive.get("m0.bin").bytes(), MEMBERS["m0.bin"]);

    // An aborted signal still stops the call before it starts.
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(archive.test({ signal: controller.signal, onMemberError: () => {} }),
      (error) => error.name === "AbortError");
  });

  await check("onMemberError can't read a member in a later volume of a set", async () => {
    const writer = new RarWriter({ version: "rar50", level: 0, volumeSize: 4096 });
    for (const [name, data] of Object.entries(MEMBERS)) writer.add(name, data);
    const archive = await RarArchive.open(await writer.volumes());
    // m0.bin is whole in the first volume; m1.bin continues into the second, where m2.bin starts.
    assert.deepEqual(archive.entries.map((entry) => entry.volumeIndex), [0, 0, 1]);
    assert.deepEqual(await archive.get("m0.bin").bytes({ onMemberError: () => {} }), MEMBERS["m0.bin"]);
    for (const name of ["m1.bin", "m2.bin"]) {
      await assert.rejects(archive.get(name).bytes({ onMemberError: () => {} }), coded("INVALID_OPTION"), name);
      await assert.rejects(archive.readMany(["m0.bin", name], { onMemberError: () => {} }), coded("INVALID_OPTION"), name);
    }
    // test() and extractAll() can carry on past those.
    await archive.test({ onMemberError: () => {} });
  });
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

console.log(`${passed} salvage checks passed`);
