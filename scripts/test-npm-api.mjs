// Test the source API without rebuilding WASM or starting a worker.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../npm-src/api.js", import.meta.url));
const { createApi } = await import(`data:text/javascript;base64,${source.toString("base64")}`);
const { RarWriter } = createApi({
  prepareEntryData: (data) => data,
  setErrorFactory() {},
});

for (const name of [(value) => value, (value) => new TextEncoder().encode(value)]) {
  const writer = new RarWriter().add(name("a"), new Uint8Array([1]))
    .add(name("b"), new Uint8Array([2]));
  assert.equal(writer.rename(name("a"), name("a")), writer);
  assert.deepEqual(writer.names, [name("a"), name("b")]);
  assert.throws(() => writer.rename(name("a"), name("b")),
    (error) => error.code === "DUPLICATE_ENTRY");
  assert.deepEqual(writer.names, [name("a"), name("b")]);
  assert.throws(() => writer.rename(name("missing"), name("b")),
    (error) => error.code === "ENTRY_NOT_FOUND");
  writer.rename(name("a"), name("c"));
  assert.deepEqual(writer.names, [name("c"), name("b")]);
}
console.log("npm source API rename checks passed");

// Decoding can make a Unicode name and a legacy byte name look identical.
const { RarArchive } = createApi({
  prepareArchiveSources: async (input) => [input],
  setErrorFactory() {},
  request: async () => ({
    entries: [
      { index: 0, name: "café", nameBytes: new TextEncoder().encode("café") },
      { index: 1, name: "café", nameBytes: new Uint8Array([99, 97, 102, 130]) },
    ],
  }),
});
const decoded = await RarArchive.open(new Uint8Array(), { legacyNameEncoding: "cp850" });
assert.throws(() => decoded.get("café"), (error) => error.code === "AMBIGUOUS_ENTRY");
assert.equal(decoded.getAll("café").length, 2);
assert.equal(decoded.get(new Uint8Array([99, 97, 102, 130])).index, 1);
assert.equal(decoded.get("missing"), undefined);
console.log("npm decoded-name ambiguity checks passed");

// Repeated raw names are distinct entries; names select the last one.
const duplicateRequests = [];
const batchRequests = [];
const { RarArchive: DuplicateArchive } = createApi({
  prepareArchiveSources: async (input) => [input],
  setErrorFactory() {},
  request: async (operation, payload) => {
    if (operation === "open") return { entries: [
      { index: 0, name: "same", nameBytes: new TextEncoder().encode("same"), size: 5 },
      { index: 1, name: "same", nameBytes: new TextEncoder().encode("same"), size: 6 },
    ] };
    if (operation === "readMany") {
      batchRequests.push([payload.indices, payload.readOptions, payload.password]);
      return payload.indices.map((index) => new Uint8Array([index]));
    }
    duplicateRequests.push(payload.index);
    return new Uint8Array([payload.index]);
  },
});
for (const settings of [{}, { legacyNameEncoding: "cp850" }]) {
  const archive = await DuplicateArchive.open(new Uint8Array(), settings);
  assert.equal(archive.get("same").index, 1);
  assert.equal(archive.get("same").size, 6);
  for (const entry of archive.getAll("same")) {
    assert.deepEqual(await entry.bytes(), new Uint8Array([entry.index]));
  }
  assert.deepEqual(await archive.readMany([archive.entries[0], "same", archive.entries[1]], {
    maxTotalOutputBytes: 11, password: "secret",
  }), [new Uint8Array([0]), new Uint8Array([1]), new Uint8Array([1])]);
  const other = await DuplicateArchive.open(new Uint8Array(), settings);
  await assert.rejects(archive.readMany([other.entries[0]]), (error) => error.code === "INVALID_OPTION");
  await assert.rejects(archive.readMany(["missing"]), (error) => error.code === "ENTRY_NOT_FOUND");
  archive.close();
  await assert.rejects(archive.readMany([]), (error) => error.code === "CLOSED");
}
assert.deepEqual(duplicateRequests, [0, 1, 0, 1]);
assert.deepEqual(batchRequests, [
  [[0, 1, 1], {maxTotalOutputBytes: 11}, "secret"],
  [[0, 1, 1], {maxTotalOutputBytes: 11}, "secret"],
]);
console.log("npm duplicate member identity checks passed");

// The handwritten API validates and forwards workspace limits without a WASM build.
const quotaRequests = [];
const { RarArchive: QuotaArchive } = createApi({
  prepareArchiveSources: async (input) => [input],
  setErrorFactory() {},
  request: async (operation, payload) => {
    quotaRequests.push([operation, payload.readOptions]);
    return { entries: [] };
  },
});
const quotaArchive = await QuotaArchive.open(new Uint8Array(), { maxReaderWorkspaceBytes: 8192n });
await quotaArchive.test({ maxReaderWorkspaceBytes: 4096 });
await quotaArchive.readComment({ maxReaderWorkspaceBytes: 2048n });
assert.deepEqual(quotaRequests, [
  ["open", { maxReaderWorkspaceBytes: 8192n }],
  ["test", { maxReaderWorkspaceBytes: 4096 }],
  ["readComment", { maxReaderWorkspaceBytes: 2048n }],
]);
for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, -1n, 1n << 64n]) {
  await assert.rejects(QuotaArchive.open(new Uint8Array(), { maxReaderWorkspaceBytes: value }),
    (error) => error.code === "INVALID_OPTION");
}
console.log("npm reader workspace forwarding checks passed");
