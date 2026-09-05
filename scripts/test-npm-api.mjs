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
