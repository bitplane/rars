// Exercise the real worker boundary with controlled WASM/platform failures.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../npm-src/worker-engine.js", import.meta.url));
const { startWorker } = await import(`data:text/javascript;base64,${source.toString("base64")}`);

async function failure(error, options = {}) {
  let dispatch;
  const replies = [];
  startWorker({
    onMessage(callback) { dispatch = callback; },
    post(message) { replies.push(structuredClone(message)); },
  }, { repair() { throw error; } }, options.platform ?? {});
  await dispatch({ id: 7, operation: "repair", payload: {
    sources: options.sources ?? [new Uint8Array([0])],
  } });
  assert.equal(replies.filter((message) => message.error).length, 1);
  assert.equal(replies.filter((message) => message.progress?.phase === "complete").length, 0);
  return replies.find((message) => message.error).error;
}

const details = {
  contexts: [{ kind: "volume", number: 3 }, { kind: "entry", nameBytes: [255, 97], operation: "reading" }],
  limitBytes: "9007199254740993", requiredBytes: "9007199254740994",
};
for (const code of ["IO", "INVALID_ARCHIVE", "UNSUPPORTED_FEATURE", "PASSWORD_REQUIRED",
  "BAD_PASSWORD", "RESOURCE_LIMIT", "CANCELLED", "SOURCE_CHANGED", "ENTRY_NOT_FOUND"]) {
  const message = "a password is required; checksum mismatch; unsafe archive path";
  assert.deepEqual(await failure(Object.assign(new Error(message), { code, details })), { code, message, details });
}
assert.equal((await failure(new Error("a password is required"))).code, "INTERNAL");
assert.equal((await failure(new TypeError("unsupported binary source"))).code, "INVALID_OPTION");
const missing = await failure(null, {
  sources: [{ kind: "path", path: `missing-${process.pid}.rar` }],
  platform: { readFile: (path) => readFile(new URL(`../target/${path}`, import.meta.url)) },
});
assert.equal(missing.code, "IO");
assert.equal(missing.details.systemCode, "ENOENT");
assert.equal(missing.details.syscall, "open");
console.log("npm worker error-code and context checks passed");
