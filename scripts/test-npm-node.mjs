// Exercise the production Node adapters with real workers and filesystem I/O.
// Codec output is controlled, so these regressions need no WASM rebuild.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const sources = new URL("../npm-src/", import.meta.url);
const temporary = await mkdtemp(path.join(os.tmpdir(), "rars-node-adapters-"));

async function stageNodeAdapter(directory, worker) {
  const node = path.join(directory, "node");
  await mkdir(path.join(node, "wasm"), { recursive: true });
  await writeFile(path.join(directory, "package.json"), '{ "type": "module" }\n');
  for (const [file, name] of [["api", "createApi"], ["client", "createClient"], ["worker-engine", "startWorker"]]) {
    const source = await readFile(new URL(`${file}.js`, sources), "utf8");
    await writeFile(path.join(node, `${file}.js`), source);
    // Match scripts/build-npm.sh's conversion of the handwritten ESM exports.
    await writeFile(path.join(node, `${file}.cjs`),
      `${source.replace(`export function ${name}`, `function ${name}`)}\nmodule.exports = { ${name} };\n`);
  }
  for (const [source, target] of [["node-index.js", "index.js"], ["node-index.cjs", "index.cjs"]]) {
    await writeFile(path.join(node, target), await readFile(new URL(source, sources)));
  }
  await writeFile(path.join(node, "worker.cjs"), worker ?? await readFile(new URL("node-worker.cjs", sources)));
  await writeFile(path.join(node, "wasm", "package.json"), '{ "type": "commonjs" }\n');
  return node;
}

try {
  const lifetime = path.join(temporary, "lifetime");
  await stageNodeAdapter(lifetime, `
    const { parentPort } = require("node:worker_threads");
    parentPort.on("message", ({ id }) => {
      setTimeout(() => parentPort.postMessage({ id, result: Uint8Array.of(id) }), id === 1 ? 5 : 100);
    });
  `);
  for (const commonjs of [false, true]) {
    const runner = path.join(lifetime, commonjs ? "run.cjs" : "run.mjs");
    await writeFile(runner, `
      ${commonjs ? 'const { RarWriter } = require("./node/index.cjs");' : 'import { RarWriter } from "./node/index.js";'}
      const writer = new RarWriter().add("file.txt", "data");
      Promise.all([writer.bytes(), writer.bytes()]).then(([first, second]) => {
        if (first[0] !== 1 || second[0] !== 2) throw new Error("incorrect worker results");
        console.log("both queued operations completed");
      }).catch((error) => { console.error(error); process.exitCode = 1; });
    `);
    // No timer or other referenced handle in the child can hide premature exit.
    const child = spawnSync(process.execPath, [runner], { encoding: "utf8", timeout: 10_000 });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout.trim(), "both queued operations completed", commonjs ? "CommonJS lifetime" : "ESM lifetime");
  }
  console.log("npm real Node queued-worker lifetime checks passed (ESM and CommonJS)");

  const node = await stageNodeAdapter(path.join(temporary, "volumes"));
  // The stub supplies one distinct byte per volume. Only the codec is replaced:
  // the public API, worker engine, path planning and writes are production code.
  await writeFile(path.join(node, "wasm", "rars_wasm.js"), `
    exports.RarBuilder = class {
      constructor(options) { this.total = options.volumeSize; }
      addBytes() {}
      toVolumes() { return Array.from({ length: this.total }, (_, index) => Uint8Array.of(index)); }
      free() {}
    };
  `);
  const { RarWriter } = await import(pathToFileURL(path.join(node, "index.js")));

  async function writeVolumes(directory, firstName, total, format = "rar29") {
    await mkdir(directory, { recursive: true });
    return new RarWriter({ format, level: 0 }).add("file.txt", "data")
      .writeVolumesTo(path.join(directory, firstName), total);
  }

  for (const firstName of ["archive", "archive.rar"]) {
    const directory = path.join(temporary, `legacy-${firstName}.parent.with.dots`);
    const actual = await writeVolumes(directory, firstName, 3);
    assert.deepEqual(actual, [firstName, "archive.r00", "archive.r01"].map((name) => path.join(directory, name)));
    assert.deepEqual((await readdir(directory)).sort(), [firstName, "archive.r00", "archive.r01"].sort());
    for (const [index, file] of actual.entries()) assert.deepEqual(await readFile(file), Buffer.of(index));
  }

  // RAR follows the case of the first extension, and unrar looks only for that name.
  for (const [firstName, later] of [["archive.RAR", "R"], ["archive.Rar", "R"], ["archive.rAR", "r"]]) {
    const directory = path.join(temporary, `legacy-case-${firstName}`);
    const actual = await writeVolumes(directory, firstName, 3);
    assert.deepEqual(actual, [firstName, `archive.${later}00`, `archive.${later}01`].map((name) => path.join(directory, name)));
  }
  {
    const directory = path.join(temporary, "rar50-upper");
    const actual = await writeVolumes(directory, "archive.RAR", 2, "rar50");
    assert.deepEqual(actual, [1, 2].map((index) => path.join(directory, `archive.part0${index}.RAR`)));
  }

  const maximum = path.join(temporary, "legacy-maximum");
  const paths = await writeVolumes(maximum, "archive.rar", 101);
  assert.equal(paths.at(-1), path.join(maximum, "archive.r99"));
  assert.equal((await readdir(maximum)).length, 101);
  assert.deepEqual(await readFile(paths.at(-1)), Buffer.of(100));

  for (const [caseIndex, [firstName, total, message]] of [
    ["archive.rar", 102, /\.r00 through \.r99/],
    ["archive.r00", 3, /paths must be distinct/],
    ["archive.R00", 3, /paths must be distinct/],
  ].entries()) {
    const directory = path.join(temporary, `refusal-${caseIndex}`);
    await mkdir(directory);
    const first = path.join(directory, firstName);
    const existing = path.join(directory, "archive.r99");
    await writeFile(first, "original first");
    await writeFile(existing, "original last");
    await assert.rejects(writeVolumes(directory, firstName, total), (error) =>
      error.code === "INVALID_OPTION" && message.test(error.message));
    assert.equal(await readFile(first, "utf8"), "original first");
    assert.equal(await readFile(existing, "utf8"), "original last");
    assert.deepEqual((await readdir(directory)).sort(), [firstName, "archive.r99"].sort());
  }

  for (const format of ["rar50", "rar70"]) {
    const directory = path.join(temporary, format);
    const actual = await writeVolumes(directory, "archive.part01.rar", 3, format);
    assert.deepEqual(actual, [1, 2, 3].map((index) => path.join(directory, `archive.part0${index}.rar`)));
    for (const [index, file] of actual.entries()) assert.deepEqual(await readFile(file), Buffer.of(index));
  }
  await assert.rejects(new RarWriter({ format: "rar29", level: 0 }).add("file.txt", "data")
    .writeVolumesTo("", 1), (error) => error.code === "INVALID_OPTION" && /needs a file name/.test(error.message));
  console.log("npm production Node volume naming, output and preservation checks passed");
} finally {
  await rm(temporary, { recursive: true, force: true });
}
