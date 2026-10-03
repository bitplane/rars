// Exercise the Rust engine in a real JS host, independently of the worker facade.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.resolve(process.argv[2] || 'npm/node/wasm/rars_wasm.js'));
const root = path.resolve(__dirname, '..');
const fixture = name => new Uint8Array(fs.readFileSync(path.join(root, 'crates/rars/tests/fixtures', name)));
const bytes = text => new TextEncoder().encode(text);
let passed = 0;
function check(name, run) {
  run();
  passed++;
  console.log(`ok ${name}`);
}
function refuses(run, code) {
  assert.throws(run, error => {
    assert.ok(error instanceof Error);
    assert.equal(error.code, code);
    return true;
  });
}
check('duplicate names select matching metadata and preserve indexed payloads', () => {
  // Two stored RAR5 entries named one.txt, containing first and second. The
  // second header name was changed from two.txt and its header CRC repaired.
  const duplicate = new Uint8Array(Buffer.from(
    'UmFyIRoHAQDFGjMyAwEAAIe1fWw4AgMjBQQFIFfucZIAAAdvbmUudHh0IgIASJ7flVWyNBvXKh1H6TwHIs0a76r8wrPpigI6do4ABypmaXJzdFbJyX04AgMjBgQGIGkRH7YAAAdvbmUudHh0IgIAJJVKEjlQkpNfDgy070r9SAIVz/fdw+qSIEAjdC8w2e9zZWNvbmQZsjo1AwUAAA==',
    'base64',
  ));
  const archive = new engine.RarFile(duplicate);
  const info = archive.getInfo('one.txt');
  assert.equal(info.size, 6);
  assert.deepEqual(archive.read('one.txt'), bytes('second'));
  assert.deepEqual(archive.readAt(0), bytes('first'));
  assert.deepEqual(archive.readAt(1), bytes('second'));
  info.free();
  archive.free();
});
check('version and stored round trips expose all metadata getters', () => {
  assert.match(engine.version(), /^\d+\.\d+\.\d+$/);
  for (const format of engine.formats()) {
    const builder = new engine.RarBuilder({format, store: true});
    builder.addBytes('first.txt', bytes('first'), {mtime: 0, mode: 0o640});
    builder.addBytesRaw(bytes('second.txt'), bytes('second'), {mtime: 1, mode: 0o640});
    assert.equal(builder.length, 2);
    assert.deepEqual(builder.names(), ['first.txt', 'second.txt']);
    builder.rename('second.txt', 'renamed.txt');
    const archive = new engine.RarFile(builder.toBytes());
    assert.deepEqual(archive.names(), ['first.txt', 'renamed.txt']);
    assert.equal(archive.sfxOffset, 0);
    assert.equal(archive.needsPassword, false);
    assert.ok(['rar13', 'rar15_40', 'rar50_plus'].includes(archive.family));
    assert.equal(archive.comment, undefined);
    const infos = archive.entries();
    for (const [index, info] of infos.entries()) {
      assert.equal(info.name, archive.names()[index]);
      assert.deepEqual(info.nameBytes, bytes(info.name));
      assert.ok(info.size > 0);
      assert.ok(info.packedSize > 0);
      assert.equal(info.isEncrypted, false);
      assert.equal(info.isStored, true);
      assert.equal(info.isDirectory, false);
      assert.equal(info.isSplitBefore, false);
      assert.equal(info.isSplitAfter, false);
      assert.equal(typeof info.isSolid, 'boolean');
      assert.ok(info.crc === undefined || Number.isInteger(info.crc));
      assert.ok(info.hostOs === undefined || Number.isInteger(info.hostOs));
      assert.ok(Number.isInteger(info.fileAttr));
      assert.ok(info.fileTime === undefined || Number.isInteger(info.fileTime));
      assert.deepEqual(archive.read(info.name), archive.readAt(index));
      info.free();
    }
    const info = archive.getInfo('first.txt');
    assert.equal(info.name, 'first.txt');
    info.free();
    assert.equal(archive.getInfo('missing'), undefined);
    archive.test();
    refuses(() => archive.read('missing'), 'ENTRY_NOT_FOUND');
    refuses(() => archive.readAt(100), 'ENTRY_NOT_FOUND');
    builder.remove('renamed.txt');
    assert.equal(builder.length, 1);
    refuses(() => builder.remove('missing'), 'ENTRY_NOT_FOUND');
    refuses(() => builder.rename('missing', 'other'), 'ENTRY_NOT_FOUND');
    refuses(() => builder.addBytes('first.txt', bytes('duplicate')), 'DUPLICATE_ENTRY');
    builder.free();archive.free();
  }
});
check('options retain conversion exceptions and exact reader limits', () => {
  refuses(() => new engine.RarBuilder({format: 'bogus'}), 'UNSUPPORTED_FORMAT');
  for (const options of [{format: 1}, {compression: '3'}, {password: 1}, {comment: []}])
    refuses(() => new engine.RarBuilder(options), 'INVALID_OPTION');
  const data = fixture('rar50/stored.rar');
  for (const value of [-1, 1.5, NaN, Infinity, 2 ** 53, '1', -1n, 1n << 64n])
    refuses(() => new engine.RarFile(data, undefined, {maxHeaderCount: value}), 'INVALID_OPTION');
  for (const value of [undefined, null, 100, 100n, (1n << 64n) - 1n]) {
    const archive = new engine.RarFile(data, undefined, {maxHeaderCount: value});
    archive.test();archive.free();
  }
  for (const settings of [{legacyNameEncoding: 1}, {legacyNameEncoding: 'auto'}])
    refuses(() => new engine.RarFile(data, undefined, settings), 'INVALID_OPTION');
  refuses(() => new engine.RarFile(data, 1), 'INVALID_OPTION');
  refuses(() => engine.RarFile.openVolumes([]), 'INVALID_ARCHIVE');
  refuses(() => engine.RarFile.openVolumes([data, []]), 'INVALID_OPTION');
});
check('comments passwords and indexed volume extraction round trip', () => {
  for (const password of ['secret', bytes('secret')]) {
    const builder = new engine.RarBuilder({store: true, password, comment: bytes('comment')});
    builder.addBytes('file', bytes('payload'));
    const archive = new engine.RarFile(builder.toBytes(), password);
    assert.equal(archive.needsPassword, true);
    assert.deepEqual(archive.comment, bytes('comment'));
    assert.deepEqual(archive.readComment(), bytes('comment'));
    assert.deepEqual(archive.read('file'), bytes('payload'));
    archive.test();archive.free();builder.free();
  }
  for (const format of ['rar14', 'rar29', 'rar50', 'rar70']) {
    const builder = new engine.RarBuilder({format, store: true, volumeSize: 64});
    builder.addBytes('file', bytes('payload'.repeat(30)));
    if (format === 'rar50' || format === 'rar70') builder.addBytes('later', bytes('last member'));
    const parts = builder.toVolumes();
    assert.ok(parts.length > 1);
    const archive = engine.RarFile.openVolumes(parts);
    assert.deepEqual(archive.readAt(0), bytes('payload'.repeat(30)));
    assert.deepEqual(archive.read('file'), bytes('payload'.repeat(30)));
    if (format === 'rar50' || format === 'rar70') assert.deepEqual(archive.read('later'), bytes('last member'));
    refuses(() => archive.read('missing'), 'ENTRY_NOT_FOUND');
    refuses(() => archive.readAt(0, undefined, {maxMemberOutputBytes: 'bad'}), 'INVALID_OPTION');
    refuses(() => archive.test(undefined, {maxMemberOutputBytes: 'bad'}), 'INVALID_OPTION');
    refuses(() => archive.readAt(100), 'ENTRY_NOT_FOUND');
    archive.test();archive.free();builder.free();
  }
});
check('recovery returns independent data and structured report getters', () => {
  const data = fixture('rar50/with_recovery.rar');
  const result = engine.repairDetailed(data);
  const report = result.report;
  assert.equal(typeof report.changed, 'boolean');
  assert.equal(typeof report.dataRepaired, 'boolean');
  assert.equal(typeof report.recoveryRecordRebuilt, 'boolean');
  assert.equal(typeof report.endRecordRebuilt, 'boolean');
  assert.ok(report.availableRecoveryShards === undefined || Number.isInteger(report.availableRecoveryShards));
  assert.ok(report.expectedRecoveryShards === undefined || Number.isInteger(report.expectedRecoveryShards));
  assert.deepEqual(result.data, engine.repair(data, null));
  const archive = new engine.RarFile(result.data);
  archive.test();archive.free();report.free();result.free();
  refuses(() => engine.repair(bytes('not an archive')), 'UNSUPPORTED_FORMAT');
  refuses(() => engine.repairDetailed(bytes('not an archive')), 'UNSUPPORTED_FORMAT');
});
check('null options and resource-aware stored outputs retain their defaults', () => {
  const defaults = new engine.RarBuilder();
  assert.equal(defaults.length, 0);defaults.free();
  for (const format of ['rar14', 'rar29', 'rar50']) {
    const builder = new engine.RarBuilder({format, store: true, compression: null,
      password: null, comment: null, maxMemoryBytes: 64n * 1024n * 1024n});
    builder.addBytesRaw(bytes('file'), bytes('payload'.repeat(30)), {mtime: null, mode: null});
    if (format !== 'rar50') {
      refuses(() => builder.toBytes(), 'UNSUPPORTED_FEATURE');
      refuses(() => builder.toVolumes(), 'UNSUPPORTED_FEATURE');
      builder.free();continue;
    }
    const archive = new engine.RarFile(builder.toBytes(), null, null);
    archive.test(null, null);
    assert.deepEqual(archive.read('file', null, null), bytes('payload'.repeat(30)));
    assert.equal(archive.readComment(null, null), undefined);archive.free();
    const volumeBuilder = new engine.RarBuilder({format, store: true, volumeSize: 64, maxMemoryBytes: 64n * 1024n * 1024n});
    volumeBuilder.addBytes('file', bytes('payload'.repeat(30)));
    const volumes = engine.RarFile.openVolumes(volumeBuilder.toVolumes(), undefined, {legacyNameEncoding: null});
    volumes.test();volumes.free();volumeBuilder.free();builder.free();
  }
  const builder = new engine.RarBuilder({format: null, store: true, compression: 0});
  builder.addBytes('file', bytes('payload'));builder.free();
});
check('reader quota errors retain structured exact amounts and contexts', () => {
  const data = fixture('rar50/stored.rar');
  let error;
  try { new engine.RarFile(data, undefined, {maxHeaderCount: 0}); } catch (caught) { error = caught; }
  assert.equal(error.code, 'RESOURCE_LIMIT');
  assert.equal(error.details.limitHeaders, '0');
  assert.equal(typeof error.details.requiredHeaders, 'string');
  refuses(() => new engine.RarFile(data, undefined, {maxHeaderBytes: 1}), 'RESOURCE_LIMIT');
  const archive = new engine.RarFile(data);
  const name = archive.names()[0];
  for (const settings of [{maxMemberOutputBytes: 0}, {maxTotalOutputBytes: 0}]) {
    try { archive.read(name, undefined, settings); assert.fail('quota must refuse'); }
    catch (caught) {
      assert.equal(caught.code, 'RESOURCE_LIMIT');
      assert.equal(caught.details.limitBytes, '0');
      assert.equal(typeof caught.details.requiredBytes, 'string');
      assert.ok(Array.isArray(caught.details.contexts));
      assert.ok(caught.details.contexts.some(context => context.kind === 'entry'));
    }
  }
  archive.free();
  const compressed = new engine.RarFile(fixture('rar50/m3_default.rar'));
  for (const settings of [{maxReaderWorkspaceBytes: 1}, {rar50DictionarySizeLimit: 1}])
    refuses(() => compressed.test(undefined, settings), 'RESOURCE_LIMIT');
  compressed.free();
  const filtered = new engine.RarFile(fixture('rar50/filter_delta.rar'));
  refuses(() => filtered.test(undefined, {rar50BufferedDecodeLimit: 1}), 'RESOURCE_LIMIT');
  filtered.free();
});
check('legacy decoded names and JavaScript getter failures survive conversion', () => {
  const builder = new engine.RarBuilder({format: 'rar29', store: true});
  builder.addBytesRaw(new Uint8Array([0x63, 0x61, 0x66, 0x82]), bytes('payload'));
  const archive = new engine.RarFile(builder.toBytes(), undefined, {legacyNameEncoding: 'cp850'});
  assert.deepEqual(archive.names(), ['café']);
  const infos = archive.entries();assert.equal(infos[0].name, 'café');infos[0].free();
  assert.deepEqual(archive.readAt(0), bytes('payload'));
  const marker = new Error('getter failure');
  assert.throws(() => new engine.RarBuilder({get format() {throw marker;}}), error => error === marker);
  assert.throws(() => new engine.RarFile(builder.toBytes(), undefined,
    {get maxHeaderCount() {throw marker;}}), error => error === marker);
  assert.throws(() => new engine.RarFile(builder.toBytes(), undefined,
    {get legacyNameEncoding() {throw marker;}}), error => error === marker);
  archive.free();builder.free();
  const invalid = new engine.RarBuilder({format: 'rar29', store: true});
  invalid.addBytesRaw(new Uint8Array([0x81]), bytes('payload'));
  const data = invalid.toBytes();
  refuses(() => new engine.RarFile(data, undefined, {legacyNameEncoding: 'windows-1252'}), 'INVALID_OPTION');
  refuses(() => engine.RarFile.openVolumes([data], undefined, {legacyNameEncoding: 'windows-1252'}), 'INVALID_OPTION');
  refuses(() => engine.RarFile.openVolumes([bytes('not an archive')]), 'UNSUPPORTED_FORMAT');
  invalid.free();
});
check('encrypted recovery forwards passwords and all reader policy errors', () => {
  const builder = new engine.RarBuilder({store: true, password: 'secret', encryptHeaders: true,
                                        recoveryPercent: 1});
  builder.addBytes('file', bytes('payload'));
  const data = builder.toBytes();
  const repaired = engine.repairDetailed(data, 'secret');
  const output = new engine.RarFile(repaired.data, 'secret');
  output.test();output.free();repaired.free();builder.free();
  const stored = fixture('rar50/stored.rar');
  for (const key of ['maxHeaderCount', 'maxHeaderBytes', 'maxMemberOutputBytes',
                    'maxTotalOutputBytes', 'maxReaderWorkspaceBytes',
                    'rar50DictionarySizeLimit', 'rar50BufferedDecodeLimit'])
    refuses(() => new engine.RarFile(stored, undefined, {[key]: 'bad'}), 'INVALID_OPTION');
  const archive = new engine.RarFile(stored);
  for (const run of [() => archive.read(archive.names()[0], 1), () => archive.readAt(0, 1),
                     () => archive.test(1), () => archive.readComment(1),
                     () => engine.repair(stored, 1), () => engine.repairDetailed(stored, 1),
                     () => engine.RarFile.openVolumes([stored], 1)])
    refuses(run, 'INVALID_OPTION');
  archive.free();
});
check('option getters and per-method reader refusals preserve errors', () => {
  const marker = new Error('property getter failed');
  for (const key of ['format', 'compression', 'store', 'solid', 'password', 'encryptHeaders',
                    'comment', 'recoveryPercent', 'volumeSize', 'maxMemoryBytes'])
    assert.throws(() => new engine.RarBuilder({get [key]() {throw marker;}}), error => error === marker);
  const builder = new engine.RarBuilder({store: true});
  for (const method of ['addBytes', 'addBytesRaw']) {
    const name = method === 'addBytes' ? 'file' : bytes('file');
    for (const key of ['mtime', 'mode'])
      refuses(() => builder[method](name, bytes('payload'), {[key]: 'bad'}), 'INVALID_OPTION');
  }
  builder.free();
  const data = fixture('rar50/stored.rar');
  const archive = new engine.RarFile(data);
  const bad = {maxMemberOutputBytes: 'bad'};
  for (const run of [() => archive.read(archive.names()[0], undefined, bad),
                     () => archive.readAt(0, undefined, bad), () => archive.test(undefined, bad),
                     () => archive.readComment(undefined, bad),
                     () => engine.RarFile.openVolumes([data], undefined, bad)])
    refuses(run, 'INVALID_OPTION');
  const corruptBuilder = new engine.RarBuilder({store: true});
  const payload = bytes('unique checksum payload!');
  corruptBuilder.addBytes('file', payload);
  const wire = corruptBuilder.toBytes();
  const original = new engine.RarFile(wire);
  assert.deepEqual(original.readAt(0), payload);original.free();
  const offset = Buffer.from(wire).indexOf(Buffer.from(payload));
  assert.ok(offset >= 0);
  assert.equal(Buffer.from(wire).lastIndexOf(Buffer.from(payload)), offset);
  wire[offset] ^= 1;
  const corrupt = new engine.RarFile(wire);
  refuses(() => corrupt.readAt(0), 'CHECKSUM_MISMATCH');corrupt.free();corruptBuilder.free();
  const commented = new engine.RarFile(fixture('rar50/with_comment.rar'));
  refuses(() => commented.readComment(undefined, {maxMemberOutputBytes: 0}), 'RESOURCE_LIMIT');
  commented.free();archive.free();
  const legacy = new engine.RarBuilder({format: 'rar14', store: true, solid: true});
  legacy.addBytes('file', bytes('payload'));
  refuses(() => legacy.toBytes(), 'UNSUPPORTED_FEATURE');
  refuses(() => legacy.toVolumes(), 'INVALID_OPTION');legacy.free();
});
if (process.env.RARS_WASM_REQUIRE_TEST_EXPORTS) assert.equal(typeof engine.__testErrorRecords, 'function');
if (engine.__testErrorRecords) check('private error conversion preserves exact counts and nested contexts', () => {
  const errors = engine.__testErrorRecords();
  assert.equal(errors.length, 14);
  for (const error of errors.slice(0, 12)) assert.equal(error.code, 'RESOURCE_LIMIT');
  for (const error of errors.slice(12)) assert.equal(error.code, 'IO');
  for (const error of errors) {
    assert.ok(error instanceof Error);
    assert.deepEqual(error.details.contexts, [
      {kind: 'volume', number: 3},
      {kind: 'archiveOffset', offset: '4294967295'},
      {kind: 'entry', nameBytes: [255, 0, 1], operation: 'reading'},
    ]);
  }
  for (const index of [0, 2, 3, 4, 5, 6]) {
    assert.equal(errors[index].details.limitBytes, '9007199254740993');
    assert.equal(errors[index].details.requiredBytes, '18446744073709551615');
    assert.equal(errors[index].details.usedBytes, '17');
  }
  assert.equal(errors[1].details.dictionaryBytes, '17');
  for (const index of [1, 7, 8, 9, 10]) {
    assert.equal(errors[index].details.limitBytes, '9007199254740993');
    assert.equal(errors[index].details.requiredBytes, '18446744073709551615');
  }
  assert.equal(errors[11].details.limitHeaders, '9007199254740993');
  assert.equal(errors[11].details.requiredHeaders, '18446744073709551615');
  assert.equal(errors[12].details.ioKind, 'PermissionDenied');
  assert.equal(errors[13].details.ioKind, 'BrokenPipe');
});
console.log(`${passed} engine groups passed`);
if (process.env.RARS_WASM_PROFILE_HELPER) {
  const {profile} = require(path.resolve(process.env.RARS_WASM_PROFILE_HELPER));
  console.log(`profile records: ${profile(engine.__coverage_exports, process.env.RARS_WASM_PROFILE_OUT)}`);
}
