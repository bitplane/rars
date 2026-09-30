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
check('version and stored round trips expose all metadata getters', () => {
  assert.match(engine.version(), /^\d+\.\d+\.\d+$/);
  for (const format of engine.formats()) {
    const builder = new engine.RarBuilder({format, store: true});
    builder.addBytes('first.txt', bytes('first'), {mtime: 0, mode: 0o640});
    builder.addBytesRaw(bytes('second.txt'), bytes('second'));
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
  assert.deepEqual(result.data, engine.repair(data));
  const archive = new engine.RarFile(result.data);
  archive.test();archive.free();report.free();result.free();
  refuses(() => engine.repair(bytes('not an archive')), 'UNSUPPORTED_FORMAT');
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
    archive.test();archive.free();
    const volumeBuilder = new engine.RarBuilder({format, store: true, volumeSize: 64, maxMemoryBytes: 64n * 1024n * 1024n});
    volumeBuilder.addBytes('file', bytes('payload'.repeat(30)));
    const volumes = engine.RarFile.openVolumes(volumeBuilder.toVolumes(), undefined, {legacyNameEncoding: null});
    volumes.test();volumes.free();volumeBuilder.free();builder.free();
  }
  const builder = new engine.RarBuilder({format: null, store: true});
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
  archive.free();builder.free();
});
console.log(`${passed} engine groups passed`);
if (process.env.RARS_WASM_PROFILE_HELPER) {
  const {profile} = require(path.resolve(process.env.RARS_WASM_PROFILE_HELPER));
  console.log(`profile records: ${profile(engine.__coverage_exports, process.env.RARS_WASM_PROFILE_OUT)}`);
}
