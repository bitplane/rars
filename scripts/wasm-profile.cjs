const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { inflateSync } = require('node:zlib');
const { writeFileSync } = require('node:fs');
function profile(exports, output) {
  const memory = Buffer.from(exports.memory.buffer);
  const start = name => exports[`__start___llvm_prf_${name}`].value;
  const stop = name => exports[`__stop___llvm_prf_${name}`].value;
  const names = new Map();
  let cursor = start('names');
  const readVint = () => {
    let value = 0, shift = 0, byte;
    do { byte = memory[cursor++]; value += (byte & 127) * 2 ** shift; shift += 7; } while(byte & 128);
    return value;
  };
  while(cursor < stop('names')) {
    const size = readVint(), compressed = readVint();
    const data = compressed ? inflateSync(memory.subarray(cursor, cursor + compressed)) : memory.subarray(cursor, cursor + size);
    cursor += compressed || size;
    assert.equal(data.length, size);
    for (const name of data.toString().split('\x01')) {
      const hash = createHash('md5').update(name).digest().readBigUInt64LE();
      names.set(hash.toString(), name);
    }
  }
  // LLVM 23's wasm32 profiling data layout, validated by the two-branch probe.
  assert.equal((stop('data') - start('data')) % 56, 0);
  let text = '', records = 0;
  for(let pos = start('data'); pos < stop('data'); pos += 56) {
    const name = names.get(memory.readBigUInt64LE(pos).toString());
    assert.notEqual(name, undefined, `unknown profiling name at ${pos}`);
    const hash = memory.readBigUInt64LE(pos + 8);
    const counters = pos + memory.readInt32LE(pos + 16);
    const count = memory.readUInt32LE(pos + 36);
    assert.ok(counters >= start('cnts') && counters + count * 8 <= stop('cnts'));
    text += `${name}\n${hash}\n${count}\n`;
    for(let index = 0; index < count; index++) text += `${memory.readBigUInt64LE(counters + index * 8)}\n`;
    text += '\n';records++;
  }
  writeFileSync(output, text);
  return records;
}
module.exports = {profile};
