import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256Hex, utf8, fromUtf8 } from '../src/canonical.js';
import { AttestError } from '../src/errors.js';

describe('canonicalJson', () => {
  it('sorts object keys at every depth so equal objects hash the same', () => {
    const a = { b: 1, a: { d: [2, 3], c: 'x' } };
    const b = { a: { c: 'x', d: [2, 3] }, b: 1 };
    expect(canonicalJson(a)).toBe('{"a":{"c":"x","d":[2,3]},"b":1}');
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(sha256Hex(canonicalJson(a))).toBe(sha256Hex(canonicalJson(b)));
  });

  it('keeps array order (it is data, not a set)', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('normalises -0 and escapes strings like JSON does', () => {
    expect(canonicalJson({ n: -0, s: 'a"b\n' })).toBe('{"n":0,"s":"a\\"b\\n"}');
  });

  it('rejects what JSON would silently drop or mangle', () => {
    expect(() => canonicalJson({ a: undefined })).toThrow(AttestError);
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(/finite/);
    expect(() => canonicalJson({ a: 1n })).toThrow(/bigint/);
    expect(() => canonicalJson({ a: () => 1 })).toThrow(/function/);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(/cycles/);
  });

  it('allows the same object twice when it is not a cycle', () => {
    const shared = { x: 1 };
    expect(canonicalJson({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });
});

describe('sha256Hex', () => {
  it('matches the known digest of "abc"', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    expect(sha256Hex(utf8('abc'))).toBe(sha256Hex('abc'));
  });

  it('round-trips UTF-8, including Thai text', () => {
    expect(fromUtf8(utf8('หลักฐาน'))).toBe('หลักฐาน');
  });
});
