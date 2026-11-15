import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  assertKeyId,
  createSigningKey,
  normalisePublicKey,
  publicKeyFingerprint,
  publicKeyMatches,
  signBytes,
  verifyBytes,
} from '../src/keys.js';
import { utf8 } from '../src/canonical.js';
import { AttestError } from '../src/errors.js';

describe('createSigningKey', () => {
  it('makes an Ed25519 pair usably linked to its label', () => {
    const key = createSigningKey('release', 1000);
    expect(key.keyId).toBe('release');
    expect(key.createdAt).toBe(1000);
    expect(key.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(key.publicKey).toContain('BEGIN PUBLIC KEY');

    const payload = utf8('artifact digest');
    expect(verifyBytes(key.publicKey, payload, signBytes(key.privateKey, payload))).toBe(true);
  });

  it('refuses labels that would be unsafe as vault paths', () => {
    expect(assertKeyId('release-2026.v1')).toBe('release-2026.v1');
    for (const bad of ['', '../escape', 'has space', 'a'.repeat(65), '.hidden']) {
      expect(() => createSigningKey(bad)).toThrow(AttestError);
    }
  });
});

describe('verifyBytes', () => {
  it('rejects a different payload, a different key and junk signatures without throwing', () => {
    const key = createSigningKey('k');
    const other = createSigningKey('other');
    const payload = utf8('payload');
    const sig = signBytes(key.privateKey, payload);

    expect(verifyBytes(key.publicKey, utf8('payload!'), sig)).toBe(false);
    expect(verifyBytes(other.publicKey, payload, sig)).toBe(false);
    expect(verifyBytes(key.publicKey, payload, 'not base64 !!')).toBe(false);
    expect(verifyBytes(key.publicKey, payload, '')).toBe(false);
    expect(
      verifyBytes('-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----', payload, sig)
    ).toBe(false);
  });
});

describe('key validation', () => {
  it('rejects non-Ed25519 and non-PEM material', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPrivate = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const rsaPublic = publicKey.export({ type: 'spki', format: 'pem' }).toString();

    expect(() => signBytes(rsaPrivate, utf8('x'))).toThrow(/ed25519/);
    expect(() => publicKeyFingerprint(rsaPublic)).toThrow(/ed25519/);
    expect(() => signBytes('not a pem', utf8('x'))).toThrow(/PKCS#8/);
    expect(() => publicKeyFingerprint('not a pem')).toThrow(/SPKI/);
  });
});

describe('public key identity', () => {
  it('compares PEMs regardless of line endings and trailing whitespace', () => {
    const key = createSigningKey('k');
    const messy = `\r\n${key.publicKey.replace(/\n/g, '\r\n')}\r\n`;
    expect(publicKeyMatches(key.publicKey, messy)).toBe(true);
    expect(normalisePublicKey(messy)).toBe(normalisePublicKey(key.publicKey));
  });

  it('fails for two different keys and fingerprints them differently', () => {
    const a = createSigningKey('a');
    const b = createSigningKey('b');
    expect(publicKeyMatches(a.publicKey, b.publicKey)).toBe(false);
    expect(publicKeyFingerprint(a.publicKey)).not.toBe(publicKeyFingerprint(b.publicKey));
    expect(publicKeyFingerprint(a.publicKey)).toHaveLength(32);
  });
});
