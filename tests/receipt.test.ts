import { describe, expect, it } from 'vitest';
import { createSigningKey, signBytes } from '../src/keys.js';
import {
  openReceipt,
  receiptId,
  receiptPayload,
  sealReceipt,
  type Receipt,
} from '../src/receipt.js';
import { canonicalJson } from '../src/canonical.js';
import { AttestError } from '../src/errors.js';

const key = createSigningKey('release', 1_700_000_000_000);
const digest = 'a'.repeat(64);

function makeReceipt(overrides: Partial<Parameters<typeof sealReceipt>[1]> = {}): Receipt {
  return sealReceipt(key, {
    action: 'artifact.built',
    actor: 'ci',
    artifact: { name: 'app.exe', sha256: digest, size: 12 },
    at: 1_700_000_000_000,
    ...overrides,
  });
}

describe('sealReceipt', () => {
  it('binds id, key and signature to the canonical body', () => {
    const receipt = makeReceipt();
    expect(receipt.id).toBe(receiptId(receipt.body));
    expect(receipt.keyId).toBe('release');
    expect(receipt.body.prev).toBeNull();
    expect(receiptPayload(receipt.body)).toEqual(
      new TextEncoder().encode(canonicalJson(receipt.body))
    );
    expect(openReceipt(receipt, { publicKey: key.publicKey })).toEqual(receipt.body);
  });

  it('normalises fields a verifier would reject (trim, meta, optional size)', () => {
    const receipt = makeReceipt({
      action: '  artifact.built  ',
      artifact: { name: ' app.exe ', sha256: digest },
      meta: {},
    });
    expect(receipt.body.action).toBe('artifact.built');
    expect(receipt.body.artifact.name).toBe('app.exe');
    expect(receipt.body.artifact.size).toBeUndefined();
    expect(receipt.body.meta).toBeUndefined();
  });

  it('rejects malformed input before signing', () => {
    expect(() => makeReceipt({ action: '   ' })).toThrow(/action/);
    expect(() => makeReceipt({ actor: 'x'.repeat(201) })).toThrow(/at most/);
    expect(() => makeReceipt({ artifact: { name: 'x', sha256: 'nope' } })).toThrow(/SHA-256/);
    expect(() => makeReceipt({ artifact: { name: 'x', sha256: digest, size: -1 } })).toThrow(
      /size/
    );
    expect(() => makeReceipt({ at: 1.5 })).toThrow(/non-negative integer/);
    expect(() => makeReceipt({ prev: 'abc' })).toThrow(/prev/);
    expect(() => makeReceipt({ meta: { '': 'v' } })).toThrow(/meta keys/);
    expect(() => makeReceipt({ meta: { k: 1 as unknown as string } })).toThrow(/meta.k/);
    expect(() => makeReceipt({ meta: 'x' as unknown as Record<string, string> })).toThrow(/object/);
    expect(() =>
      makeReceipt({ artifact: null as unknown as { name: string; sha256: string } })
    ).toThrow(/artifact is required/);
  });
});

describe('openReceipt', () => {
  it('detects an edited body', () => {
    const receipt = makeReceipt();
    const edited = { ...receipt, body: { ...receipt.body, actor: 'someone-else' } };
    expect(() => openReceipt(edited, { publicKey: key.publicKey })).toThrow(
      /does not hash its own body/
    );
  });

  it('detects a body that keeps its id but loses its signature', () => {
    const receipt = makeReceipt();
    const other = createSigningKey('other');
    const forged = {
      ...receipt,
      sig: signBytes(other.privateKey, receiptPayload(receipt.body)),
    };
    expect(() => openReceipt(forged, { publicKey: key.publicKey })).toThrow(/signature/);
  });

  it('refuses to verify against the wrong key', () => {
    const receipt = makeReceipt();
    const other = createSigningKey('other');
    expect(() => openReceipt(receipt, { publicKey: other.publicKey })).toThrow(
      /expected public key/
    );
  });

  it('needs the key to be pinned by label when a key set is supplied', () => {
    const receipt = makeReceipt();
    expect(() => openReceipt(receipt, { trustedKeys: { release: key.publicKey } })).not.toThrow();
    expect(() => openReceipt(receipt, { trustedKeys: {} })).toThrow(AttestError);
    const other = createSigningKey('release');
    expect(() => openReceipt(receipt, { trustedKeys: { release: other.publicKey } })).toThrow(
      /not the pinned public key/
    );
  });

  it('rejects data that is not a receipt at all', () => {
    for (const junk of [null, 42, [], {}, { v: 2, id: 'x' }, { v: 1, id: 'x', body: {} }]) {
      expect(() => openReceipt(junk, { publicKey: key.publicKey })).toThrow(AttestError);
    }
  });

  it('reports an unknown key label with its own error code', () => {
    const receipt = makeReceipt();
    try {
      openReceipt(receipt, { trustedKeys: { 'other-label': key.publicKey } });
      expect.unreachable();
    } catch (error) {
      expect((error as AttestError).code).toBe('unknown-key');
    }
  });
});
