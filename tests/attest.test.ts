import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault } from 'sovereign-vault';
import {
  Attest,
  AttestError,
  createSigningKey,
  idOf,
  loadReceipt,
  loadSigningKey,
  saveHead,
  saveReceipt,
  sealReceipt,
  sha256Hex,
  signedBy,
  utf8,
  keyPath,
  type Receipt,
} from '../src/index.js';

const MASTER_KEY = new Uint8Array(32).fill(3);
const BYTES = utf8('sovereign-os release 1.3.10');

async function openVault() {
  const store = new MemoryBlobStore();
  const vault = await Vault.open({ store, masterKey: MASTER_KEY });
  return { store, vault };
}

async function openAttest(keyId = 'release') {
  const { store, vault } = await openVault();
  let clock = 1_700_000_000_000;
  const attest = await Attest.open({ vault, keyId, now: () => (clock += 1000) });
  return { store, vault, attest, tick: () => (clock += 1000) };
}

describe('Attest.open', () => {
  it('creates the signing key inside the vault on first open and reuses it after', async () => {
    const { vault, attest } = await openAttest();
    expect(attest.keyId).toBe('release');
    expect(attest.publicKey).toContain('BEGIN PUBLIC KEY');

    const reopened = await Attest.open({ vault, keyId: 'release' });
    expect(reopened.publicKey).toBe(attest.publicKey);

    const stored = await loadSigningKey(vault, 'release');
    expect(stored?.publicKey).toBe(attest.publicKey);
    expect(stored?.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('keeps separate keys per label', async () => {
    const { vault, attest } = await openAttest('release');
    const second = await Attest.open({ vault, keyId: 'audit' });
    expect(second.publicKey).not.toBe(attest.publicKey);
    expect(second.trustedKeys()).toEqual({ audit: second.publicKey });
  });

  it('refuses a key blob it cannot read as a key', async () => {
    const { vault } = await openVault();
    await vault.put(keyPath('release'), utf8('{"keyId":"release"}'));
    await expect(Attest.open({ vault, keyId: 'release' })).rejects.toThrow(/not a signing key/);
  });

  it('refuses a key blob whose halves do not belong together', async () => {
    const { vault } = await openVault();
    const ours = createSigningKey('release');
    const other = createSigningKey('release');
    await vault.put(
      keyPath('release'),
      utf8(JSON.stringify({ ...ours, publicKey: other.publicKey }))
    );
    await expect(Attest.open({ vault, keyId: 'release' })).rejects.toThrow(/probe/);
  });

  it('rejects something that is not a vault', async () => {
    await expect(Attest.open({ vault: {} as never })).rejects.toThrow(/needs a vault/);
  });
});

describe('Attest.record', () => {
  it('hashes and sizes artifact bytes, and stores them when asked', async () => {
    const { vault, attest } = await openAttest();
    const receipt = await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
      meta: { pipeline: 'release' },
      storeArtifact: true,
    });

    expect(receipt.body.artifact.sha256).toBe(sha256Hex(BYTES));
    expect(receipt.body.artifact.size).toBe(BYTES.length);
    expect(receipt.body.prev).toBeNull();
    expect(await vault.get(`attest/artifacts/${sha256Hex(BYTES)}`)).toEqual(BYTES);
    expect(attest.verify(receipt)).toEqual(receipt.body);
  });

  it('accepts a caller-supplied digest (for artifacts too big to hand over)', async () => {
    const { attest } = await openAttest();
    const digest = sha256Hex(BYTES);
    const receipt = await attest.record({
      action: 'artifact.verified',
      actor: 'auditor',
      artifact: { name: 'app.exe', sha256: digest },
    });
    expect(receipt.body.artifact.sha256).toBe(digest);
    expect(receipt.body.artifact.size).toBeUndefined();
  });

  it('refuses an artifact it cannot identify', async () => {
    const { attest } = await openAttest();
    await expect(
      attest.record({ action: 'a', actor: 'b', artifact: { name: 'x' } as never })
    ).rejects.toThrow(/unidentifiable/);
    await expect(
      attest.record({
        action: 'a',
        actor: 'b',
        artifact: { name: 'x', sha256: sha256Hex(BYTES) },
        storeArtifact: true,
      })
    ).rejects.toThrow(/needs artifact bytes/);
  });

  it('chains each claim to the previous one for the same artifact', async () => {
    const { attest } = await openAttest();
    const first = await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    const second = await attest.record({
      action: 'artifact.shipped',
      actor: 'release-bot',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    expect(second.body.prev).toBe(first.id);
    expect(second.body.at).toBeGreaterThan(first.body.at);
    expect(first.id).toBe(idOf(first.body));
  });

  it('moves the vault root, so an anchor covers the new claim', async () => {
    const { attest } = await openAttest();
    const before = await attest.root();
    await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    expect(await attest.root()).not.toBe(before);
  });
});

describe('Attest.provenance', () => {
  async function twoReceipts() {
    const ctx = await openAttest();
    const first = await ctx.attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    const second = await ctx.attest.record({
      action: 'artifact.shipped',
      actor: 'release-bot',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    return { ...ctx, first, second, digest: sha256Hex(BYTES) };
  }

  it('returns the chain oldest first, with the head', async () => {
    const { attest, first, second, digest } = await twoReceipts();
    const report = await attest.provenance(digest);
    expect(report.receipts.map((receipt) => receipt.id)).toEqual([first.id, second.id]);
    expect(report.head).toBe(second.id);
    expect(report.artifact).toBe(digest);
  });

  it('returns an empty chain for an artifact nobody claimed', async () => {
    const { attest } = await twoReceipts();
    const report = await attest.provenance('b'.repeat(64));
    expect(report).toEqual({ artifact: 'b'.repeat(64), receipts: [], head: null });
  });

  it('reports a head that points at a receipt the vault does not have', async () => {
    const { vault, attest } = await openAttest();
    const digest = sha256Hex(BYTES);
    await saveHead(vault, digest, 'c'.repeat(64));
    await expect(attest.provenance(digest)).rejects.toMatchObject({ code: 'missing-receipt' });
  });

  it('reports a receipt that is about another artifact', async () => {
    const { vault, attest, first } = await twoReceipts();
    const otherDigest = sha256Hex('another artifact');
    await saveHead(vault, otherDigest, first.id);
    await expect(attest.provenance(otherDigest)).rejects.toMatchObject({ code: 'chain-broken' });
  });

  it('rejects a receipt edited on disk', async () => {
    const { vault, attest, first, digest } = await twoReceipts();
    const edited: Receipt = {
      ...first,
      body: { ...first.body, actor: 'someone-else' },
    };
    await saveReceipt(vault, edited);
    await expect(attest.provenance(digest)).rejects.toMatchObject({ code: 'invalid-receipt' });
  });

  it('rejects a receipt signed by a key the caller does not trust', async () => {
    const { vault, attest, digest } = await twoReceipts();
    const rogue = createSigningKey('release');
    const forged = sealReceipt(rogue, {
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', sha256: digest, size: BYTES.length },
      at: 1,
    });
    await saveReceipt(vault, forged);
    await saveHead(vault, digest, forged.id);
    await expect(attest.provenance(digest)).rejects.toMatchObject({ code: 'unknown-key' });
    // ...unless the caller pins that key explicitly.
    const pinned = await attest.provenance(digest, {
      trustedKeys: { release: rogue.publicKey },
    });
    expect(pinned.receipts.at(-1)?.id).toBe(forged.id);
  });

  it('detects a receipt that is signed but no longer stored where the chain expects it', async () => {
    const { vault, attest, first, second, digest } = await twoReceipts();
    expect(await loadReceipt(vault, first.id)).not.toBeNull();
    await saveHead(vault, digest, second.id);
    const report = await attest.provenance(digest);
    expect(report.receipts).toHaveLength(2);
  });
});

describe('receipt helpers', () => {
  it('signedBy compares keys without verifying the signature', async () => {
    const { attest } = await openAttest();
    const receipt = await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    expect(signedBy(receipt, attest.publicKey)).toBe(true);
    expect(signedBy(receipt, createSigningKey('x').publicKey)).toBe(false);
  });

  it('errors carry a stable code for callers that branch on them', async () => {
    const { attest } = await openAttest();
    try {
      await attest.record({ action: '', actor: 'ci', artifact: { name: 'x', sha256: 'bad' } });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AttestError);
      expect((error as AttestError).code).toBe('invalid-subject');
    }
  });
});
