import { mkdtemp, rm, cp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  FileBlobStore,
  MemoryAnchorLog,
  MemoryBlobStore,
  Vault,
  VaultRollbackError,
} from 'sovereign-vault';
import { Attest, sha256Hex, utf8, type Receipt } from '../src/index.js';

const MASTER_KEY = new Uint8Array(32).fill(9);
const BYTES = utf8('release artifact');
const DIGEST = sha256Hex(BYTES);

const dirs: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sovereign-attest-'));
  dirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (dirs.length > 0) {
    await rm(dirs.pop()!, { recursive: true, force: true });
  }
});

async function recordOne(attest: Attest, action = 'artifact.built'): Promise<Receipt> {
  return attest.record({
    action,
    actor: 'ci',
    artifact: { name: 'app.exe', bytes: BYTES },
    storeArtifact: true,
  });
}

describe('keys and receipts at rest', () => {
  it('stores the private key only inside encrypted vault objects', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault, keyId: 'release' });
    await recordOne(attest);

    const blobs: Uint8Array[] = [];
    for (const path of await store.list('')) {
      const bytes = await store.read(path);
      if (bytes) blobs.push(bytes);
    }
    const raw = Buffer.concat(blobs.map((bytes) => Buffer.from(bytes))).toString('latin1');
    expect(raw).not.toContain('BEGIN PRIVATE KEY');
    expect(raw).not.toContain('artifact.built');
    expect(raw).not.toContain('app.exe');
  });

  it('survives reopening the vault from the same files', async () => {
    const dir = await tempDir();
    const first = await Vault.open({ store: new FileBlobStore(dir), masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault: first, keyId: 'release' });
    const before = await recordOne(attest);
    const rootBefore = await first.root();

    const reopened = await Vault.open({ store: new FileBlobStore(dir), masterKey: MASTER_KEY });
    const again = await Attest.open({ vault: reopened, keyId: 'release' });
    expect(again.publicKey).toBe(attest.publicKey);
    expect(await reopened.root()).toBe(rootBefore);

    const chain = await again.provenance(DIGEST);
    expect(chain.receipts.map((receipt) => receipt.id)).toEqual([before.id]);
    expect(await reopened.get(`attest/artifacts/${DIGEST}`)).toEqual(BYTES);

    // The same key keeps working for new claims after the restart.
    const after = await recordOne(again, 'artifact.shipped');
    expect(after.body.prev).toBe(before.id);
  });
});

describe('anchoring', () => {
  it('anchors the root that covers keys and receipts, and detects a rollback', async () => {
    const dir = await tempDir();
    const anchors = new MemoryAnchorLog();
    const vault = await Vault.open({ store: new FileBlobStore(dir), masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault, keyId: 'release' });

    await recordOne(attest);
    const anchored = await attest.anchor(anchors);
    expect(anchored.root).toBe(await vault.root());

    const backup = await tempDir();
    await cp(dir, backup, { recursive: true });

    await recordOne(attest, 'artifact.shipped');
    const rolled = await attest.anchor(anchors);
    expect(rolled.root).not.toBe(anchored.root);

    // Someone restores yesterday's store: the anchor now disagrees with the root.
    await rm(dir, { recursive: true, force: true });
    await cp(backup, dir, { recursive: true });

    const restored = await Vault.open({ store: new FileBlobStore(dir), masterKey: MASTER_KEY });
    const restoredAttest = await Attest.open({ vault: restored, keyId: 'release' });
    await expect(restoredAttest.checkAnchor(anchors)).rejects.toBeInstanceOf(VaultRollbackError);
    await expect(restoredAttest.checkAnchor(anchors, rolled.root)).rejects.toBeInstanceOf(
      VaultRollbackError
    );
    // The pinned root of the rolled-back state still matches: pinning is the caller's policy.
    await expect(
      restoredAttest.checkAnchor(new MemoryAnchorLog(), anchored.root)
    ).resolves.toBeTruthy();
  });
});

describe('garbage collection', () => {
  it('never prunes keys, receipts or heads, because the index references them', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault, keyId: 'release' });
    await recordOne(attest);
    await recordOne(attest, 'artifact.shipped');

    const report = await vault.pruneOrphans({ dryRun: true });
    expect(report.paths).toEqual([]);
    expect(await vault.pruneOrphans()).toEqual({ paths: [], bytes: 0 });
    expect((await attest.provenance(DIGEST)).receipts).toHaveLength(2);
  });

  it('removes a blob left behind by a crash, and the attest data still works', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault, keyId: 'release' });
    await recordOne(attest);

    // A write that never reached the index, exactly what putStream leaves on a crash.
    const orphan = `objects/${'d'.repeat(64)}`;
    await store.write(orphan, utf8('sealed bytes nobody points at'));

    const dry = await vault.pruneOrphans({ dryRun: true });
    expect(dry.paths).toEqual([orphan]);
    expect(await store.read(orphan)).not.toBeNull();

    const real = await vault.pruneOrphans();
    expect(real.paths).toEqual([orphan]);
    expect(await store.read(orphan)).toBeNull();

    expect((await attest.provenance(DIGEST)).receipts).toHaveLength(1);
    const next = await recordOne(attest, 'artifact.shipped');
    expect(next.body.prev).not.toBeNull();
  });

  it('creates a fresh key when the store has none, so recovery never blocks', async () => {
    const first = await Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY });
    const attest = await Attest.open({ vault: first, keyId: 'release' });

    const fresh = await Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY });
    const reopened = await Attest.open({ vault: fresh, keyId: 'release' });
    expect(reopened.publicKey).not.toBe(attest.publicKey);
    expect((await reopened.provenance(DIGEST)).receipts).toEqual([]);
  });
});
