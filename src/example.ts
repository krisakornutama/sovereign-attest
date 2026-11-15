/**
 * End-to-end demo against the real `sovereign-vault`:
 * key inside the vault → two chained receipts → tamper is rejected → anchored.
 *
 * Run with `npm run example`.
 */
import { MemoryAnchorLog, MemoryBlobStore, Vault } from 'sovereign-vault';
import { Attest, AttestError, sha256Hex } from './index.js';

const masterKey = new Uint8Array(32).fill(7);
const store = new MemoryBlobStore();
const vault = await Vault.open({ store, masterKey });
const attest = await Attest.open({ vault, keyId: 'release' });

console.log('signing key:', attest.keyId, attest.publicKey.split('\n')[1].slice(0, 16) + '…');
console.log('key lives in the vault at attest/keys/release.json (AES-256-GCM at rest)');

const artifact = new TextEncoder().encode('sovereign-os release 1.3.10');
const built = await attest.record({
  action: 'artifact.built',
  actor: 'ci',
  artifact: { name: 'sovereign-os-1.3.10.exe', bytes: artifact },
  meta: { pipeline: 'release' },
  storeArtifact: true,
});
const shipped = await attest.record({
  action: 'artifact.shipped',
  actor: 'release-bot',
  artifact: { name: 'sovereign-os-1.3.10.exe', bytes: artifact },
  meta: { tag: 'v1.3.10' },
});

console.log('receipt 1:', built.id.slice(0, 16), built.body.action);
console.log(
  'receipt 2:',
  shipped.id.slice(0, 16),
  shipped.body.action,
  '← prev',
  built.id.slice(0, 16)
);

const digest = sha256Hex(artifact);
const chain = await attest.provenance(digest);
console.log('provenance:', chain.receipts.map((receipt) => receipt.body.action).join(' → '));

// A receipt fetched from disk that someone edited no longer verifies.
const tampered = {
  ...built,
  body: { ...built.body, action: 'artifact.built-but-different' },
};
try {
  attest.verify(tampered);
  console.log('UNEXPECTED: tampered receipt verified');
} catch (error) {
  const code = error instanceof AttestError ? error.code : 'unknown';
  console.log('tampered receipt rejected:', code);
}

// Receipts, heads and keys are all index entries, so the vault GC leaves them alone.
const pruned = await vault.pruneOrphans();
console.log('pruneOrphans removed:', pruned.paths.length, 'paths');

// Anchor the vault root: rolling the store back (or swapping the key) now fails.
const anchors = new MemoryAnchorLog();
await attest.anchor(anchors);
const check = await attest.checkAnchor(anchors);
console.log('anchored root:', (check as { root: string }).root.slice(0, 16), '…');
