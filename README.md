# sovereign-attest

Signed receipts and artifact provenance for Sovereign OS. Every claim about an artifact — built, signed off, shipped, revoked — becomes an Ed25519-signed receipt, chained to the previous claim for that artifact. The signing key lives inside [`sovereign-vault`](https://github.com/krisakornutama/sovereign-vault): encrypted at rest, covered by the vault root, and never deleted by garbage collection.

No cloud, no account, no network. An auditor verifies offline from the receipts alone.

## Install

```bash
npm install sovereign-attest sovereign-vault
```

Sovereign OS ships it as plain ESM for Node 20+.

## Use

```ts
import { MemoryBlobStore, Vault } from 'sovereign-vault';
import { Attest } from 'sovereign-attest';

const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey });
const attest = await Attest.open({ vault, keyId: 'release' });

const built = await attest.record({
  action: 'artifact.built',
  actor: 'ci',
  artifact: { name: 'sovereign-os-1.3.10.exe', bytes },
  meta: { pipeline: 'release' },
  storeArtifact: true,
});

const shipped = await attest.record({
  action: 'artifact.shipped',
  actor: 'release-bot',
  artifact: { name: 'sovereign-os-1.3.10.exe', bytes },
  meta: { tag: 'v1.3.10' },
});

shipped.body.prev; // built.id — the claim chain for this artifact
await attest.provenance(shipped.body.artifact.sha256); // oldest first, verified
```

Verify anywhere, without the vault or the writer:

```ts
import { openReceipt } from 'sovereign-attest';

const body = openReceipt(receiptFromARegistry, { publicKey: pinnedReleaseKey });
```

## What a receipt is

```json
{
  "v": 1,
  "id": "<sha256 of the canonical body>",
  "keyId": "release",
  "publicKey": "-----BEGIN PUBLIC KEY-----…",
  "body": {
    "v": 1,
    "action": "artifact.shipped",
    "actor": "release-bot",
    "artifact": { "name": "sovereign-os-1.3.10.exe", "sha256": "…", "size": 188327298 },
    "at": 1731400000000,
    "prev": "<id of the previous receipt for this artifact>",
    "meta": { "tag": "v1.3.10" }
  },
  "sig": "<base64 Ed25519 signature over canonical body>"
}
```

- **Canonical body.** Keys sorted, no whitespace, numbers normalised. Signer and verifier hash identical bytes on any platform, so `id` is stable and doubles as the vault path.
- **Chain.** `prev` points at the previous receipt for the same artifact digest. Rewriting history means breaking a signature you do not have the key for.
- **Self-contained.** The receipt carries the public key, so verification needs no vault, no registry and no network — trust comes from pinning that key, not from where the file was found.

## API

| Export                                                              | What it does                                                                                                 |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `Attest.open({ vault, keyId?, now? })`                              | Loads the signing key from the vault or creates and stores it; validates an existing key before use          |
| `attest.record({ action, actor, artifact, meta?, storeArtifact? })` | Signs a claim, chains it to the artifact's previous receipt and stores both receipt and head in the vault    |
| `attest.provenance(sha256, { trustedKeys? })`                       | Walks and verifies the chain, oldest first                                                                   |
| `attest.verify(receipt)`                                            | Verifies one receipt against this writer's key                                                               |
| `attest.anchor(log)` / `attest.checkAnchor(log, expectedRoot?)`     | Anchors the vault root (which covers keys, receipts and heads) into an append-only log, and detects rollback |
| `openReceipt(receipt, trust)`                                       | Standalone verification with `{ publicKey }` or `{ trustedKeys }`                                            |
| `sealReceipt(key, body)` / `receiptId(body)`                        | Sign and predict ids without a vault                                                                         |
| `createSigningKey(keyId)`                                           | Ed25519 pair for cases where the vault is not in the loop                                                    |

## Why the key lives in the vault

| Property          | How the vault gives it                                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Confidentiality   | Key blobs are sealed with AES-256-GCM; a stolen store directory yields no private key                                                  |
| Tamper evidence   | The vault root hashes every entry, so swapping the key blob changes the root the anchor log already recorded                           |
| Durability        | Keys, receipts and heads are index entries: `pruneOrphans()` only removes blobs no entry references, so attest data is never collected |
| Disaster recovery | The key travels with the data it vouches for; restoring the vault restores the ability to keep signing                                 |

Crash safety: a receipt is written before the head pointer. A crash in between leaves an unreferenced receipt — harmless and still verifiable — never a head that points at nothing.

## Limitations (deliberate, milestone 1)

- **One writer per vault.** The vault assumes a single writer; concurrent writers can interleave heads. Multi-writer sequencing is not solved yet.
- **No revocation list.** A receipt can say `action: 'artifact.revoked'` and it chains, but nothing enforces "do not trust receipts before a revocation".
- **No transparency log.** Anchoring covers _a_ vault root; publishing that anchor to a witness the attacker cannot rewrite is an operator task (the vault anchor log can already point anywhere).
- **Artifacts are optional payload.** `storeArtifact` keeps bytes in the vault for small artifacts; larger ones stay outside and are referenced by digest.
- **No key rotation ceremony.** Open with a new `keyId` and both keys are trusted (`trustedKeys`), but there is no signed rotation statement yet.

## Scripts

```bash
npm run lint && npm run typecheck && npm run format:check
npm run test:coverage   # gate: 90 statements / 80 branches / 90 functions / 90 lines
npm run build
npm run example         # end-to-end demo against the real vault
```

MIT.
