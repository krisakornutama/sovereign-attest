import { sha256Hex, utf8 } from './canonical.js';
import { AttestError } from './errors.js';
import {
  createSigningKey,
  publicKeyMatches,
  signBytes,
  verifyBytes,
  type SigningKey,
} from './keys.js';
import {
  openReceipt,
  receiptId,
  sealReceipt,
  type Receipt,
  type ReceiptBody,
  type ReceiptTrust,
} from './receipt.js';
import {
  artifactPath,
  loadHead,
  loadReceipt,
  loadSigningKey,
  saveHead,
  saveReceipt,
  saveSigningKey,
  type AnchorLogLike,
  type AttestVault,
} from './store.js';

export interface AttestOptions {
  /** Anything that behaves like `sovereign-vault`'s `Vault`. */
  readonly vault: AttestVault;
  /** Label for the signing key; the key is created on first open and then reused. */
  readonly keyId?: string;
  /** Injectable clock, so tests and replays get stable receipt timestamps. */
  readonly now?: () => number;
}

export type ArtifactInput =
  | { readonly name: string; readonly sha256: string; readonly size?: number }
  | { readonly name: string; readonly bytes: Uint8Array; readonly sha256?: never };

export interface RecordInput {
  readonly action: string;
  readonly actor: string;
  readonly artifact: ArtifactInput;
  readonly meta?: Readonly<Record<string, string>>;
  /** Store the artifact bytes in the vault (content-addressed) alongside the claim. */
  readonly storeArtifact?: boolean;
}

export interface ProvenanceReport {
  /** Artifact the chain is about. */
  readonly artifact: string;
  /** Oldest first; the last entry is the current head of the chain. */
  readonly receipts: readonly Receipt[];
  readonly head: string | null;
}

export interface AnchorReport {
  readonly root: string;
  readonly entry: unknown;
}

const PROBE = utf8('sovereign-attest key probe');

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/**
 * Signs artifact claims with a key kept inside the vault.
 *
 * Why the key lives in the vault: it is encrypted at rest with the vault key,
 * travels with the data it vouches for, is covered by the vault root (so the
 * anchor log detects a swapped key), and is referenced by the index — which is
 * exactly what keeps {@link Vault.pruneOrphans} from ever deleting it.
 */
export class Attest {
  readonly keyId: string;
  readonly publicKey: string;

  private readonly vault: AttestVault;
  private readonly key: SigningKey;
  private readonly clock: () => number;

  private constructor(options: { vault: AttestVault; key: SigningKey; clock: () => number }) {
    this.vault = options.vault;
    this.key = options.key;
    this.clock = options.clock;
    this.keyId = options.key.keyId;
    this.publicKey = options.key.publicKey;
  }

  /**
   * Loads the signing key for `keyId` from the vault, or creates and stores one.
   * An existing key is validated before use: a corrupted or swapped key blob fails
   * here instead of silently producing unverifiable receipts.
   */
  static async open(options: AttestOptions): Promise<Attest> {
    // Runtime guard: JS callers can pass anything, whatever the type says.
    const vault = options.vault as AttestVault | null | undefined;
    if (!vault || typeof vault.get !== 'function' || typeof vault.put !== 'function') {
      throw new AttestError('invalid-key', 'Attest.open needs a vault with get/put');
    }
    const clock = options.now ?? Date.now;
    const keyId = options.keyId ?? 'primary';

    let key = await loadSigningKey(vault, keyId);
    if (!key) {
      key = createSigningKey(keyId, clock());
      await saveSigningKey(vault, key);
    } else {
      const sane = verifyBytes(key.publicKey, PROBE, signBytes(key.privateKey, PROBE));
      if (!sane) {
        throw new AttestError(
          'invalid-key',
          `stored key "${keyId}" cannot sign a probe payload it should verify`
        );
      }
    }
    return new Attest({ vault, key, clock });
  }

  /** Public keys this writer trusts by default (its own), for verifying its receipts. */
  trustedKeys(): Readonly<Record<string, string>> {
    return { [this.keyId]: this.publicKey };
  }

  async root(): Promise<string> {
    return this.vault.root();
  }

  /**
   * Records and signs a claim about an artifact, chaining it to the previous claim
   * for the same artifact digest.
   *
   * The receipt is written before the head pointer: a crash in between leaves an
   * unreferenced receipt (harmless, still verifiable), never a head that points at
   * nothing. Receipts and heads are both index entries, so the vault's GC keeps them.
   */
  async record(input: RecordInput): Promise<Receipt> {
    const { artifact, bytes } = resolveArtifact(input.artifact);

    if (input.storeArtifact === true) {
      if (!bytes) {
        throw new AttestError('invalid-subject', 'storeArtifact needs artifact bytes');
      }
      await this.vault.put(artifactPath(artifact.sha256), bytes);
    }

    const prev = await loadHead(this.vault, artifact.sha256);
    const body = sealReceipt(this.key, {
      action: input.action,
      actor: input.actor,
      artifact,
      at: this.clock(),
      prev,
      meta: input.meta,
    });
    await saveReceipt(this.vault, body);
    await saveHead(this.vault, artifact.sha256, body.id);
    return body;
  }

  /**
   * Walks the receipt chain for an artifact from the current head back to the first
   * claim, verifying every signature and link. Returns oldest first.
   */
  async provenance(
    subject: string,
    options: { readonly trustedKeys?: Readonly<Record<string, string>> } = {}
  ): Promise<ProvenanceReport> {
    const trust: ReceiptTrust = {
      trustedKeys: options.trustedKeys ?? this.trustedKeys(),
    };
    const head = await loadHead(this.vault, subject);
    const chain: Receipt[] = [];
    let next = head;

    // A cycle would need a receipt whose `prev` reproduces its own hash, so the
    // walk terminates by construction; the loop only guards against bad storage.
    while (next !== null) {
      const receipt = await loadReceipt(this.vault, next);
      if (!receipt) {
        throw new AttestError(
          'missing-receipt',
          `chain for ${subject} points at receipt ${next}, which is not in the vault`
        );
      }
      const body = openReceipt(receipt, trust);
      if (body.artifact.sha256 !== subject) {
        throw new AttestError(
          'chain-broken',
          `receipt ${receipt.id} is about ${body.artifact.sha256}, not ${subject}`
        );
      }
      chain.push(receipt);
      next = body.prev;
    }

    return {
      artifact: subject,
      receipts: chain.reverse(),
      head: head,
    };
  }

  /** Verifies a single receipt the way this writer would verify its own. */
  verify(receipt: unknown): ReceiptBody {
    return openReceipt(receipt, { trustedKeys: this.trustedKeys() });
  }

  /**
   * Anchors the vault root (which covers every stored key, receipt and head) into an
   * append-only anchor log. A later rollback of the vault then fails
   * {@link checkAnchor}, including a rewrite that swaps the signing key.
   */
  async anchor(log: AnchorLogLike): Promise<AnchorReport> {
    const entry = await this.vault.anchorNow(log, this.clock());
    return { root: await this.vault.root(), entry };
  }

  async checkAnchor(log: AnchorLogLike, expectedRoot?: string): Promise<unknown> {
    return this.vault.verifyAnchor(log, expectedRoot);
  }
}

function resolveArtifact(input: ArtifactInput): {
  artifact: { name: string; sha256: string; size?: number };
  bytes: Uint8Array | null;
} {
  if (isBytes((input as { bytes?: unknown }).bytes)) {
    const bytes = (input as { bytes: Uint8Array }).bytes;
    return {
      artifact: { name: input.name, sha256: sha256Hex(bytes), size: bytes.length },
      bytes,
    };
  }
  const sha256 = (input as { sha256?: unknown }).sha256;
  const size = (input as { size?: number }).size;
  if (typeof sha256 !== 'string') {
    throw new AttestError(
      'invalid-subject',
      'artifact needs either bytes or a hex sha256; refusing to sign an unidentifiable artifact'
    );
  }
  return {
    artifact: {
      name: input.name,
      sha256,
      ...(size === undefined ? {} : { size }),
    },
    bytes: null,
  };
}

/** Stable id of a body, exported so callers can predict the receipt id before signing. */
export function idOf(body: ReceiptBody): string {
  return receiptId(body);
}

/** True when a receipt belongs to the expected key, without checking the signature. */
export function signedBy(receipt: Receipt, publicKey: string): boolean {
  return publicKeyMatches(receipt.publicKey, publicKey);
}
