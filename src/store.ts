import { AttestError } from './errors.js';
import { fromUtf8, utf8 } from './canonical.js';
import { assertKeyId, type SigningKey } from './keys.js';
import { isReceipt, type Receipt } from './receipt.js';

/**
 * The slice of `sovereign-vault`'s `Vault` that attest needs. Kept structural and
 * type-only so this package has no runtime dependency on the vault: it works with
 * a vault, and the vault keeps keys encrypted at rest and GC-safe.
 */
export interface AnchorLogLike {
  append(root: string, at: number): Promise<unknown>;
}

export interface AttestVault {
  get(key: string): Promise<Uint8Array>;
  put(key: string, value: Uint8Array): Promise<unknown>;
  root(): Promise<string>;
  anchorNow(anchor: AnchorLogLike, at?: number): Promise<unknown>;
  verifyAnchor(anchor: AnchorLogLike, expectedRoot?: string): Promise<unknown>;
  pruneOrphans(options?: { readonly dryRun?: boolean }): Promise<{
    readonly paths: readonly string[];
    readonly bytes: number;
  }>;
}

export const KEY_PREFIX = 'attest/keys/';
export const RECEIPT_PREFIX = 'attest/receipts/';
export const HEAD_PREFIX = 'attest/heads/';
export const ARTIFACT_PREFIX = 'attest/artifacts/';

const KEY_SUFFIX = '.json';

export function keyPath(keyId: string): string {
  return `${KEY_PREFIX}${assertKeyId(keyId)}${KEY_SUFFIX}`;
}

export function receiptPath(id: string): string {
  if (!/^[0-9a-f]{64}$/.test(id)) {
    throw new AttestError('invalid-receipt', `receipt path needs a hex id, got "${id}"`);
  }
  return `${RECEIPT_PREFIX}${id}.json`;
}

export function headPath(subject: string): string {
  if (!/^[0-9a-f]{64}$/.test(subject)) {
    throw new AttestError('invalid-subject', 'head path needs a hex artifact digest');
  }
  return `${HEAD_PREFIX}${subject}.json`;
}

export function artifactPath(sha256: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256)) {
    throw new AttestError('invalid-subject', 'artifact path needs a hex digest');
  }
  return `${ARTIFACT_PREFIX}${sha256}`;
}

/** The vault throws `not-found` for a missing key; that is the only absence we forgive. */
async function readOptional(vault: AttestVault, path: string): Promise<Uint8Array | null> {
  try {
    return await vault.get(path);
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

function isNotFound(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'not-found'
  );
}

function parseJson(bytes: Uint8Array, path: string): unknown {
  try {
    return JSON.parse(fromUtf8(bytes));
  } catch (error) {
    throw new AttestError('invalid-receipt', `stored attest data at ${path} is not JSON`, {
      cause: error,
    });
  }
}

export async function loadSigningKey(
  vault: AttestVault,
  keyId: string
): Promise<SigningKey | null> {
  const path = keyPath(keyId);
  const bytes = await readOptional(vault, path);
  if (!bytes) return null;
  const stored = parseJson(bytes, path) as Partial<SigningKey> | null;
  if (
    typeof stored !== 'object' ||
    stored === null ||
    stored.keyId !== keyId ||
    typeof stored.privateKey !== 'string' ||
    typeof stored.publicKey !== 'string' ||
    typeof stored.createdAt !== 'number'
  ) {
    throw new AttestError('invalid-key', `stored key at ${path} is not a signing key`);
  }
  return {
    keyId,
    privateKey: stored.privateKey,
    publicKey: stored.publicKey,
    createdAt: stored.createdAt,
  };
}

export async function saveSigningKey(vault: AttestVault, key: SigningKey): Promise<void> {
  await vault.put(keyPath(key.keyId), utf8(JSON.stringify(key)));
}

export async function loadReceipt(vault: AttestVault, id: string): Promise<Receipt | null> {
  const path = receiptPath(id);
  const bytes = await readOptional(vault, path);
  if (!bytes) return null;
  const stored = parseJson(bytes, path);
  if (!isReceipt(stored)) {
    throw new AttestError('invalid-receipt', `stored receipt at ${path} has an unknown shape`);
  }
  return stored;
}

export async function saveReceipt(vault: AttestVault, receipt: Receipt): Promise<void> {
  await vault.put(receiptPath(receipt.id), utf8(JSON.stringify(receipt)));
}

export async function loadHead(vault: AttestVault, subject: string): Promise<string | null> {
  const bytes = await readOptional(vault, headPath(subject));
  if (!bytes) return null;
  const stored = parseJson(bytes, headPath(subject)) as { head?: unknown } | null;
  const head = stored?.head;
  if (typeof head !== 'string' || !/^[0-9a-f]{64}$/.test(head)) {
    throw new AttestError('invalid-receipt', `stored head for ${subject} is not a receipt id`);
  }
  return head;
}

export async function saveHead(vault: AttestVault, subject: string, id: string): Promise<void> {
  await vault.put(headPath(subject), utf8(JSON.stringify({ head: id })));
}
