import { AttestError } from './errors.js';
import { canonicalJson, sha256Hex, utf8 } from './canonical.js';
import { publicKeyMatches, signBytes, verifyBytes, type SigningKey } from './keys.js';

export const RECEIPT_VERSION = 1 as const;

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/** What the receipt is about: a named artifact identified by its content digest. */
export interface ArtifactRef {
  readonly name: string;
  /** Hex SHA-256 of the artifact bytes. */
  readonly sha256: string;
  readonly size?: number;
}

/** The signed claim. `prev` links a receipt to the previous one for the same artifact. */
export interface ReceiptBody {
  readonly v: typeof RECEIPT_VERSION;
  readonly action: string;
  readonly actor: string;
  readonly artifact: ArtifactRef;
  /** Unix epoch milliseconds. */
  readonly at: number;
  /** Receipt id of the previous claim about this artifact, or null for the first. */
  readonly prev: string | null;
  readonly meta?: Readonly<Record<string, string | number>>;
}

/** Body plus the signature and the key that can check it, self-contained for offline audit. */
export interface Receipt {
  readonly v: typeof RECEIPT_VERSION;
  /** SHA-256 of the canonical body: also the lookup key inside the vault. */
  readonly id: string;
  readonly keyId: string;
  readonly publicKey: string;
  readonly body: ReceiptBody;
  readonly sig: string;
}

export type ReceiptTrust =
  | { readonly publicKey: string }
  | { readonly trustedKeys: Readonly<Record<string, string | undefined>> };

function assertText(value: unknown, field: string, max: number): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new AttestError('invalid-receipt', `receipt ${field} must be a non-empty string`);
  }
  const trimmed = value.trim();
  if (trimmed.length > max) {
    throw new AttestError('invalid-receipt', `receipt ${field} must be at most ${max} characters`);
  }
  return trimmed;
}

export function assertSha256(value: unknown, field = 'artifact.sha256'): string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new AttestError('invalid-subject', `${field} must be a lowercase hex SHA-256 digest`);
  }
  return value;
}

function normaliseMeta(meta: unknown): Record<string, string | number> | undefined {
  if (meta === undefined) return undefined;
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) {
    throw new AttestError(
      'invalid-receipt',
      'receipt meta must be an object of strings or numbers'
    );
  }
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(meta as Record<string, unknown>)) {
    // ตัวเลขมีไว้เก็บเวลาที่มีผล (เช่น revokedAt) — canonical รองรับ number อยู่แล้ว
    if (typeof value !== 'string' && !(typeof value === 'number' && Number.isFinite(value))) {
      throw new AttestError(
        'invalid-receipt',
        `receipt meta.${key} must be a string or a finite number`
      );
    }
    if (key.length === 0 || key.length > 64) {
      throw new AttestError('invalid-receipt', 'receipt meta keys must be 1-64 characters');
    }
    out[key] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Validates and normalises a caller-supplied claim. Throws on anything a verifier would reject. */
export function normaliseBody(input: {
  readonly action: string;
  readonly actor: string;
  readonly artifact: ArtifactRef;
  readonly at: number;
  readonly prev?: string | null;
  readonly meta?: Readonly<Record<string, string | number>>;
}): ReceiptBody {
  // Callers can hand us untrusted JSON, so the type is narrower than reality.
  const artifact = input.artifact as ArtifactRef | null | undefined;
  if (typeof artifact !== 'object' || artifact === null) {
    throw new AttestError('invalid-receipt', 'receipt artifact is required');
  }
  const size = artifact.size;
  if (size !== undefined && (!Number.isInteger(size) || size < 0)) {
    throw new AttestError('invalid-receipt', 'artifact.size must be a non-negative integer');
  }
  const at = input.at;
  if (!Number.isInteger(at) || at < 0) {
    throw new AttestError('invalid-receipt', 'receipt at must be a non-negative integer');
  }
  const prev = input.prev ?? null;
  if (prev !== null && !SHA256_PATTERN.test(prev)) {
    throw new AttestError('invalid-receipt', 'receipt prev must be a receipt id or null');
  }
  const meta = normaliseMeta(input.meta);
  const body: ReceiptBody = {
    v: RECEIPT_VERSION,
    action: assertText(input.action, 'action', 200),
    actor: assertText(input.actor, 'actor', 200),
    artifact: {
      name: assertText(artifact.name, 'artifact.name', 256),
      sha256: assertSha256(artifact.sha256),
      ...(size === undefined ? {} : { size }),
    },
    at,
    prev,
    ...(meta === undefined ? {} : { meta }),
  };
  return body;
}

export function receiptId(body: ReceiptBody): string {
  return sha256Hex(canonicalJson(body));
}

export function receiptPayload(body: ReceiptBody): Uint8Array {
  return utf8(canonicalJson(body));
}

/** Signs a validated body. The id doubles as the signature's fingerprint and the vault path. */
export function sealReceipt(key: SigningKey, input: Parameters<typeof normaliseBody>[0]): Receipt {
  const body = normaliseBody(input);
  return {
    v: RECEIPT_VERSION,
    id: receiptId(body),
    keyId: key.keyId,
    publicKey: key.publicKey,
    body,
    sig: signBytes(key.privateKey, receiptPayload(body)),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Checks a receipt from disk or the wire: shape, id, key identity and signature.
 * Returns the signed body on success; throws {@link AttestError} otherwise.
 */
export function openReceipt(receipt: unknown, trust: ReceiptTrust): ReceiptBody {
  if (
    !isRecord(receipt) ||
    receipt.v !== RECEIPT_VERSION ||
    typeof receipt.id !== 'string' ||
    typeof receipt.keyId !== 'string' ||
    typeof receipt.publicKey !== 'string' ||
    typeof receipt.sig !== 'string' ||
    !isRecord(receipt.body)
  ) {
    throw new AttestError('invalid-receipt', 'receipt does not have the expected shape');
  }

  const body = normaliseBody(receipt.body as unknown as Parameters<typeof normaliseBody>[0]);
  const expectedId = receiptId(body);
  if (expectedId !== receipt.id) {
    throw new AttestError(
      'invalid-receipt',
      `receipt id ${receipt.id} does not hash its own body (${expectedId})`
    );
  }

  if ('trustedKeys' in trust) {
    const pinned = trust.trustedKeys[receipt.keyId];
    if (pinned === undefined) {
      throw new AttestError(
        'unknown-key',
        `receipt was signed by unconfigured key "${receipt.keyId}"`
      );
    }
    if (!publicKeyMatches(pinned, receipt.publicKey)) {
      throw new AttestError(
        'unknown-key',
        `receipt key "${receipt.keyId}" is not the pinned public key`
      );
    }
  } else if (!publicKeyMatches(trust.publicKey, receipt.publicKey)) {
    throw new AttestError('unknown-key', 'receipt was not signed by the expected public key');
  }

  if (!verifyBytes(receipt.publicKey, receiptPayload(body), receipt.sig)) {
    throw new AttestError('bad-signature', `receipt ${receipt.id} fails its signature check`);
  }
  return body;
}

export function isReceipt(value: unknown): value is Receipt {
  return isRecord(value) && value.v === RECEIPT_VERSION && typeof value.id === 'string';
}
