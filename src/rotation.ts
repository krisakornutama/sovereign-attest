import { canonicalJson, utf8 } from './canonical.js';
import { AttestError } from './errors.js';
import { publicKeyMatches, signBytes, verifyBytes, type SigningKey } from './keys.js';

export const ROTATION_VERSION = 1 as const;

export interface KeyRef {
  readonly keyId: string;
  readonly publicKey: string;
}

/**
 * "กุญแจเก่ายอมรับกุญแจใหม่ตั้งแต่เวลานี้" — ขาดใบนี้ การเปลี่ยนกุญแจจะถูกมองว่าเป็น
 * ผู้บุกรุกเซ็น receipt แทน (ผู้ตรวจไม่รู้ว่าการเปลี่ยนเป็นเจตนาของเจ้าของ)
 */
export interface RotationStatement {
  readonly v: typeof ROTATION_VERSION;
  readonly from: KeyRef;
  readonly to: KeyRef;
  /** Unix epoch milliseconds; receipts at or after this time may be signed by `to`. */
  readonly at: number;
  /** Ed25519 signature by the old key over the canonical statement. */
  readonly sig: string;
}

function statementBody(from: KeyRef, to: KeyRef, at: number) {
  if (!Number.isInteger(at) || at < 0) {
    throw new AttestError('invalid-key', 'rotation time must be a non-negative integer');
  }
  if (from.keyId === to.keyId) {
    throw new AttestError('invalid-key', 'a key cannot rotate to itself');
  }
  if (publicKeyMatches(from.publicKey, to.publicKey)) {
    throw new AttestError('invalid-key', 'rotation must name a different public key');
  }
  return {
    v: ROTATION_VERSION,
    from: { keyId: from.keyId, publicKey: from.publicKey },
    to: { keyId: to.keyId, publicKey: to.publicKey },
    at,
  };
}

export function rotationPayload(from: KeyRef, to: KeyRef, at: number): Uint8Array {
  return utf8(canonicalJson(statementBody(from, to, at)));
}

/** Old key endorses the new one. Only the holder of the old private key can do this. */
export function sealRotation(from: SigningKey, to: SigningKey, at: number): RotationStatement {
  const body = statementBody(from, to, at);
  return {
    ...body,
    sig: signBytes(from.privateKey, utf8(canonicalJson(body))),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function keyRefOf(value: unknown, field: string): KeyRef {
  if (!isRecord(value) || typeof value.keyId !== 'string' || typeof value.publicKey !== 'string') {
    throw new AttestError('invalid-key', `rotation ${field} must carry keyId and publicKey`);
  }
  return { keyId: value.keyId, publicKey: value.publicKey };
}

/**
 * Verifies that `endorser` (a key the caller already pins) signed this rotation.
 * Returns the statement with a normalised shape; throws on any tampering.
 */
export function openRotation(statement: unknown, endorserPublicKey: string): RotationStatement {
  if (
    !isRecord(statement) ||
    statement.v !== ROTATION_VERSION ||
    typeof statement.sig !== 'string' ||
    typeof statement.at !== 'number'
  ) {
    throw new AttestError('invalid-key', 'rotation statement has an unknown shape');
  }
  const from = keyRefOf(statement.from, 'from');
  const to = keyRefOf(statement.to, 'to');
  if (!publicKeyMatches(from.publicKey, endorserPublicKey)) {
    throw new AttestError(
      'unknown-key',
      `rotation for "${to.keyId}" is not endorsed by the key we trust ("${from.keyId}")`
    );
  }
  const body = statementBody(from, to, statement.at);
  if (!verifyBytes(from.publicKey, utf8(canonicalJson(body)), statement.sig)) {
    throw new AttestError(
      'bad-signature',
      `rotation "${from.keyId}" → "${to.keyId}" fails its signature`
    );
  }
  return { ...body, sig: statement.sig };
}

/**
 * Expands a trust map with every key the caller's keys have endorsed, in order.
 * A rotation must be endorsed by a key that is already trusted, so a rogue key
 * cannot bootstrap itself into the set.
 */
export function expandTrust(
  trustedKeys: Readonly<Record<string, string | undefined>>,
  rotations: readonly unknown[]
): Record<string, string> {
  const trust: Record<string, string> = {};
  for (const [keyId, publicKey] of Object.entries(trustedKeys)) {
    if (publicKey) trust[keyId] = publicKey;
  }

  let progressed = true;
  const pending = [...rotations];
  while (progressed && pending.length > 0) {
    progressed = false;
    for (let index = pending.length - 1; index >= 0; index -= 1) {
      const candidate = pending[index];
      const shape = isRecord(candidate) ? candidate : null;
      const fromKey = shape ? (shape.from as { publicKey?: unknown } | undefined)?.publicKey : null;
      if (typeof fromKey !== 'string') {
        throw new AttestError('invalid-key', 'rotation statement has an unknown shape');
      }
      const endorser = Object.values(trust).find((pinned) => publicKeyMatches(pinned, fromKey));
      if (!endorser) continue;
      const statement = openRotation(candidate, endorser);
      trust[statement.to.keyId] = statement.to.publicKey;
      pending.splice(index, 1);
      progressed = true;
    }
  }

  if (pending.length > 0) {
    throw new AttestError(
      'unknown-key',
      `rotation chain has ${pending.length} statement(s) not endorsed by a trusted key`
    );
  }
  return trust;
}
