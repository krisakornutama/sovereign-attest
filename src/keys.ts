import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { sha256Hex, utf8 } from './canonical.js';
import { AttestError } from './errors.js';

/** A signing key as it is stored inside the vault (the private half never leaves it). */
export interface SigningKey {
  readonly keyId: string;
  readonly privateKey: string;
  readonly publicKey: string;
  readonly createdAt: number;
}

const ALGORITHM = 'ed25519';
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PRIVATE_PREFIX = '-----BEGIN PRIVATE KEY-----';
const PUBLIC_PREFIX = '-----BEGIN PUBLIC KEY-----';

export function assertKeyId(keyId: string): string {
  if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
    throw new AttestError(
      'invalid-key',
      `keyId must be 1-64 characters of letters, digits, dot, dash or underscore (got ${JSON.stringify(keyId)})`
    );
  }
  return keyId;
}

/** Fresh Ed25519 key pair; the label is caller-chosen and travels in every receipt. */
export function createSigningKey(keyId: string, at: number = Date.now()): SigningKey {
  assertKeyId(keyId);
  const { privateKey, publicKey } = generateKeyPairSync(ALGORITHM);
  return {
    keyId,
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    createdAt: at,
  };
}

function privateKeyOf(pem: string): KeyObject {
  const trimmed = typeof pem === 'string' ? pem.trim() : '';
  if (!trimmed.startsWith(PRIVATE_PREFIX)) {
    throw new AttestError('invalid-key', 'signing key must be a PKCS#8 PEM private key');
  }
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: trimmed, format: 'pem' });
  } catch (error) {
    throw new AttestError('invalid-key', 'signing key PEM does not parse', { cause: error });
  }
  if (key.asymmetricKeyType !== ALGORITHM) {
    throw new AttestError(
      'invalid-key',
      `signing key must be ${ALGORITHM}, not ${key.asymmetricKeyType}`
    );
  }
  return key;
}

function publicKeyOf(pem: string): KeyObject {
  const trimmed = typeof pem === 'string' ? pem.trim() : '';
  if (!trimmed.startsWith(PUBLIC_PREFIX)) {
    throw new AttestError('invalid-key', 'public key must be an SPKI PEM key');
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: trimmed, format: 'pem' });
  } catch (error) {
    throw new AttestError('invalid-key', 'public key PEM does not parse', { cause: error });
  }
  if (key.asymmetricKeyType !== ALGORITHM) {
    throw new AttestError(
      'invalid-key',
      `public key must be ${ALGORITHM}, not ${key.asymmetricKeyType}`
    );
  }
  return key;
}

export function signBytes(privateKeyPem: string, payload: Uint8Array): string {
  const key = privateKeyOf(privateKeyPem);
  return sign(null, payload, key).toString('base64');
}

/** Returns false for any malformed input: verification must never throw on bad data. */
export function verifyBytes(publicKeyPem: string, payload: Uint8Array, signature: string): boolean {
  let key: KeyObject;
  let raw: Buffer;
  try {
    key = publicKeyOf(publicKeyPem);
    raw = Buffer.from(signature, 'base64');
  } catch {
    return false;
  }
  if (raw.length === 0) return false;
  try {
    return verify(null, payload, key, raw);
  } catch {
    return false;
  }
}

/** Short stable fingerprint of a public key, for logs and trust-on-first-use listings. */
export function publicKeyFingerprint(publicKeyPem: string): string {
  const der = publicKeyOf(publicKeyPem).export({ type: 'spki', format: 'der' });
  return sha256Hex(new Uint8Array(der)).slice(0, 32);
}

/** Normalises a PEM so the same key always compares equal across line endings. */
export function normalisePublicKey(publicKeyPem: string): string {
  return publicKeyOf(publicKeyPem)
    .export({ type: 'spki', format: 'pem' })
    .toString()
    .replace(/\r\n/g, '\n')
    .trim();
}

export function publicKeyMatches(left: string, right: string): boolean {
  return normalisePublicKey(left) === normalisePublicKey(right);
}

/** Signatures are over UTF-8 bytes of canonical JSON, never over a re-serialised object. */
export function signaturePayload(canonical: string): Uint8Array {
  return utf8(canonical);
}
