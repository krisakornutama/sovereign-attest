import { createHash } from 'node:crypto';
import { AttestError } from './errors.js';

/**
 * Deterministic JSON: object keys sorted, no whitespace, no trailing data.
 *
 * A receipt is only verifiable on another machine if both sides hash exactly the
 * same bytes, so the encoding cannot depend on insertion order or on a
 * library's formatting choices.
 */
export function canonicalJson(value: unknown): string {
  return encode(value, new Set());
}

function encode(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new AttestError('invalid-receipt', 'receipt numbers must be finite');
      }
      // -0 and 0 hash the same on the wire; normalise so signer and verifier agree.
      return JSON.stringify(value === 0 ? 0 : value);
    case 'object':
      break;
    default:
      throw new AttestError(
        'invalid-receipt',
        `receipt values cannot be ${typeof value} (only JSON types are allowed)`
      );
  }

  const object = value as object;
  if (seen.has(object)) {
    throw new AttestError('invalid-receipt', 'receipt values cannot contain cycles');
  }
  seen.add(object);
  try {
    if (Array.isArray(object)) {
      return `[${object.map((item) => encode(item, seen)).join(',')}]`;
    }
    const entries = Object.entries(object as Record<string, unknown>);
    for (const [key, entry] of entries) {
      if (entry === undefined) {
        throw new AttestError('invalid-receipt', `receipt field "${key}" is undefined`);
      }
    }
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const fields = entries.map(([key, entry]) => `${JSON.stringify(key)}:${encode(entry, seen)}`);
    return `{${fields.join(',')}}`;
  } finally {
    seen.delete(object);
  }
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** UTF-8 helpers kept here so the whole package encodes strings one way. */
export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
