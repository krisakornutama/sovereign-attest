export type AttestErrorCode =
  | 'invalid-key'
  | 'invalid-receipt'
  | 'invalid-subject'
  | 'bad-signature'
  | 'unknown-key'
  | 'missing-receipt'
  | 'chain-broken'
  | 'invalid-anchor';

/** One error type for everything attest rejects, so callers can branch on `code`. */
export class AttestError extends Error {
  readonly code: AttestErrorCode;

  constructor(code: AttestErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AttestError';
    this.code = code;
  }
}
