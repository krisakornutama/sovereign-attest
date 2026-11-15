export { canonicalJson, fromUtf8, sha256Hex, utf8 } from './canonical.js';
export { AttestError } from './errors.js';
export type { AttestErrorCode } from './errors.js';
export {
  assertKeyId,
  createSigningKey,
  normalisePublicKey,
  publicKeyFingerprint,
  publicKeyMatches,
  signBytes,
  verifyBytes,
} from './keys.js';
export type { SigningKey } from './keys.js';
export { openReceipt, receiptId, sealReceipt, assertSha256 } from './receipt.js';
export type { ArtifactRef, Receipt, ReceiptBody, ReceiptTrust } from './receipt.js';
export { Attest, idOf, signedBy } from './attest.js';
export type {
  AnchorReport,
  ArtifactInput,
  AttestOptions,
  ProvenanceReport,
  RecordInput,
} from './attest.js';
export {
  ARTIFACT_PREFIX,
  HEAD_PREFIX,
  KEY_PREFIX,
  RECEIPT_PREFIX,
  artifactPath,
  headPath,
  keyPath,
  loadHead,
  loadReceipt,
  loadSigningKey,
  receiptPath,
  saveHead,
  saveReceipt,
  saveSigningKey,
} from './store.js';
export type { AnchorLogLike, AttestVault } from './store.js';
