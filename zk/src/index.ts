/**
 * `@pactum/zk-reputation` — zero-knowledge Trust Score threshold proofs.
 *
 * See docs/zk-reputation-proofs.md for the proof-generation flow, the security
 * properties this does and does not provide, and the trusted-setup caveat.
 */

export { trustScore, MAX_TRUST_SCORE, type ReputationCounts } from './score.ts';
export { decodeEd25519PublicKey, addressToLimbs } from './strkey.ts';
export {
  DEFAULT_TREE_DEPTH,
  EMPTY_LEAF,
  buildPoseidonHash,
  buildSnapshot,
  findLeafIndex,
  leafForEntry,
  merklePath,
  sortEntries,
  type MerklePath,
  type PoseidonHash,
  type ReputationEntry,
  type ReputationSnapshot,
} from './tree.ts';
export {
  BATCH_SIZE,
  BATCH_TREE_DEPTH,
  computePoseidon4Accumulator,
  estimateBatchCircuitConstraints,
  evaluateBatchCircuitWitness,
  generateBatchReputationProof,
  generateTrustThresholdProof,
  toBatchCircuitInput,
  toCircuitInput,
  type BatchProofEntry,
  type BatchTrustCircuitInput,
  type BatchTrustProofRequest,
  type CircuitArtifact,
  type Groth16Proof,
  type TrustCircuitInput,
  type TrustProof,
  type TrustProofRequest,
} from './prove.ts';
export {
  BATCH_PUBLIC_SIGNAL_ORDER,
  parseBatchPublicSignals,
  parsePublicSignals,
  verifyBatchReputationProof,
  verifyTrustThresholdProof,
  PUBLIC_SIGNAL_ORDER,
  type BatchPublicSignals,
  type BatchVerificationResult,
  type BatchVerifyRequest,
  type PublicSignals,
  type VerificationKey,
  type VerificationResult,
  type VerifyRequest,
} from './verify.ts';
