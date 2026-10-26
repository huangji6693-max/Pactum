use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon_nostd::{Poseidon, PoseidonHasher};
use soroban_sdk::{BytesN, Env, Vec};

use crate::types::{
    BatchReputationClaim, BatchReputationEntry, CommitmentData, DataKey, MerkleProof, BATCH_DEPTH,
    REPUTATION_BATCH_SIZE,
};

/// Helper to convert a byte slice into an `Fr` element.
/// In Circom, values are often BigInts. For our hashing, we take the bytes,
/// treat them as a big-endian integer, and convert to Fr.
fn bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Helper to convert an `Fr` element to `BytesN<32>`.
fn fr_to_bytes32(env: &Env, fr: Fr) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    let rep = fr.into_bigint();
    // ark-ff BigInteger::to_bytes_le is available. But circom uses little-endian or big-endian?
    // Wait, the cross-check test needs to be deterministic. We will use big-endian.
    let be_bytes = rep.to_bytes_be();
    bytes.copy_from_slice(&be_bytes);
    BytesN::from_array(env, &bytes)
}

/// Computes a Poseidon hash of two inputs (e.g. for Merkle tree nodes).
fn hash2(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let inputs = alloc::vec![
        bytes_to_fr(&left.to_array()),
        bytes_to_fr(&right.to_array())
    ];
    let hash = poseidon.hash(&inputs).unwrap();
    fr_to_bytes32(env, hash)
}

/// Converts a Soroban `Address` to a stable 32-byte representation by
/// serialising the strkey encoding via XDR and SHA-256-hashing it,
/// then converting that to a field element for Poseidon.
fn address_to_fr(env: &Env, addr: &soroban_sdk::Address) -> Fr {
    // XDR-serialise the address into raw bytes
    use soroban_sdk::xdr::ToXdr;
    let xdr_bytes = addr.clone().to_xdr(env);
    let hash: BytesN<32> = env.crypto().sha256(&xdr_bytes).into();
    bytes_to_fr(&hash.to_array())
}

/// Computes the Poseidon hash for a commitment leaf.
/// 4 inputs: issuer, counterparty, terms_hash, due_at.
fn commitment_leaf(env: &Env, commitment: &CommitmentData) -> BytesN<32> {
    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
    let issuer_fr = address_to_fr(env, &commitment.issuer);
    let cp_fr = address_to_fr(env, &commitment.counterparty);
    let terms_fr = bytes_to_fr(&commitment.terms_hash.to_array());
    let due_at_fr = Fr::from(commitment.due_at);

    let inputs = alloc::vec![issuer_fr, cp_fr, terms_fr, due_at_fr];
    let hash = poseidon.hash(&inputs).unwrap();
    fr_to_bytes32(env, hash)
}

/// Recomputes the Merkle root from a commitment leaf and its authentication path.
fn recompute_root(
    env: &Env,
    leaf: BytesN<32>,
    siblings: &Vec<BytesN<32>>,
    path_bits: &Vec<u32>,
) -> BytesN<32> {
    assert_eq!(
        siblings.len(),
        BATCH_DEPTH,
        "siblings length must equal BATCH_DEPTH"
    );
    assert_eq!(
        path_bits.len(),
        BATCH_DEPTH,
        "path_bits length must equal BATCH_DEPTH"
    );

    let mut current = leaf;
    for i in 0..BATCH_DEPTH {
        let sibling = siblings.get(i).unwrap();
        let bit = path_bits.get(i).unwrap();
        current = if bit == 0 {
            hash2(env, &current, &sibling) // current is left child
        } else {
            hash2(env, &sibling, &current) // current is right child
        };
    }
    current
}

/// Determines whether a fraud proof is valid by independently recomputing
/// the Merkle root from the supplied commitment data and authentication path,
/// then comparing against the root the sequencer registered on-chain.
///
/// # Security properties
/// - `registered_root` is fetched directly from persistent storage, not from caller input.
/// - The challenger cannot forge `correct_root`: the contract computes it itself.
pub fn verify_merkle_fraud(
    env: &Env,
    batch_ledger_seq: u32,
    commitment: &CommitmentData,
    proof: &MerkleProof,
) -> bool {
    // SECURITY FIX: Fetch the registered root from storage, NOT from caller.
    // If the batch doesn't exist, this panics and rejects the challenge.
    let registered_root: BytesN<32> = env
        .storage()
        .persistent()
        .get(&DataKey::Batch(batch_ledger_seq))
        .expect("Batch not registered");

    let leaf = commitment_leaf(env, commitment);
    let recomputed = recompute_root(env, leaf, &proof.siblings, &proof.path_bits);

    recomputed != registered_root
}

/// Computes `Poseidon(3)(addr_hi, addr_lo, score)` matching `batch_reputation.circom`.
pub fn reputation_leaf(
    env: &Env,
    addr_hi: &BytesN<32>,
    addr_lo: &BytesN<32>,
    score: u32,
) -> BytesN<32> {
    let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();
    let inputs = alloc::vec![
        bytes_to_fr(&addr_hi.to_array()),
        bytes_to_fr(&addr_lo.to_array()),
        Fr::from(score as u64),
    ];
    let hash = poseidon.hash(&inputs).unwrap();
    fr_to_bytes32(env, hash)
}

/// Recomputes a Poseidon binary Merkle root over an arbitrary-depth authentication path.
pub fn recompute_variable_root(
    env: &Env,
    leaf: BytesN<32>,
    siblings: &Vec<BytesN<32>>,
    path_bits: &Vec<u32>,
) -> BytesN<32> {
    assert_eq!(
        siblings.len(),
        path_bits.len(),
        "siblings and path_bits must have identical length"
    );
    let depth = siblings.len();
    let mut current = leaf;
    for i in 0..depth {
        let sibling = siblings.get(i).unwrap();
        let bit = path_bits.get(i).unwrap();
        assert!(bit == 0 || bit == 1, "path_bit must be 0 or 1");
        current = if bit == 0 {
            hash2(env, &current, &sibling)
        } else {
            hash2(env, &sibling, &current)
        };
    }
    current
}

/// Computes the 4-ary Poseidon tree accumulator over `k = 8` reputation leaf commitments:
///   branch0 = Poseidon(4)(leaves[0..4])
///   branch1 = Poseidon(4)(leaves[4..8])
///   out     = Poseidon(2)(branch0, branch1)
pub fn poseidon4_accumulator(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
    assert_eq!(
        leaves.len(),
        REPUTATION_BATCH_SIZE,
        "poseidon4_accumulator requires exactly 8 leaves"
    );
    let mut p4_left = Poseidon::<Fr>::new_circom(4).unwrap();
    let left_inputs = alloc::vec![
        bytes_to_fr(&leaves.get(0).unwrap().to_array()),
        bytes_to_fr(&leaves.get(1).unwrap().to_array()),
        bytes_to_fr(&leaves.get(2).unwrap().to_array()),
        bytes_to_fr(&leaves.get(3).unwrap().to_array()),
    ];
    let branch0 = fr_to_bytes32(env, p4_left.hash(&left_inputs).unwrap());

    let mut p4_right = Poseidon::<Fr>::new_circom(4).unwrap();
    let right_inputs = alloc::vec![
        bytes_to_fr(&leaves.get(4).unwrap().to_array()),
        bytes_to_fr(&leaves.get(5).unwrap().to_array()),
        bytes_to_fr(&leaves.get(6).unwrap().to_array()),
        bytes_to_fr(&leaves.get(7).unwrap().to_array()),
    ];
    let branch1 = fr_to_bytes32(env, p4_right.hash(&right_inputs).unwrap());

    hash2(env, &branch0, &branch1)
}

/// Verifies a batched multi-outcome reputation claim (`k = 8` entries) against an
/// authoritative snapshot root and 4-ary Poseidon accumulator commitment (#298).
pub fn verify_batch_reputation(
    env: &Env,
    registered_root: &BytesN<32>,
    entries: &Vec<BatchReputationEntry>,
    claim: &BatchReputationClaim,
) -> bool {
    if entries.len() != REPUTATION_BATCH_SIZE {
        return false;
    }
    if &claim.snapshot_root != registered_root {
        return false;
    }
    if claim.claimed_cumulative_score < claim.min_cumulative_score {
        return false;
    }

    let mut leaves = Vec::new(env);
    let mut cumulative_score: u64 = 0;

    for i in 0..REPUTATION_BATCH_SIZE {
        let entry = entries.get(i).unwrap();
        if entry.score <= claim.min_threshold {
            return false;
        }
        if entry.siblings.len() != entry.path_bits.len() {
            return false;
        }

        let leaf = reputation_leaf(env, &entry.addr_hi, &entry.addr_lo, entry.score);
        let root = recompute_variable_root(env, leaf.clone(), &entry.siblings, &entry.path_bits);
        if &root != registered_root {
            return false;
        }

        leaves.push_back(leaf);
        cumulative_score = cumulative_score.saturating_add(entry.score as u64);
    }

    if cumulative_score != claim.claimed_cumulative_score {
        return false;
    }

    let computed_accumulator = poseidon4_accumulator(env, &leaves);
    computed_accumulator == claim.claimed_batch_commitment
}
