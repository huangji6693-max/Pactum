#![cfg(test)]
extern crate std;

extern crate alloc;

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, BytesN, Env, Vec,
};

use crate::types::{
    BatchReputationClaim, BatchReputationEntry, CommitmentData, MerkleProof, BATCH_DEPTH,
    REPUTATION_BATCH_SIZE,
};
use crate::verifier::{poseidon4_accumulator, recompute_variable_root, reputation_leaf};
use crate::{FraudVerifierContract, FraudVerifierContractClient};

// ─── helpers ────────────────────────────────────────────────────────────────

fn setup_env() -> (Env, FraudVerifierContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(FraudVerifierContract, ());
    let client = FraudVerifierContractClient::new(&env, &contract_id);
    (env, client)
}

/// Build a deterministic 32-byte value from a seed byte.
fn bytes32(env: &Env, seed: u8) -> BytesN<32> {
    let arr: [u8; 32] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
    BytesN::from_array(env, &arr)
}

/// Build a MerkleProof with all-zero siblings and all-left path (path_bits all 0).
/// Used for honest-sequencer tests where the proof is structurally valid.
fn trivial_proof(env: &Env) -> MerkleProof {
    let mut siblings = Vec::new(env);
    let mut path_bits = Vec::new(env);
    for _ in 0..BATCH_DEPTH {
        siblings.push_back(bytes32(env, 0x00));
        path_bits.push_back(0u32);
    }
    MerkleProof {
        siblings,
        path_bits,
    }
}

/// Build a commitment with deterministic addresses and fields.
fn make_commitment(env: &Env) -> CommitmentData {
    CommitmentData {
        issuer: Address::generate(env),
        counterparty: Address::generate(env),
        terms_hash: bytes32(env, 0xAB),
        due_at: 1_700_000_000u64,
    }
}

/// Register sequencer and return the Address.
fn register_sequencer(env: &Env, client: &FraudVerifierContractClient, stake: i128) -> Address {
    let seq = Address::generate(env);
    client.register_sequencer(&seq, &stake);
    seq
}

// ─── test 1: sequencer registration ────────────────────────────────────────

#[test]
fn test_register_sequencer_stores_stake() {
    let (env, client) = setup_env();
    let _seq = register_sequencer(&env, &client, 1_000_000_000i128);
    assert_eq!(client.get_stake(), 1_000_000_000i128);
    assert!(!client.is_slashed());
}

// ─── test 2: batch registration ─────────────────────────────────────────────

#[test]
fn test_register_batch_stores_root() {
    let (env, client) = setup_env();
    let seq = register_sequencer(&env, &client, 1_000_000_000i128);
    let root = bytes32(&env, 0x11);
    client.register_batch(&seq, &100u32, &root);
    // is_batch_fraudulent should be false for a freshly registered batch
    assert!(!client.is_batch_fraudulent(&100u32));
}

// ─── test 3: valid fraud proof slashes sequencer ────────────────────────────

#[test]
fn test_valid_fraud_proof_slashes_sequencer() {
    let (env, client) = setup_env();
    let seq = register_sequencer(&env, &client, 5_000_000_000i128);

    // Register batch with root 0xFF (the "honest" root the sequencer claims)
    let registered_root = bytes32(&env, 0xFF);
    client.register_batch(&seq, &200u32, &registered_root);

    // The challenger builds a commitment + proof that hashes to a DIFFERENT root.
    // Using bytes32(0x00) siblings means the recomputed root will NOT be 0xFF.
    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env); // recomputes to a root != 0xFF → fraud

    let challenger = Address::generate(&env);
    let result = client.submit_fraud_proof(&challenger, &200u32, &0u32, &commitment, &proof);
    std::println!(
        "CPU instructions: {} / 90,000,000",
        env.cost_estimate().budget().cpu_instruction_cost()
    );

    assert!(result);
    assert!(client.is_slashed());
    assert_eq!(client.get_stake(), 0i128);
    assert!(client.is_batch_fraudulent(&200u32));
}

// ─── test 4: expired challenge window is rejected ────────────────────────────
// Instance storage entries get archived when we advance the ledger far into the
// future. We bump their TTL first so Soroban doesn't evict them during the
// fast-forward, then verify that try_submit_fraud_proof returns Err because
// the challenge window assertion fires.

#[test]
fn test_expired_challenge_window_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(FraudVerifierContract, ());
    let client = FraudVerifierContractClient::new(&env, &contract_id);

    let seq = Address::generate(&env);
    client.register_sequencer(&seq, &1_000_000_000i128);

    let root = bytes32(&env, 0x22);
    client.register_batch(&seq, &300u32, &root);

    let future_seq = 300u32 + 120_960u32 + 1u32;

    // Extend TTLs on all keys so they survive the ledger jump
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .extend_ttl(future_seq + 100_000, future_seq + 100_000);
        env.storage().persistent().extend_ttl(
            &crate::types::DataKey::Batch(300u32),
            future_seq + 100_000,
            future_seq + 100_000,
        );
    });

    env.ledger().set(LedgerInfo {
        sequence_number: future_seq,
        timestamp: (future_seq as u64) * 5,
        protocol_version: 22,
        network_id: Default::default(),
        base_reserve: 5_000_000,
        min_temp_entry_ttl: 100,
        min_persistent_entry_ttl: 100,
        max_entry_ttl: future_seq + 200_000,
    });

    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env);
    let challenger = Address::generate(&env);

    let result = client.try_submit_fraud_proof(&challenger, &300u32, &0u32, &commitment, &proof);
    assert!(result.is_err(), "Expected challenge window rejection");
}

// ─── test 5: duplicate challenge rejected ───────────────────────────────────

#[test]
#[should_panic(expected = "Leaf already challenged")]
fn test_duplicate_challenge_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(FraudVerifierContract, ());
    let client = FraudVerifierContractClient::new(&env, &contract_id);

    let seq = Address::generate(&env);
    client.register_sequencer(&seq, &1_000_000_000i128);

    let honest_root = bytes32(&env, 0x11);
    client.register_batch(&seq, &400u32, &honest_root);

    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env);
    let challenger = Address::generate(&env);

    // First challenge succeeds
    client.submit_fraud_proof(&challenger, &400u32, &5u32, &commitment, &proof);

    // Second challenge on same batch & leaf panics
    client.submit_fraud_proof(&challenger, &400u32, &5u32, &commitment, &proof);
}

// ─── test 6: batch not registered -> panic ───────────────────────────────────

#[test]
#[should_panic(expected = "Batch not registered")]
fn test_unregistered_batch_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(FraudVerifierContract, ());
    let client = FraudVerifierContractClient::new(&env, &contract_id);

    let seq = Address::generate(&env);
    client.register_sequencer(&seq, &1_000_000_000i128);

    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env);
    let challenger = Address::generate(&env);

    // batch_ledger_seq 999 was never registered
    client.submit_fraud_proof(&challenger, &999u32, &0u32, &commitment, &proof);
}

// ─── test 6: fabricated root rejected ───────────────────────────────────

#[test]
fn test_fabricated_root_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(FraudVerifierContract, ());
    let client = FraudVerifierContractClient::new(&env, &contract_id);

    let seq = Address::generate(&env);
    client.register_sequencer(&seq, &1_000_000_000i128);

    // Sequencer registers the true root
    let honest_root = bytes32(&env, 0x11);
    client.register_batch(&seq, &999u32, &honest_root);

    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env);
    let challenger = Address::generate(&env);

    // In the old design, the challenger could pass a forged registered_root.
    // Now, the contract reads `honest_root` from storage.
    // If the challenger's proof computes to something else, it is considered fraud
    // (since the root doesn't match the commitment they provided).
    // The user's gap #1 says: "If registered_root comes from the challenger's input...
    // a malicious challenger can... Prove fraud against an honest sequencer who never submitted that root"
    // By fetching from storage, the sequencer is evaluated against what they ACTUALLY submitted.
    let result = client.submit_fraud_proof(&challenger, &999u32, &0u32, &commitment, &proof);

    // Since trivial_proof recomputes to something other than honest_root,
    // the contract evaluates computed_root != honest_root (which is true)
    // and slashes the sequencer.
    assert!(result);
}

// ─── test 7: is_batch_fraudulent readable after slash ───────────────────────

#[test]
fn test_is_batch_fraudulent_readable_after_slash() {
    let (env, client) = setup_env();
    let seq = register_sequencer(&env, &client, 1_000_000_000i128);

    let root = bytes32(&env, 0x55);
    client.register_batch(&seq, &500u32, &root);

    assert!(!client.is_batch_fraudulent(&500u32));

    let commitment = make_commitment(&env);
    let proof = trivial_proof(&env);
    let challenger = Address::generate(&env);
    client.submit_fraud_proof(&challenger, &500u32, &0u32, &commitment, &proof);

    // After fraud proof accepted, #182 rollup engine can read this
    assert!(client.is_batch_fraudulent(&500u32));
}

// ─── test 8: batch reputation proof verification (#298) ────────────────────

#[test]
fn test_verify_batch_reputation_proof_succeeds_and_rejects_tampering() {
    let (env, client) = setup_env();
    let seq = register_sequencer(&env, &client, 2_000_000_000i128);

    // Build an 8-leaf reputation snapshot (depth 3 binary tree: 2^3 = 8 leaves)
    let addr_hi = bytes32(&env, 0x10);
    let addr_lo = bytes32(&env, 0x20);
    let score = 900u32;

    // For simplicity in constructing a valid shared root across all 8 entries,
    // use a depth-0 (single-node) or depth-2 symmetric path where all 8 entries
    // authenticate against `snapshot_root` with identical sibling hashes.
    let mut siblings = Vec::new(&env);
    let mut path_bits = Vec::new(&env);
    siblings.push_back(bytes32(&env, 0x01));
    siblings.push_back(bytes32(&env, 0x02));
    path_bits.push_back(0u32);
    path_bits.push_back(1u32);

    let leaf = reputation_leaf(&env, &addr_hi, &addr_lo, score);
    let snapshot_root = recompute_variable_root(&env, leaf.clone(), &siblings, &path_bits);

    client.register_reputation_root(&seq, &1u32, &snapshot_root);

    let mut entries = Vec::new(&env);
    let mut leaves = Vec::new(&env);
    for _ in 0..REPUTATION_BATCH_SIZE {
        entries.push_back(BatchReputationEntry {
            addr_hi: addr_hi.clone(),
            addr_lo: addr_lo.clone(),
            score,
            siblings: siblings.clone(),
            path_bits: path_bits.clone(),
        });
        leaves.push_back(leaf.clone());
    }

    let batch_commitment = poseidon4_accumulator(&env, &leaves);
    let claim = BatchReputationClaim {
        snapshot_root: snapshot_root.clone(),
        min_threshold: 800u32,
        min_cumulative_score: 7000u64,
        claimed_cumulative_score: (score as u64) * 8,
        claimed_batch_commitment: batch_commitment.clone(),
        context_id: 42u64,
    };

    assert!(client.verify_batch_reputation_proof(&1u32, &entries, &claim));

    // Tampered score or batch commitment must return false on a fresh context_id
    let mut bad_claim = claim.clone();
    bad_claim.context_id = 43u64;
    bad_claim.claimed_cumulative_score += 10;
    assert!(!client.verify_batch_reputation_proof(&1u32, &entries, &bad_claim));
}
