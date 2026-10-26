#![no_std]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::duplicated_attributes)]

extern crate alloc;

pub mod bisection;

use crate::bisection::{BisectionGame, BisectionStatus};
use crate::types::{CommitmentData, DataKey, MerkleProof, SequencerRecord};
use crate::verifier::verify_merkle_fraud;
use soroban_sdk::{contract, contractimpl, log, Address, BytesN, Env};

#[cfg(test)]
mod tests;
mod types;
mod verifier;

/// Challenge window: 7 days expressed in ledger sequences.
/// Soroban produces ~1 ledger every 5 seconds → 7 * 24 * 3600 / 5 ≈ 120,960 ledgers.
const CHALLENGE_PERIOD_LEDGERS: u32 = 120_960;

#[contract]
pub struct FraudVerifierContract;

#[contractimpl]
impl FraudVerifierContract {
    /// Register a sequencer with a staked amount.
    /// The sequencer must authenticate this call.
    /// Only one sequencer is supported per contract instance (single-sequencer model v1).
    ///
    /// Integration with #182: the rollup engine should verify `is_slashed() == false`
    /// before accepting new batch submissions from this sequencer.
    pub fn register_sequencer(env: Env, sequencer: Address, stake: i128) {
        sequencer.require_auth();
        env.storage().instance().set(
            &DataKey::Sequencer,
            &SequencerRecord {
                address: sequencer,
                stake,
                slashed: false,
            },
        );
    }

    /// Sequencer registers a batch root on-chain.
    /// This stores the authoritative `batch_ledger_seq → claimed_batch_root` mapping
    /// which `submit_fraud_proof` uses to verify the challenger's claim.
    pub fn register_batch(
        env: Env,
        sequencer: Address,
        batch_ledger_seq: u32,
        claimed_batch_root: BytesN<32>,
    ) {
        sequencer.require_auth();

        let record: Option<SequencerRecord> = env.storage().instance().get(&DataKey::Sequencer);
        assert!(
            record.is_some() && record.as_ref().unwrap().address == sequencer,
            "Not the registered sequencer"
        );
        assert!(!record.unwrap().slashed, "Sequencer is slashed");

        env.storage()
            .persistent()
            .set(&DataKey::Batch(batch_ledger_seq), &claimed_batch_root);
    }

    /// Submit a fraud proof against a specific batch.
    ///
    /// # Verification steps (in order)
    /// 1. Challenge window: reject if ledger > batch_ledger_seq + CHALLENGE_PERIOD_LEDGERS
    /// 2. Deduplication: reject if (batch_ledger_seq, leaf_pos) was already challenged
    /// 3. Root lookup: retrieve the root the sequencer registered for this batch
    /// 4. Merkle recomputation: the contract independently computes the root from
    ///    raw commitment fields — the challenger cannot forge this value
    /// 5. If recomputed root ≠ registered root → fraud confirmed → slash
    ///
    /// # Token transfer (Follow-up: issue #190)
    /// Slashing currently records the event and zeroes the sequencer's stake in storage.
    /// Actual XLM transfer to the challenger via Soroban's token interface is deferred
    /// to issue #190 to keep this PR's scope reviewable. The slash amount is emitted
    /// in the event for off-chain monitoring.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_fraud_proof(
        env: Env,
        challenger: Address,
        batch_ledger_seq: u32,
        leaf_pos: u32,
        commitment: CommitmentData,
        proof: MerkleProof,
    ) -> bool {
        challenger.require_auth();

        // 1. Challenge window enforcement
        let current_ledger = env.ledger().sequence();
        assert!(
            current_ledger <= batch_ledger_seq + CHALLENGE_PERIOD_LEDGERS,
            "Challenge window has expired"
        );

        // 2. Deduplication: prevent double-challenging the same leaf
        let challenge_key = DataKey::Challenge(batch_ledger_seq, leaf_pos);
        assert!(
            !env.storage().persistent().has(&challenge_key),
            "Leaf already challenged"
        );
        env.storage().persistent().set(&challenge_key, &true);

        // 3 & 4. The contract independently recomputes the Merkle root and compares
        //        against the registered root. `verify_merkle_fraud` fetches the
        //        registered root from storage directly to prevent caller spoofing.
        let fraud_detected = verify_merkle_fraud(&env, batch_ledger_seq, &commitment, &proof);

        if fraud_detected {
            log!(
                &env,
                "Fraud detected at batch {} leaf {}. Slashing sequencer.",
                batch_ledger_seq,
                leaf_pos
            );

            // Mark batch as fraudulent (readable by #182 rollup engine via is_batch_fraudulent)
            env.storage()
                .persistent()
                .set(&DataKey::FraudFlag(batch_ledger_seq), &true);

            // Slash sequencer: zero stake in storage, mark slashed
            let mut record: SequencerRecord =
                env.storage().instance().get(&DataKey::Sequencer).unwrap();
            assert!(!record.slashed, "Already slashed");

            let slash_amount = record.stake;
            record.slashed = true;
            record.stake = 0;
            env.storage().instance().set(&DataKey::Sequencer, &record);

            // Emit event for off-chain monitoring and future token transfer (#190)
            env.events().publish(
                (crate::types::FRAUD_PROVEN_TOPIC,),
                (challenger, slash_amount, batch_ledger_seq, leaf_pos),
            );
        }

        fraud_detected
    }

    /// Returns whether the sequencer has been slashed.
    /// The #182 rollup engine should call this before accepting new batches.
    pub fn is_slashed(env: Env) -> bool {
        let record: Option<SequencerRecord> = env.storage().instance().get(&DataKey::Sequencer);
        record.map(|r| r.slashed).unwrap_or(false)
    }

    /// Returns whether a specific batch has been proven fraudulent.
    /// This is the primary integration point for the #182 rollup engine:
    ///   - The rollup engine calls this after each ledger close
    ///   - If true, it halts processing of new batches from this sequencer
    pub fn is_batch_fraudulent(env: Env, batch_ledger_seq: u32) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::FraudFlag(batch_ledger_seq))
            .unwrap_or(false)
    }

    /// Returns the sequencer's current stake balance.
    /// Returns 0 if no sequencer is registered or if already slashed.
    pub fn get_stake(env: Env) -> i128 {
        let record: Option<SequencerRecord> = env.storage().instance().get(&DataKey::Sequencer);
        record.map(|r| r.stake).unwrap_or(0)
    }

    /// Starts an interactive O(log N) bisection dispute game over `[0, total_steps]`.
    #[allow(clippy::too_many_arguments)]
    pub fn start_bisection_game(
        env: Env,
        challenger: Address,
        batch_ledger_seq: u32,
        total_steps: u32,
        initial_state_root: BytesN<32>,
        claimed_final_root: BytesN<32>,
        challenger_bond: i128,
        turn_timeout_ledgers: u32,
    ) -> u64 {
        bisection::start_bisection(
            &env,
            challenger,
            batch_ledger_seq,
            total_steps,
            initial_state_root,
            claimed_final_root,
            challenger_bond,
            turn_timeout_ledgers,
            CHALLENGE_PERIOD_LEDGERS,
        )
    }

    /// Sequencer submits the intermediate state root at the midpoint of the current disputed interval.
    pub fn submit_midpoint_root(
        env: Env,
        sequencer: Address,
        game_id: u64,
        midpoint_root: BytesN<32>,
    ) -> BisectionGame {
        bisection::submit_midpoint(&env, sequencer, game_id, midpoint_root)
    }

    /// Challenger chooses whether to dispute the lower half (`challenge_lower_half == true`)
    /// or the upper half (`challenge_lower_half == false`) of the interval.
    pub fn choose_disputed_half(
        env: Env,
        challenger: Address,
        game_id: u64,
        challenge_lower_half: bool,
    ) -> BisectionGame {
        bisection::choose_half(&env, challenger, game_id, challenge_lower_half)
    }

    /// Executes single-instruction ZK transition & Merkle verification once the interval
    /// converges to a single step (`high_step - low_step == 1`), slashing the dishonest party.
    pub fn resolve_single_step(
        env: Env,
        caller: Address,
        game_id: u64,
        commitment: CommitmentData,
        opcode: u32,
        proof: MerkleProof,
    ) -> BisectionStatus {
        bisection::verify_single_step_and_resolve(
            &env,
            caller,
            game_id,
            &commitment,
            opcode,
            &proof,
        )
    }

    /// Enforces turn-based chess clock timeout if an adversary fails to submit their move within deadline.
    pub fn claim_bisection_timeout(env: Env, caller: Address, game_id: u64) -> BisectionStatus {
        bisection::claim_timeout(&env, caller, game_id)
    }

    /// Returns the current state of an interactive bisection game.
    pub fn get_bisection_game(env: Env, game_id: u64) -> BisectionGame {
        bisection::get_game(&env, game_id)
    }
}
