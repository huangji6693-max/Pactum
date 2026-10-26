use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon_nostd::{Poseidon, PoseidonHasher};
use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol};

use crate::types::{CommitmentData, DataKey, MerkleProof, SequencerRecord, FRAUD_PROVEN_TOPIC};
use crate::verifier::verify_merkle_fraud;

pub const BISECTION_RESOLVED_TOPIC: Symbol = soroban_sdk::symbol_short!("Bisect");

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BisectionTurn {
    SequencerProvideMidpoint,
    ChallengerChooseHalf,
    ReadyForSingleStepZk,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BisectionStatus {
    Active,
    ChallengerWon,
    SequencerWon,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BisectionGame {
    pub game_id: u64,
    pub batch_ledger_seq: u32,
    pub sequencer: Address,
    pub challenger: Address,
    pub challenger_bond: i128,
    pub low_step: u32,
    pub high_step: u32,
    pub agreed_low_root: BytesN<32>,
    pub disputed_high_root: BytesN<32>,
    pub pending_mid_root: Option<BytesN<32>>,
    pub round: u32,
    pub max_rounds: u32,
    pub turn: BisectionTurn,
    pub turn_deadline_ledger: u32,
    pub turn_timeout_ledgers: u32,
    pub status: BisectionStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BisectionKey {
    NextGameId,
    Game(u64),
}

fn bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn fr_to_bytes32(env: &Env, fr: Fr) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    let be_bytes = fr.into_bigint().to_bytes_be();
    bytes.copy_from_slice(&be_bytes);
    BytesN::from_array(env, &bytes)
}

fn address_to_fr(env: &Env, addr: &Address) -> Fr {
    use soroban_sdk::xdr::ToXdr;
    let xdr_bytes = addr.clone().to_xdr(env);
    let hash: BytesN<32> = env.crypto().sha256(&xdr_bytes).into();
    bytes_to_fr(&hash.to_array())
}

/// Computes the Poseidon commitment leaf matching `CommitmentHash()` in Circom.
pub fn compute_commitment_leaf(env: &Env, commitment: &CommitmentData) -> BytesN<32> {
    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
    let inputs = alloc::vec![
        address_to_fr(env, &commitment.issuer),
        address_to_fr(env, &commitment.counterparty),
        bytes_to_fr(&commitment.terms_hash.to_array()),
        Fr::from(commitment.due_at),
    ];
    let hash = poseidon.hash(&inputs).unwrap();
    fr_to_bytes32(env, hash)
}

/// Computes the single-instruction Poseidon transition root matching `SingleStepTransition()`
/// in `zk/circuits/FraudProof.circom`:
///   `post_state_root = Poseidon(pre_state_root, commitment_id, step_index, opcode)`
pub fn compute_single_step_transition(
    env: &Env,
    pre_state_root: &BytesN<32>,
    commitment: &CommitmentData,
    step_index: u32,
    opcode: u32,
) -> BytesN<32> {
    let commitment_id = compute_commitment_leaf(env, commitment);
    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
    let inputs = alloc::vec![
        bytes_to_fr(&pre_state_root.to_array()),
        bytes_to_fr(&commitment_id.to_array()),
        Fr::from(u64::from(step_index)),
        Fr::from(u64::from(opcode)),
    ];
    let out = poseidon.hash(&inputs).unwrap();
    fr_to_bytes32(env, out)
}

fn ceil_log2(mut n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    n -= 1;
    let mut bits = 0;
    while n > 0 {
        bits += 1;
        n >>= 1;
    }
    bits
}

fn slash_sequencer_for_game(env: &Env, game: &BisectionGame) {
    env.storage()
        .persistent()
        .set(&DataKey::FraudFlag(game.batch_ledger_seq), &true);

    let mut record: SequencerRecord = env
        .storage()
        .instance()
        .get(&DataKey::Sequencer)
        .expect("Sequencer not registered");

    let slash_amount = record.stake;
    record.slashed = true;
    record.stake = 0;
    env.storage().instance().set(&DataKey::Sequencer, &record);

    env.events().publish(
        (FRAUD_PROVEN_TOPIC,),
        (
            game.challenger.clone(),
            slash_amount,
            game.batch_ledger_seq,
            game.low_step,
        ),
    );
}

/// Initializes a new interactive bisection dispute game over `[0, total_steps]`.
#[allow(clippy::too_many_arguments)]
pub fn start_bisection(
    env: &Env,
    challenger: Address,
    batch_ledger_seq: u32,
    total_steps: u32,
    initial_state_root: BytesN<32>,
    claimed_final_root: BytesN<32>,
    challenger_bond: i128,
    turn_timeout_ledgers: u32,
    challenge_period_ledgers: u32,
) -> u64 {
    challenger.require_auth();

    assert!(total_steps > 0, "total_steps must be positive");
    assert!(challenger_bond > 0, "challenger_bond must be positive");
    assert!(
        turn_timeout_ledgers > 0,
        "turn_timeout_ledgers must be positive"
    );
    assert!(
        initial_state_root != claimed_final_root,
        "roots must differ to initiate dispute"
    );

    let current_ledger = env.ledger().sequence();
    assert!(
        current_ledger <= batch_ledger_seq + challenge_period_ledgers,
        "Challenge window has expired"
    );

    assert!(
        env.storage()
            .persistent()
            .has(&DataKey::Batch(batch_ledger_seq)),
        "Batch not registered"
    );

    let record: SequencerRecord = env
        .storage()
        .instance()
        .get(&DataKey::Sequencer)
        .expect("Sequencer not registered");
    assert!(!record.slashed, "Sequencer is slashed");

    let game_id: u64 = env
        .storage()
        .instance()
        .get(&BisectionKey::NextGameId)
        .unwrap_or(1);
    env.storage()
        .instance()
        .set(&BisectionKey::NextGameId, &(game_id + 1));

    let max_rounds = ceil_log2(total_steps);
    let initial_turn = if total_steps == 1 {
        BisectionTurn::ReadyForSingleStepZk
    } else {
        BisectionTurn::SequencerProvideMidpoint
    };

    let game = BisectionGame {
        game_id,
        batch_ledger_seq,
        sequencer: record.address,
        challenger,
        challenger_bond,
        low_step: 0,
        high_step: total_steps,
        agreed_low_root: initial_state_root,
        disputed_high_root: claimed_final_root,
        pending_mid_root: None,
        round: 0,
        max_rounds,
        turn: initial_turn,
        turn_deadline_ledger: current_ledger + turn_timeout_ledgers,
        turn_timeout_ledgers,
        status: BisectionStatus::Active,
    };

    env.storage()
        .persistent()
        .set(&BisectionKey::Game(game_id), &game);

    game_id
}

/// Sequencer submits the state root at the midpoint `mid = (low_step + high_step) / 2`.
pub fn submit_midpoint(
    env: &Env,
    sequencer: Address,
    game_id: u64,
    midpoint_root: BytesN<32>,
) -> BisectionGame {
    sequencer.require_auth();

    let mut game: BisectionGame = env
        .storage()
        .persistent()
        .get(&BisectionKey::Game(game_id))
        .expect("Bisection game not found");

    assert!(game.status == BisectionStatus::Active, "Game is not active");
    assert!(game.sequencer == sequencer, "Caller is not the sequencer");
    assert!(
        game.turn == BisectionTurn::SequencerProvideMidpoint,
        "Not sequencer's turn to provide midpoint"
    );
    assert!(
        game.high_step - game.low_step > 1,
        "Interval already narrowed to a single step"
    );

    let current_ledger = env.ledger().sequence();
    assert!(
        current_ledger <= game.turn_deadline_ledger,
        "Sequencer turn deadline expired"
    );

    game.pending_mid_root = Some(midpoint_root);
    game.turn = BisectionTurn::ChallengerChooseHalf;
    game.turn_deadline_ledger = current_ledger + game.turn_timeout_ledgers;

    env.storage()
        .persistent()
        .set(&BisectionKey::Game(game_id), &game);

    game
}

/// Challenger selects either the lower half `[low_step, mid]` (`challenge_lower_half == true`)
/// or the upper half `[mid, high_step]` (`challenge_lower_half == false`), halving the disputed
/// execution trace interval in `O(1)` on-chain work per round.
pub fn choose_half(
    env: &Env,
    challenger: Address,
    game_id: u64,
    challenge_lower_half: bool,
) -> BisectionGame {
    challenger.require_auth();

    let mut game: BisectionGame = env
        .storage()
        .persistent()
        .get(&BisectionKey::Game(game_id))
        .expect("Bisection game not found");

    assert!(game.status == BisectionStatus::Active, "Game is not active");
    assert!(
        game.challenger == challenger,
        "Caller is not the challenger"
    );
    assert!(
        game.turn == BisectionTurn::ChallengerChooseHalf,
        "Not challenger's turn to choose half"
    );

    let current_ledger = env.ledger().sequence();
    assert!(
        current_ledger <= game.turn_deadline_ledger,
        "Challenger turn deadline expired"
    );

    let mid_root = game
        .pending_mid_root
        .clone()
        .expect("Midpoint root missing");
    let mid = game.low_step + (game.high_step - game.low_step) / 2;

    if challenge_lower_half {
        game.high_step = mid;
        game.disputed_high_root = mid_root;
    } else {
        game.low_step = mid;
        game.agreed_low_root = mid_root;
    }

    game.pending_mid_root = None;
    game.round += 1;
    assert!(game.round <= game.max_rounds, "Exceeded max_rounds");

    game.turn = if game.high_step - game.low_step == 1 {
        BisectionTurn::ReadyForSingleStepZk
    } else {
        BisectionTurn::SequencerProvideMidpoint
    };
    game.turn_deadline_ledger = current_ledger + game.turn_timeout_ledgers;

    env.storage()
        .persistent()
        .set(&BisectionKey::Game(game_id), &game);

    game
}

/// Executes the single-instruction ZK transition & Merkle verification once the bisection game
/// has converged to `high_step - low_step == 1`. Slashes the dishonest party upon resolution.
pub fn verify_single_step_and_resolve(
    env: &Env,
    caller: Address,
    game_id: u64,
    commitment: &CommitmentData,
    opcode: u32,
    merkle_proof: &MerkleProof,
) -> BisectionStatus {
    caller.require_auth();

    let mut game: BisectionGame = env
        .storage()
        .persistent()
        .get(&BisectionKey::Game(game_id))
        .expect("Bisection game not found");

    assert!(game.status == BisectionStatus::Active, "Game is not active");
    assert!(
        caller == game.challenger || caller == game.sequencer,
        "Unauthorized caller"
    );
    assert!(
        game.turn == BisectionTurn::ReadyForSingleStepZk && game.high_step - game.low_step == 1,
        "Game has not converged to a single step"
    );

    let current_ledger = env.ledger().sequence();
    assert!(
        current_ledger <= game.turn_deadline_ledger,
        "Resolution turn deadline expired"
    );

    let expected_post_root = compute_single_step_transition(
        env,
        &game.agreed_low_root,
        commitment,
        game.low_step,
        opcode,
    );
    let batch_merkle_mismatch =
        verify_merkle_fraud(env, game.batch_ledger_seq, commitment, merkle_proof);

    if expected_post_root != game.disputed_high_root || batch_merkle_mismatch {
        game.status = BisectionStatus::ChallengerWon;
        slash_sequencer_for_game(env, &game);
    } else {
        game.status = BisectionStatus::SequencerWon;
        let mut record: SequencerRecord = env
            .storage()
            .instance()
            .get(&DataKey::Sequencer)
            .expect("Sequencer not registered");
        record.stake = record.stake.saturating_add(game.challenger_bond);
        env.storage().instance().set(&DataKey::Sequencer, &record);
    }

    env.storage()
        .persistent()
        .set(&BisectionKey::Game(game_id), &game);

    env.events().publish(
        (BISECTION_RESOLVED_TOPIC,),
        (game_id, game.status, game.low_step, game.round),
    );

    game.status
}

/// Enforces the turn-based chess clock: if the party whose turn is active fails to submit
/// their move before `turn_deadline_ledger`, awards victory to the counterparty and slashes
/// the stalling adversary's bond/stake.
pub fn claim_timeout(env: &Env, caller: Address, game_id: u64) -> BisectionStatus {
    caller.require_auth();

    let mut game: BisectionGame = env
        .storage()
        .persistent()
        .get(&BisectionKey::Game(game_id))
        .expect("Bisection game not found");

    assert!(game.status == BisectionStatus::Active, "Game is not active");
    assert!(
        caller == game.challenger || caller == game.sequencer,
        "Unauthorized caller"
    );

    let current_ledger = env.ledger().sequence();
    assert!(
        current_ledger > game.turn_deadline_ledger,
        "Turn deadline has not expired yet"
    );

    match game.turn {
        BisectionTurn::SequencerProvideMidpoint => {
            // Sequencer stalled: challenger wins and sequencer is slashed.
            game.status = BisectionStatus::ChallengerWon;
            slash_sequencer_for_game(env, &game);
        }
        BisectionTurn::ChallengerChooseHalf | BisectionTurn::ReadyForSingleStepZk => {
            // Challenger stalled: sequencer wins and claims challenger's bond.
            game.status = BisectionStatus::SequencerWon;
            let mut record: SequencerRecord = env
                .storage()
                .instance()
                .get(&DataKey::Sequencer)
                .expect("Sequencer not registered");
            record.stake = record.stake.saturating_add(game.challenger_bond);
            env.storage().instance().set(&DataKey::Sequencer, &record);
        }
    }

    env.storage()
        .persistent()
        .set(&BisectionKey::Game(game_id), &game);

    env.events().publish(
        (BISECTION_RESOLVED_TOPIC,),
        (game_id, game.status, game.low_step, game.round),
    );

    game.status
}

/// Loads a bisection game by ID.
pub fn get_game(env: &Env, game_id: u64) -> BisectionGame {
    env.storage()
        .persistent()
        .get(&BisectionKey::Game(game_id))
        .expect("Bisection game not found")
}

#[cfg(test)]
mod bisection_tests {
    extern crate std;

    use super::*;
    use crate::{FraudVerifierContract, FraudVerifierContractClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Vec,
    };

    fn setup_bisection_env() -> (
        Env,
        FraudVerifierContractClient<'static>,
        Address,
        Address,
        CommitmentData,
        MerkleProof,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(FraudVerifierContract, ());
        let client = FraudVerifierContractClient::new(&env, &contract_id);

        let sequencer = Address::generate(&env);
        let challenger = Address::generate(&env);
        client.register_sequencer(&sequencer, &5_000_000_000i128);

        let commitment = CommitmentData {
            issuer: Address::generate(&env),
            counterparty: Address::generate(&env),
            terms_hash: BytesN::from_array(&env, &[0xAB; 32]),
            due_at: 1_700_000_000u64,
        };

        let mut siblings = Vec::new(&env);
        let mut path_bits = Vec::new(&env);
        for _ in 0..crate::types::BATCH_DEPTH {
            siblings.push_back(BytesN::from_array(&env, &[0u8; 32]));
            path_bits.push_back(0u32);
        }
        let proof = MerkleProof {
            siblings,
            path_bits,
        };

        // Compute the honest batch Merkle root for `commitment` + `proof` so we can isolate
        // single-step state transition fraud during bisection tests.
        let leaf = compute_commitment_leaf(&env, &commitment);
        let mut honest_batch_root = leaf;
        for i in 0..crate::types::BATCH_DEPTH {
            let sib = proof.siblings.get(i).unwrap();
            let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
            let h = poseidon
                .hash(&alloc::vec![
                    bytes_to_fr(&honest_batch_root.to_array()),
                    bytes_to_fr(&sib.to_array()),
                ])
                .unwrap();
            honest_batch_root = fr_to_bytes32(&env, h);
        }

        client.register_batch(&sequencer, &100u32, &honest_batch_root);

        (env, client, sequencer, challenger, commitment, proof)
    }

    #[test]
    fn test_bisection_converges_from_1024_steps_in_10_rounds_and_slashes_fraudulent_sequencer() {
        let (env, client, sequencer, challenger, commitment, proof) = setup_bisection_env();

        // Build an execution trace of N = 1024 steps where step 611 is corrupted by the sequencer.
        let total_steps: u32 = 1024;
        let corrupted_step: u32 = 611;
        let initial_root = BytesN::from_array(&env, &[0x01; 32]);
        let claimed_final_root = BytesN::from_array(&env, &[0xFE; 32]);

        let game_id = client.start_bisection_game(
            &challenger,
            &100u32,
            &total_steps,
            &initial_root,
            &claimed_final_root,
            &500_000_000i128,
            &50u32,
        );

        let mut game = client.get_bisection_game(&game_id);
        assert_eq!(game.low_step, 0);
        assert_eq!(game.high_step, 1024);
        assert_eq!(game.max_rounds, 10);

        // Run the O(log N) interactive bisection loop toward `corrupted_step = 611`.
        while game.high_step - game.low_step > 1 {
            let mid = game.low_step + (game.high_step - game.low_step) / 2;
            let mid_root = BytesN::from_array(&env, &[(mid & 0xFF) as u8; 32]);

            client.submit_midpoint_root(&sequencer, &game_id, &mid_root);

            let challenge_lower = corrupted_step < mid;
            game = client.choose_disputed_half(&challenger, &game_id, &challenge_lower);
        }

        // Verify convergence in <= 10 on-chain rounds to exact step [611, 612].
        assert!(game.round <= 10);
        assert_eq!(game.round, 10);
        assert_eq!(game.low_step, corrupted_step);
        assert_eq!(game.high_step, corrupted_step + 1);
        assert_eq!(game.turn, BisectionTurn::ReadyForSingleStepZk);

        // Execute the single-step ZK transition verification at step 611.
        // Because `game.disputed_high_root` was fabricated by the dishonest sequencer and does not
        // equal `Poseidon(agreed_low_root, commitment_id, 611, opcode)`, the sequencer is slashed!
        let outcome = client.resolve_single_step(&challenger, &game_id, &commitment, &1u32, &proof);
        assert_eq!(outcome, BisectionStatus::ChallengerWon);
        assert!(client.is_slashed());
        assert_eq!(client.get_stake(), 0);
        assert!(client.is_batch_fraudulent(&100u32));
    }

    #[test]
    fn test_bisection_honest_sequencer_wins_when_single_step_transition_is_valid() {
        let (env, client, sequencer, challenger, commitment, proof) = setup_bisection_env();

        let pre_root = BytesN::from_array(&env, &[0x10; 32]);
        // Sequencer's state root at step 0 -> 1 is genuinely computed via Poseidon single-step transition.
        let valid_post_root = compute_single_step_transition(&env, &pre_root, &commitment, 0, 7);

        let game_id = client.start_bisection_game(
            &challenger,
            &100u32,
            &2u32,
            &pre_root,
            &BytesN::from_array(&env, &[0x99; 32]),
            &250_000_000i128,
            &50u32,
        );

        // Midpoint at step 1 is `valid_post_root`; challenger challenges lower half [0, 1].
        client.submit_midpoint_root(&sequencer, &game_id, &valid_post_root);
        let game = client.choose_disputed_half(&challenger, &game_id, &true);
        assert_eq!(game.low_step, 0);
        assert_eq!(game.high_step, 1);
        assert_eq!(game.turn, BisectionTurn::ReadyForSingleStepZk);

        let outcome = client.resolve_single_step(&sequencer, &game_id, &commitment, &7u32, &proof);
        assert_eq!(outcome, BisectionStatus::SequencerWon);
        assert!(!client.is_slashed());
        // Sequencer keeps their 5_000_000_000 stake + wins challenger's 250_000_000 bond!
        assert_eq!(client.get_stake(), 5_250_000_000i128);
    }

    #[test]
    fn test_bisection_chess_clock_timeout_penalizes_stalling_adversary() {
        let (env, client, sequencer, challenger, _commitment, _proof) = setup_bisection_env();

        let game_id = client.start_bisection_game(
            &challenger,
            &100u32,
            &1024u32,
            &BytesN::from_array(&env, &[0xAA; 32]),
            &BytesN::from_array(&env, &[0xBB; 32]),
            &300_000_000i128,
            &20u32, // 20-ledger chess clock per turn
        );

        // Claiming timeout before deadline (ledger 0 <= 20) must fail.
        let premature = client.try_claim_bisection_timeout(&challenger, &game_id);
        assert!(premature.is_err());

        // Advance ledger past sequencer's turn deadline (ledger 25 > 20).
        env.ledger().set(LedgerInfo {
            sequence_number: 25,
            timestamp: 125,
            protocol_version: 22,
            network_id: Default::default(),
            base_reserve: 5_000_000,
            min_temp_entry_ttl: 100,
            min_persistent_entry_ttl: 100,
            max_entry_ttl: 500_000,
        });

        let outcome = client.claim_bisection_timeout(&challenger, &game_id);
        assert_eq!(outcome, BisectionStatus::ChallengerWon);
        assert!(client.is_slashed());
        assert_eq!(client.get_stake(), 0);
        assert!(client.is_batch_fraudulent(&100u32));
        let _ = sequencer;
    }
}
