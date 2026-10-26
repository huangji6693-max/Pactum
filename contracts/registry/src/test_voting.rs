//! Tests for M-of-N attestor voting and slashing (Issue 86, Phase 2).

use crate::commitments::CommitmentStatus;
use crate::errors::Error;
use crate::staking::AttestorStake;
use crate::{RegistryContract, RegistryContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, BytesN, Env, Vec,
};

/// Unix seconds at which tests start; advanced via `env.ledger().with_mut`.
const T0: u64 = 1_000_000;

/// Builds an initialized registry with a staking asset and a five-attestor
/// panel, every one of them staked `STAKE` units.
///
/// Returns the environment, the registry client, the token, the issuer, the
/// counterparty, the resolver (the arbitrator), and the panel vector.
const STAKE: i128 = 1_000;

fn setup_voting(
    env: &Env,
) -> (
    RegistryContractClient<'static>,
    Address,
    Address,
    Address,
    Address,
    Address,
    Vec<Address>,
) {
    env.mock_all_auths();

    let contract_id = env.register(RegistryContract, ());
    let client = RegistryContractClient::new(env, &contract_id);

    let arbitrator = Address::generate(env);
    let admin = Address::generate(env);
    client.initialize(&soroban_sdk::vec![env, arbitrator.clone()], &admin);

    let token = env
        .register_stellar_asset_contract_v2(arbitrator.clone())
        .address();
    client.set_staking_token(&arbitrator, &token);

    // Also configure the same token as the dispute token: dispute() requires
    // a token transfer (DISPUTE_STAKE_AMOUNT) from the caller, and panics with
    // error #40 (DisputeTokenNotSet) if none is configured.
    client.set_dispute_token(&arbitrator, &token);

    let issuer = Address::generate(env);
    let counterparty = Address::generate(env);

    // Mint dispute tokens to both parties and each attestor, since any party
    // to a commitment can raise a dispute in these tests.
    let dispute_asset = StellarAssetClient::new(env, &token);
    let dispute_fund = crate::commitments::DISPUTE_STAKE_AMOUNT * 10;
    dispute_asset.mint(&issuer, &dispute_fund);
    dispute_asset.mint(&counterparty, &dispute_fund);

    let mut attestors = Vec::new(env);
    for _ in 0..5 {
        let attestor = Address::generate(env);
        StellarAssetClient::new(env, &token).mint(&attestor, &(STAKE * 2));
        client.stake_attestor(&attestor, &STAKE);
        // Also mint dispute tokens: panel members can be disputers.
        dispute_asset.mint(&attestor, &dispute_fund);
        attestors.push_back(attestor);
    }

    env.ledger().with_mut(|l| l.timestamp = T0);

    (
        client,
        token,
        arbitrator,
        admin,
        issuer,
        counterparty,
        attestors,
    )
}

/// Creates a panel-governed commitment, attests it as `Fulfilled`, and raises
/// a dispute on it. Returns the commitment ID.
fn disputed_panel_commitment(
    env: &Env,
    client: &RegistryContractClient<'static>,
    issuer: &Address,
    counterparty: &Address,
    resolver: &Address,
    attestors: &Vec<Address>,
    threshold: u32,
) -> u64 {
    let terms = BytesN::from_array(env, &[9u8; 32]);
    let id = client.create_commitment(
        issuer,
        counterparty,
        &terms,
        &(T0 + 60),
        resolver,
        &None,
        &None,
        attestors,
        &threshold,
    );
    client.attest(issuer, &id, &CommitmentStatus::Fulfilled);
    client.dispute(issuer, &id);
    id
}

#[test]
fn test_vote_threshold_resolves_and_slashes_dissenters() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let (a1, a2, a3, a4, a5) = (
        attestors.get(0).unwrap(),
        attestors.get(1).unwrap(),
        attestors.get(2).unwrap(),
        attestors.get(3).unwrap(),
        attestors.get(4).unwrap(),
    );

    let id = disputed_panel_commitment(&env, &client, &issuer, &counterparty, &a5, &attestors, 3);

    // While the dispute is active every panel member's stake is locked.
    assert_eq!(
        client.get_stake_info(&a1),
        AttestorStake {
            staked: STAKE,
            unbonding_until: None,
            locked: true,
        }
    );

    // Four votes, one dissenting: the dispute resolves to Fulfilled.
    client.cast_dispute_vote(&a1, &id, &CommitmentStatus::Fulfilled);
    client.cast_dispute_vote(&a4, &id, &CommitmentStatus::Breached);
    client.cast_dispute_vote(&a2, &id, &CommitmentStatus::Fulfilled);
    client.cast_dispute_vote(&a3, &id, &CommitmentStatus::Fulfilled);

    let commitment = client.get_commitment(&id);
    assert_eq!(commitment.status, CommitmentStatus::Fulfilled);
    assert_eq!(commitment.attested_at, None);

    // The panel is unlocked, and the dissenting voter lost 10% of their stake.
    assert_eq!(
        client.get_stake_info(&a1),
        AttestorStake {
            staked: STAKE,
            unbonding_until: None,
            locked: false,
        }
    );
    assert_eq!(
        client.get_stake_info(&a4),
        AttestorStake {
            staked: STAKE - STAKE / 10,
            unbonding_until: None,
            locked: false,
        }
    );
    // Abstainers are unlocked and untouched.
    assert_eq!(
        client.get_stake_info(&a5),
        AttestorStake {
            staked: STAKE,
            unbonding_until: None,
            locked: false,
        }
    );
}

#[test]
fn test_vote_rejects_double_vote() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let a1 = attestors.get(0).unwrap();

    let id = disputed_panel_commitment(
        &env,
        &client,
        &issuer,
        &counterparty,
        &attestors.get(4).unwrap(),
        &attestors,
        3,
    );

    client.cast_dispute_vote(&a1, &id, &CommitmentStatus::Fulfilled);
    let res = client.try_cast_dispute_vote(&a1, &id, &CommitmentStatus::Late);
    assert_eq!(res, Err(Ok(Error::AttestorAlreadyVoted.into())));
}

#[test]
fn test_vote_rejects_unstaked_caller() {
    let env = Env::default();
    let (client, token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let stranger = Address::generate(&env);

    // A panel containing a member with no stake at all.
    let mut panel = attestors.clone();
    panel.push_back(stranger.clone());

    let id = disputed_panel_commitment(
        &env,
        &client,
        &issuer,
        &counterparty,
        &attestors.get(4).unwrap(),
        &panel,
        3,
    );

    // A member outside the panel is not an attestor.
    let outsider = Address::generate(&env);
    StellarAssetClient::new(&env, &token).mint(&outsider, &(STAKE * 2));
    client.stake_attestor(&outsider, &STAKE);
    let res = client.try_cast_dispute_vote(&outsider, &id, &CommitmentStatus::Fulfilled);
    assert_eq!(res, Err(Ok(Error::NotAttestor.into())));

    // A panel member with zero stake cannot vote.
    let res = client.try_cast_dispute_vote(&stranger, &id, &CommitmentStatus::Fulfilled);
    assert_eq!(res, Err(Ok(Error::InsufficientStake.into())));
}

#[test]
fn test_vote_rejects_invalid_outcome_and_non_disputed() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let a1 = attestors.get(0).unwrap();

    let terms = BytesN::from_array(&env, &[8u8; 32]);
    let id = client.create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 60),
        &attestors.get(4).unwrap(),
        &None,
        &None,
        &attestors,
        &3,
    );

    // Pending: not votable.
    let res = client.try_cast_dispute_vote(&a1, &id, &CommitmentStatus::Fulfilled);
    assert_eq!(res, Err(Ok(Error::InvalidTransition.into())));

    // Disputed, but Pending/Disputed are not valid votes.
    client.attest(&issuer, &id, &CommitmentStatus::Fulfilled);
    client.dispute(&issuer, &id);
    let res = client.try_cast_dispute_vote(&a1, &id, &CommitmentStatus::Pending);
    assert_eq!(res, Err(Ok(Error::InvalidOutcome.into())));
}

#[test]
fn test_vote_timeout_falls_back_to_breached() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let a1 = attestors.get(0).unwrap();

    let id = disputed_panel_commitment(
        &env,
        &client,
        &issuer,
        &counterparty,
        &attestors.get(4).unwrap(),
        &attestors,
        3,
    );

    // The window has not elapsed yet: finalization is refused.
    let res = client.try_check_dispute_timeout(&id);
    assert_eq!(res, Err(Ok(Error::VotesNotMet.into())));

    // Jump past the 7-day voting window without reaching the threshold.
    env.ledger()
        .with_mut(|l| l.timestamp = T0 + crate::voting::ATTESTOR_VOTE_TIMEOUT_SECONDS + 1);

    // Voting is now closed.
    let res = client.try_cast_dispute_vote(&a1, &id, &CommitmentStatus::Fulfilled);
    assert_eq!(res, Err(Ok(Error::VotingClosed.into())));

    client.check_dispute_timeout(&id);

    let commitment = client.get_commitment(&id);
    assert_eq!(commitment.status, CommitmentStatus::Breached);
    assert_eq!(commitment.attested_at, None);

    // The panel is unlocked.
    assert_eq!(
        client.get_stake_info(&a1),
        AttestorStake {
            staked: STAKE,
            unbonding_until: None,
            locked: false,
        }
    );
}

#[test]
fn test_resolve_dispute_rejected_for_panel_commitment() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);

    let id = disputed_panel_commitment(
        &env,
        &client,
        &issuer,
        &counterparty,
        &attestors.get(4).unwrap(),
        &attestors,
        3,
    );

    let res = client.try_resolve_dispute(
        &attestors.get(4).unwrap(),
        &id,
        &CommitmentStatus::Fulfilled,
    );
    assert_eq!(res, Err(Ok(Error::UseVotingResolution.into())));
}

#[test]
fn test_create_rejects_invalid_thresholds() {
    let env = Env::default();
    let (client, _token, arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);
    let terms = BytesN::from_array(&env, &[7u8; 32]);

    // Threshold above panel size.
    let res = client.try_create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 60),
        &arbitrator,
        &None,
        &None,
        &attestors,
        &6,
    );
    assert_eq!(res, Err(Ok(Error::ThresholdInvalid.into())));

    // Panel without threshold.
    let res = client.try_create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 60),
        &arbitrator,
        &None,
        &None,
        &attestors,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::ThresholdInvalid.into())));

    // Threshold without a panel.
    let empty = Vec::new(&env);
    let res = client.try_create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 60),
        &arbitrator,
        &None,
        &None,
        &empty,
        &2,
    );
    assert_eq!(res, Err(Ok(Error::ThresholdInvalid.into())));

    // Empty panel with zero threshold is the legacy single-resolver path.
    let id = client.create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 60),
        &arbitrator,
        &None,
        &None,
        &empty,
        &0,
    );
    let commitment = client.get_commitment(&id);
    assert!(commitment.attestors.is_empty());
    assert_eq!(commitment.vote_threshold(), 0);
}

#[test]
fn test_vote_balance_unaffected_by_threshold_vote() {
    let env = Env::default();
    let (client, token, _arbitrator, _admin, _issuer, _counterparty, attestors) =
        setup_voting(&env);
    let (a1, a2) = (attestors.get(0).unwrap(), attestors.get(1).unwrap());
    let resolver = attestors.get(4).unwrap();

    let terms = BytesN::from_array(&env, &[6u8; 32]);
    let id = client.create_commitment(
        &attestors.get(3).unwrap(),
        &resolver,
        &terms,
        &(T0 + 60),
        &resolver,
        &None,
        &None,
        &attestors,
        &3,
    );
    client.attest(&attestors.get(3).unwrap(), &id, &CommitmentStatus::Late);
    client.dispute(&attestors.get(3).unwrap(), &id);

    // Voting does not move tokens; slashing only happens at resolution.
    let token_client = TokenClient::new(&env, &token);
    let vault_before = token_client.balance(&client.address);

    client.cast_dispute_vote(&a1, &id, &CommitmentStatus::Late);
    client.cast_dispute_vote(&a2, &id, &CommitmentStatus::Late);

    assert_eq!(token_client.balance(&client.address), vault_before);
}

#[test]
fn test_vrf_panel_selection_zero_duplicates_and_excludes_conflicted_parties() {
    let env = Env::default();
    let (client, token, _arbitrator, _admin, issuer, counterparty, attestors) = setup_voting(&env);

    // Even if issuer and counterparty stake as attestors, they must be excluded from VRF selection.
    let asset = StellarAssetClient::new(&env, &token);
    asset.mint(&issuer, &(STAKE * 10));
    asset.mint(&counterparty, &(STAKE * 10));
    client.stake_attestor(&issuer, &(STAKE * 5));
    client.stake_attestor(&counterparty, &(STAKE * 5));

    // Also add one attestor who initiates unbonding; unbonding attestors must be excluded.
    let unbonding_attestor = Address::generate(&env);
    asset.mint(&unbonding_attestor, &(STAKE * 2));
    client.stake_attestor(&unbonding_attestor, &STAKE);
    client.request_unstake(&unbonding_attestor);

    let terms = BytesN::from_array(&env, &[0xAB; 32]);

    for trial in 0u32..40 {
        env.ledger().with_mut(|l| {
            l.sequence_number = 10_000 + trial;
            l.timestamp = T0 + (trial as u64) * 5;
        });

        let entropy = BytesN::from_array(&env, &[trial as u8; 32]);
        let panel = env.as_contract(&client.address, || {
            let seed = crate::staking::derive_vrf_dispute_seed(
                &env,
                u64::from(trial + 1),
                &issuer,
                &counterparty,
                &terms,
                &entropy,
            );
            crate::staking::select_vrf_stake_weighted_panel(&env, &seed, 4, &issuer, &counterparty)
        });

        assert_eq!(panel.len(), 4);

        // Verify zero duplicate attestors and no conflicted or unbonding parties.
        for i in 0..panel.len() {
            let member_i = panel.get(i).unwrap();
            assert_ne!(member_i, issuer);
            assert_ne!(member_i, counterparty);
            assert_ne!(member_i, unbonding_attestor);
            assert!(attestors.contains(&member_i));
            for j in (i + 1)..panel.len() {
                let member_j = panel.get(j).unwrap();
                assert_ne!(member_i, member_j, "duplicate attestor in VRF panel");
            }
        }
    }
}

#[test]
fn test_vrf_panel_selection_stake_proportional_distribution() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(RegistryContract, ());
    let client = RegistryContractClient::new(&env, &contract_id);

    let arbitrator = Address::generate(&env);
    let admin = Address::generate(&env);
    client.initialize(&soroban_sdk::vec![&env, arbitrator.clone()], &admin);

    let token = env
        .register_stellar_asset_contract_v2(arbitrator.clone())
        .address();
    client.set_staking_token(&arbitrator, &token);

    let asset = StellarAssetClient::new(&env, &token);
    let low_stake_attestor = Address::generate(&env);
    let mid_stake_attestor = Address::generate(&env);
    let high_stake_attestor = Address::generate(&env);

    // Stake weights: 100 (10%), 300 (30%), 600 (60%) => total 1,000.
    asset.mint(&low_stake_attestor, &100);
    asset.mint(&mid_stake_attestor, &300);
    asset.mint(&high_stake_attestor, &600);
    client.stake_attestor(&low_stake_attestor, &100);
    client.stake_attestor(&mid_stake_attestor, &300);
    client.stake_attestor(&high_stake_attestor, &600);

    let issuer = Address::generate(&env);
    let counterparty = Address::generate(&env);
    let terms = BytesN::from_array(&env, &[0x42; 32]);

    let mut low_count: u32 = 0;
    let mut mid_count: u32 = 0;
    let mut high_count: u32 = 0;
    let trials: u32 = 300;

    for i in 0..trials {
        env.ledger().with_mut(|l| {
            l.sequence_number = 50_000 + i;
            l.timestamp = T0 + u64::from(i) * 5;
        });
        let entropy = BytesN::from_array(&env, &[(i & 0xFF) as u8; 32]);
        let selected = env.as_contract(&client.address, || {
            let seed = crate::staking::derive_vrf_dispute_seed(
                &env,
                u64::from(i + 1),
                &issuer,
                &counterparty,
                &terms,
                &entropy,
            );
            crate::staking::select_vrf_stake_weighted_panel(&env, &seed, 1, &issuer, &counterparty)
        });
        let winner = selected.get(0).unwrap();
        if winner == low_stake_attestor {
            low_count += 1;
        } else if winner == mid_stake_attestor {
            mid_count += 1;
        } else if winner == high_stake_attestor {
            high_count += 1;
        } else {
            panic!("unexpected attestor selected");
        }
    }

    assert_eq!(low_count + mid_count + high_count, trials);
    // Expected counts over 300 trials: ~30 (low), ~90 (mid), ~180 (high).
    // Verify monotonic stake-proportional ordering and statistically sound bounds.
    assert!(
        high_count > mid_count && mid_count > low_count,
        "expected high ({high_count}) > mid ({mid_count}) > low ({low_count})"
    );
    assert!((10..=60).contains(&low_count), "low_count={low_count}");
    assert!((55..=130).contains(&mid_count), "mid_count={mid_count}");
    assert!((140..=230).contains(&high_count), "high_count={high_count}");
}

#[test]
fn test_vrf_seed_unpredictability_across_ledger_sequences_and_disputes() {
    let env = Env::default();
    let (client, _token, _arbitrator, _admin, issuer, counterparty, _attestors) =
        setup_voting(&env);
    let terms = BytesN::from_array(&env, &[0x11; 32]);
    let entropy_a = BytesN::from_array(&env, &[0x01; 32]);
    let entropy_b = BytesN::from_array(&env, &[0x02; 32]);

    env.ledger().with_mut(|l| {
        l.sequence_number = 777;
        l.timestamp = T0;
    });

    let (seed_base, seed_replay, seed_diff_commitment, seed_diff_entropy) =
        env.as_contract(&client.address, || {
            let s1 = crate::staking::derive_vrf_dispute_seed(
                &env,
                1,
                &issuer,
                &counterparty,
                &terms,
                &entropy_a,
            );
            let s1_again = crate::staking::derive_vrf_dispute_seed(
                &env,
                1,
                &issuer,
                &counterparty,
                &terms,
                &entropy_a,
            );
            let s_cid = crate::staking::derive_vrf_dispute_seed(
                &env,
                2,
                &issuer,
                &counterparty,
                &terms,
                &entropy_a,
            );
            let s_ent = crate::staking::derive_vrf_dispute_seed(
                &env,
                1,
                &issuer,
                &counterparty,
                &terms,
                &entropy_b,
            );
            (s1, s1_again, s_cid, s_ent)
        });

    assert_eq!(seed_base, seed_replay);
    assert_ne!(seed_base, seed_diff_commitment);
    assert_ne!(seed_base, seed_diff_entropy);

    // Advance ledger sequence by 1: seed must change unpredictably.
    env.ledger().with_mut(|l| {
        l.sequence_number = 778;
    });
    let seed_next_ledger = env.as_contract(&client.address, || {
        crate::staking::derive_vrf_dispute_seed(&env, 1, &issuer, &counterparty, &terms, &entropy_a)
    });
    assert_ne!(seed_base, seed_next_ledger);
}

#[test]
fn test_vrf_commitment_panel_cryptographic_binding_and_end_to_end_voting() {
    let env = Env::default();
    let (client, _token, arbitrator, _admin, issuer, counterparty, _attestors) = setup_voting(&env);

    env.ledger().with_mut(|l| {
        l.sequence_number = 9_001;
        l.timestamp = T0;
    });

    // Create a commitment initially without a static panel, then attest & dispute it.
    let empty_panel = Vec::new(&env);
    let terms = BytesN::from_array(&env, &[0x55; 32]);
    let id = client.create_commitment(
        &issuer,
        &counterparty,
        &terms,
        &(T0 + 600),
        &arbitrator,
        &None,
        &None,
        &empty_panel,
        &0,
    );
    client.attest(&issuer, &id, &CommitmentStatus::Fulfilled);
    client.dispute(&counterparty, &id);

    // Assign a 3-member VRF committee with threshold = 2 at dispute block sequence 9_001.
    let entropy = BytesN::from_array(&env, &[0x99; 32]);
    let record = env.as_contract(&client.address, || {
        crate::commitments::assign_vrf_dispute_panel(&env, id, 3, 2, &entropy)
    });

    assert_eq!(record.commitment_id, id);
    assert_eq!(record.ledger_sequence, 9_001);
    assert_eq!(record.vote_threshold, 2);
    assert_eq!(record.panel.len(), 3);

    // Cryptographic binding verification must succeed and match commitment storage.
    let binding_ok = env.as_contract(&client.address, || {
        crate::commitments::verify_dispute_panel_binding(&env, id)
    });
    assert!(binding_ok);

    let commitment = client.get_commitment(&id);
    assert_eq!(commitment.attestors, record.panel);
    assert_eq!(commitment.vote_threshold(), 2);

    // All 3 selected committee members have their stakes locked while the dispute is active.
    let m0 = record.panel.get(0).unwrap();
    let m1 = record.panel.get(1).unwrap();
    let m2 = record.panel.get(2).unwrap();
    assert!(client.get_stake_info(&m0).locked);
    assert!(client.get_stake_info(&m1).locked);
    assert!(client.get_stake_info(&m2).locked);

    // Cast M-of-N votes (m0 and m2 vote Breached, m1 dissents with Fulfilled).
    client.cast_dispute_vote(&m0, &id, &CommitmentStatus::Breached);
    client.cast_dispute_vote(&m1, &id, &CommitmentStatus::Fulfilled);
    client.cast_dispute_vote(&m2, &id, &CommitmentStatus::Breached);

    // Dispute resolves to Breached, dissenter m1 is slashed 10%, and all 3 are unlocked.
    let resolved = client.get_commitment(&id);
    assert_eq!(resolved.status, CommitmentStatus::Breached);
    assert!(!client.get_stake_info(&m0).locked);
    assert!(!client.get_stake_info(&m1).locked);
    assert!(!client.get_stake_info(&m2).locked);
    assert_eq!(client.get_stake_info(&m0).staked, STAKE);
    assert_eq!(client.get_stake_info(&m1).staked, STAKE - STAKE / 10);
    assert_eq!(client.get_stake_info(&m2).staked, STAKE);
}
