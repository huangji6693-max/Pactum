//! Timelock tests, driven end to end against the real registry contract.
//!
//! The target is the actual `registry::RegistryContract` rather than a mock, so these
//! exercise the whole governance path: the timelock authorizing as itself across a
//! cross-contract call, and the registry's `require_auth` on its stored upgrade admin
//! accepting that authorization.

use super::*;
use crate::errors::Error;
use crate::types::{
    ProposalAction, ProposalState, GRACE_PERIOD_SECONDS, MAX_DELAY_SECONDS, MIN_DELAY_SECONDS,
};
use registry::{RegistryContract, RegistryContractClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, BytesN, Env};

const START: u64 = 1_700_000_000;

struct Gov {
    env: Env,
    timelock: TimelockContractClient<'static>,
    timelock_id: Address,
    registry: RegistryContractClient<'static>,
    registry_id: Address,
    admin: Address,
    guardian: Address,
    arbitrator: Address,
}

/// Deploys a timelock and a registry, and installs the timelock as the registry's
/// upgrade admin — the production wiring.
fn setup() -> Gov {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let timelock_id = env.register(TimelockContract, ());
    let timelock = TimelockContractClient::new(&env, &timelock_id);
    let admin = Address::generate(&env);
    let guardian = Address::generate(&env);
    timelock.initialize(&admin, &guardian, &MIN_DELAY_SECONDS);

    let registry_id = env.register(RegistryContract, ());
    let registry = RegistryContractClient::new(&env, &registry_id);
    let arbitrator = Address::generate(&env);
    registry.initialize(&soroban_sdk::vec![&env, arbitrator.clone()], &admin);
    registry.init_upgrade_admin(&admin, &timelock_id);

    Gov {
        env,
        timelock,
        timelock_id,
        registry,
        registry_id,
        admin,
        guardian,
        arbitrator,
    }
}

fn hash(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Uploads the test fixture Wasm so a proposal can execute for real.
#[cfg(feature = "wasm-tests")]
mod fixture_contract {
    soroban_sdk::contractimport!(
        file = "../target/wasm32-unknown-unknown/release/upgrade_fixture.wasm"
    );
}

fn advance(env: &Env, seconds: u64) {
    env.ledger().with_mut(|l| l.timestamp += seconds);
}

// -------------------------------------------------------------------------
// Initialization
// -------------------------------------------------------------------------

#[test]
fn test_initialize_sets_governance_parameters() {
    let g = setup();
    assert_eq!(g.timelock.get_admin(), g.admin);
    assert_eq!(g.timelock.get_guardian(), g.guardian);
    assert_eq!(g.timelock.get_delay(), MIN_DELAY_SECONDS);
    assert_eq!(g.timelock.get_admin_epoch(), 0);
    assert_eq!(g.timelock.min_delay(), 7 * 24 * 60 * 60);
}

#[test]
fn test_initialize_can_only_run_once() {
    let g = setup();
    let err = g
        .timelock
        .try_initialize(&g.admin, &g.guardian, &MIN_DELAY_SECONDS)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::AlreadyInitialized.into());
}

#[test]
fn test_initialize_rejects_a_delay_below_seven_days() {
    // The whole point of the contract: the review window cannot be configured away.
    let env = Env::default();
    env.mock_all_auths();
    let timelock = TimelockContractClient::new(&env, &env.register(TimelockContract, ()));

    let err = timelock
        .try_initialize(
            &Address::generate(&env),
            &Address::generate(&env),
            &(MIN_DELAY_SECONDS - 1),
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::DelayTooShort.into());
}

#[test]
fn test_initialize_rejects_an_absurd_delay() {
    let env = Env::default();
    env.mock_all_auths();
    let timelock = TimelockContractClient::new(&env, &env.register(TimelockContract, ()));

    let err = timelock
        .try_initialize(
            &Address::generate(&env),
            &Address::generate(&env),
            &(MAX_DELAY_SECONDS + 1),
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::DelayTooLong.into());
}

#[test]
#[should_panic]
fn test_initialize_requires_both_admin_and_guardian_auth() {
    let env = Env::default();
    let timelock = TimelockContractClient::new(&env, &env.register(TimelockContract, ()));
    // No mocked auths at all: neither role has consented to being enrolled.
    timelock.initialize(
        &Address::generate(&env),
        &Address::generate(&env),
        &MIN_DELAY_SECONDS,
    );
}

// -------------------------------------------------------------------------
// Queueing
// -------------------------------------------------------------------------

#[test]
fn test_queue_pins_the_wasm_hash_and_sets_the_eta() {
    let g = setup();
    let wasm = hash(&g.env, 0xAB);
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(wasm.clone(), 2),
        &hash(&g.env, 0x01),
    );

    let p = g.timelock.get_proposal(&id);
    assert_eq!(p.id, 1);
    assert_eq!(p.target, g.registry_id);
    assert_eq!(p.proposer, g.admin);
    assert_eq!(p.state, ProposalState::Queued);
    assert_eq!(p.queued_at, START);
    assert_eq!(p.eta, START + MIN_DELAY_SECONDS);
    assert_eq!(
        p.expires_at,
        START + MIN_DELAY_SECONDS + GRACE_PERIOD_SECONDS
    );
    assert_eq!(p.admin_epoch, 0);
    // The reviewed bytes are recorded on-chain at proposal time.
    assert_eq!(p.action, ProposalAction::Upgrade(wasm, 2));
}

#[test]
fn test_queue_assigns_sequential_ids() {
    let g = setup();
    let a = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 1), 2),
        &hash(&g.env, 0),
    );
    let b = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 2), 2),
        &hash(&g.env, 0),
    );
    assert_eq!((a, b), (1, 2));
}

#[test]
fn test_non_admin_cannot_queue() {
    let g = setup();
    let stranger = Address::generate(&g.env);
    let err = g
        .timelock
        .try_queue(
            &stranger,
            &g.registry_id,
            &ProposalAction::Upgrade(hash(&g.env, 9), 2),
            &hash(&g.env, 0),
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NotAdmin.into());
}

#[test]
fn test_guardian_cannot_queue() {
    // The guardian holds a veto, not a proposal power.
    let g = setup();
    let err = g
        .timelock
        .try_queue(
            &g.guardian,
            &g.registry_id,
            &ProposalAction::Upgrade(hash(&g.env, 9), 2),
            &hash(&g.env, 0),
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NotAdmin.into());
}

#[test]
#[should_panic]
fn test_queue_requires_proposer_signature() {
    let g = setup();
    g.env.set_auths(&[]);
    g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 9), 2),
        &hash(&g.env, 0),
    );
}

#[test]
fn test_queue_rejects_schema_version_zero() {
    let g = setup();
    let err = g
        .timelock
        .try_queue(
            &g.admin,
            &g.registry_id,
            &ProposalAction::Upgrade(hash(&g.env, 9), 0),
            &hash(&g.env, 0),
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::InvalidSchemaVersion.into());
}

// -------------------------------------------------------------------------
// The 7-day delay
// -------------------------------------------------------------------------

/// Queues a real upgrade of the registry to the fixture executable.
#[cfg(feature = "wasm-tests")]
fn queue_real_upgrade(g: &Gov) -> u64 {
    let wasm_hash = g
        .env
        .deployer()
        .upload_contract_wasm(fixture_contract::WASM);
    g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(wasm_hash, 2),
        &hash(&g.env, 0xDE),
    )
}

#[test]
fn test_execution_is_rejected_before_the_delay_elapses() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    assert!(!g.timelock.is_executable(&id));
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::TimelockNotElapsed.into());
}

#[test]
fn test_execution_is_rejected_one_second_before_the_eta() {
    // Boundary: the delay is "at least 7 days", so 7 days minus a second must fail.
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    advance(&g.env, MIN_DELAY_SECONDS - 1);
    assert!(!g.timelock.is_executable(&id));
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::TimelockNotElapsed.into());
}

#[test]
fn test_proposal_becomes_executable_exactly_at_the_eta() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    advance(&g.env, MIN_DELAY_SECONDS);
    // Inclusive boundary: exactly 7 days is enough.
    assert!(g.timelock.is_executable(&id));
}

#[test]
fn test_proposal_expires_after_the_grace_period() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    // Last executable instant.
    advance(&g.env, MIN_DELAY_SECONDS + GRACE_PERIOD_SECONDS);
    assert!(g.timelock.is_executable(&id));

    // One second later the approval is stale and must be re-proposed.
    advance(&g.env, 1);
    assert!(!g.timelock.is_executable(&id));
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::ProposalExpired.into());
}

#[test]
fn test_changing_the_delay_does_not_pull_a_queued_proposal_forward() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    let original_eta = g.timelock.get_proposal(&id).eta;

    // Even the shortest legal delay cannot shorten an in-flight proposal's window.
    g.timelock.set_delay(&MIN_DELAY_SECONDS);
    assert_eq!(g.timelock.get_proposal(&id).eta, original_eta);

    advance(&g.env, MIN_DELAY_SECONDS - 1);
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::TimelockNotElapsed.into());
}

#[test]
fn test_delay_cannot_be_set_below_the_hard_floor() {
    let g = setup();
    let err = g
        .timelock
        .try_set_delay(&(MIN_DELAY_SECONDS - 1))
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::DelayTooShort.into());
    assert_eq!(g.timelock.get_delay(), MIN_DELAY_SECONDS);
}

#[test]
fn test_a_longer_delay_applies_to_new_proposals() {
    let g = setup();
    let longer = MIN_DELAY_SECONDS * 2;
    g.timelock.set_delay(&longer);

    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    assert_eq!(g.timelock.get_proposal(&id).eta, START + longer);
}

// -------------------------------------------------------------------------
// Cancellation, replay, and staleness
// -------------------------------------------------------------------------

#[test]
fn test_guardian_can_cancel_a_queued_proposal() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    g.timelock.cancel(&g.guardian, &id);
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Cancelled);

    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(!g.timelock.is_executable(&id));
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::ProposalNotQueued.into());
}

#[test]
fn test_admin_can_withdraw_its_own_proposal() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    g.timelock.cancel(&g.admin, &id);
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Cancelled);
}

#[test]
fn test_stranger_cannot_cancel() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    let err = g
        .timelock
        .try_cancel(&Address::generate(&g.env), &id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NotAdminOrGuardian.into());
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Queued);
}

#[test]
fn test_cancelled_proposal_cannot_be_cancelled_again() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    g.timelock.cancel(&g.guardian, &id);
    let err = g
        .timelock
        .try_cancel(&g.guardian, &id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::ProposalNotQueued.into());
}

#[test]
fn test_unknown_proposal_id_is_rejected() {
    let g = setup();
    let err = g.timelock.try_get_proposal(&99).unwrap_err().unwrap();
    assert_eq!(err, Error::ProposalNotFound.into());
}

#[test]
fn test_queued_proposal_cannot_be_swapped_for_different_wasm() {
    // The pinning guarantee. Queueing a second proposal creates a *new* id with its own
    // fresh 7-day clock; it cannot overwrite or re-point the one already under review.
    let g = setup();
    let reviewed = hash(&g.env, 0xAA);
    let malicious = hash(&g.env, 0xBB);

    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(reviewed.clone(), 2),
        &hash(&g.env, 0),
    );

    advance(&g.env, MIN_DELAY_SECONDS - 60);
    let second = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(malicious.clone(), 2),
        &hash(&g.env, 0),
    );

    assert_ne!(id, second);
    // The proposal under review still names the bytes reviewers inspected.
    assert_eq!(
        g.timelock.get_proposal(&id).action,
        ProposalAction::Upgrade(reviewed, 2)
    );
    // The substitute starts its own full delay from scratch.
    let swapped = g.timelock.get_proposal(&second);
    assert_eq!(swapped.action, ProposalAction::Upgrade(malicious, 2));
    assert_eq!(
        swapped.eta,
        START + MIN_DELAY_SECONDS - 60 + MIN_DELAY_SECONDS
    );
    advance(&g.env, 60);
    assert!(!g.timelock.is_executable(&second));
}

#[test]
fn test_admin_rotation_invalidates_queued_proposals() {
    // A queued upgrade does not survive a change of governance: whoever takes over must
    // re-propose, which restarts the full review window.
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    let new_admin = Address::generate(&g.env);
    g.timelock.transfer_admin(&new_admin);
    assert_eq!(g.timelock.get_admin(), new_admin);
    assert_eq!(g.timelock.get_admin_epoch(), 1);

    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(!g.timelock.is_executable(&id));
    let err = g
        .timelock
        .try_execute(&new_admin, &id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::ProposalStale.into());
}

#[test]
fn test_the_old_admin_cannot_execute_after_rotation() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    let new_admin = Address::generate(&g.env);
    g.timelock.transfer_admin(&new_admin);

    advance(&g.env, MIN_DELAY_SECONDS);
    let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
    assert_eq!(err, Error::NotAdmin.into());
}

#[test]
fn test_guardian_rotation_does_not_invalidate_proposals() {
    // The guardian never queues anything, so rotating it says nothing about the
    // provenance of work already in flight.
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );

    let new_guardian = Address::generate(&g.env);
    g.timelock.transfer_guardian(&new_guardian);
    assert_eq!(g.timelock.get_guardian(), new_guardian);
    assert_eq!(g.timelock.get_admin_epoch(), 0);

    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(g.timelock.is_executable(&id));
}

#[test]
fn test_new_guardian_can_veto_and_old_guardian_cannot() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    let new_guardian = Address::generate(&g.env);
    g.timelock.transfer_guardian(&new_guardian);

    let err = g
        .timelock
        .try_cancel(&g.guardian, &id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NotAdminOrGuardian.into());

    g.timelock.cancel(&new_guardian, &id);
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Cancelled);
}

#[test]
#[should_panic]
fn test_admin_rotation_requires_the_guardians_signature() {
    // Two-of-two: a compromised admin key alone cannot hand governance to an attacker.
    let g = setup();
    g.env.set_auths(&[]);
    g.timelock.transfer_admin(&Address::generate(&g.env));
}

// -------------------------------------------------------------------------
// Execution against the real registry
// -------------------------------------------------------------------------

#[test]
fn test_non_admin_cannot_execute_a_matured_proposal() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    advance(&g.env, MIN_DELAY_SECONDS);

    for caller in [Address::generate(&g.env), g.guardian.clone()] {
        let err = g.timelock.try_execute(&caller, &id).unwrap_err().unwrap();
        assert_eq!(err, Error::NotAdmin.into());
    }
    // Still queued and still executable by the rightful admin.
    assert!(g.timelock.is_executable(&id));
}

#[test]
#[should_panic]
fn test_execute_requires_the_admins_signature() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xAB), 2),
        &hash(&g.env, 0),
    );
    advance(&g.env, MIN_DELAY_SECONDS);
    g.env.set_auths(&[]);
    g.timelock.execute(&g.admin, &id);
}

#[test]
fn test_the_registry_rejects_an_upgrade_that_did_not_come_from_the_timelock() {
    // The other half of the guarantee: even a valid Wasm hash is useless to anyone who
    // is not the installed upgrade admin, so the delay cannot simply be bypassed.
    let g = setup();
    g.env.set_auths(&[]);
    let outcome = g.registry.try_upgrade(&hash(&g.env, 0xAB), &2);
    assert!(outcome.is_err());
}

#[test]
fn test_set_upgrade_admin_proposal_rotates_registry_authority() {
    let g = setup();
    let successor = Address::generate(&g.env);
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::SetUpgradeAdmin(successor.clone()),
        &hash(&g.env, 0x77),
    );

    advance(&g.env, MIN_DELAY_SECONDS - 1);
    assert!(g.timelock.try_execute(&g.admin, &id).is_err());

    advance(&g.env, 1);
    g.timelock.execute(&g.admin, &id);

    // Authority moved, and the old timelock can no longer upgrade the registry.
    assert_eq!(g.registry.get_upgrade_admin(), Some(successor));
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Executed);

    let follow_up = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::SetUpgradeAdmin(g.timelock_id.clone()),
        &hash(&g.env, 0x78),
    );
    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(g.timelock.try_execute(&g.admin, &follow_up).is_err());
}

#[test]
fn test_registry_state_is_untouched_by_a_rejected_early_execution() {
    let g = setup();
    let id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::SetUpgradeAdmin(Address::generate(&g.env)),
        &hash(&g.env, 0),
    );

    assert!(g.timelock.try_execute(&g.admin, &id).is_err());
    // Nothing moved: the registry still answers to this timelock, and the proposal is
    // still queued rather than burned.
    assert_eq!(g.registry.get_upgrade_admin(), Some(g.timelock_id.clone()));
    assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Queued);
    assert_eq!(g.registry.get_arbitrator(), g.arbitrator);
}

// -------------------------------------------------------------------------
// Guardian Multi-Sig Veto, Circuit Breaker & Post-Pause Unwinding (#311)
// -------------------------------------------------------------------------

#[contract]
pub struct MockUpgradeTarget;

#[contractimpl]
impl MockUpgradeTarget {
    pub fn upgrade(_env: Env, _wasm_hash: BytesN<32>, _schema_version: u32) {}
    pub fn set_upgrade_admin(_env: Env, _new_admin: Address) {}
}

#[test]
fn test_guardian_multisig_veto_and_purge_removes_malicious_proposal_prior_to_eta() {
    let g = setup();
    let g1 = g.guardian.clone();
    let g2 = Address::generate(&g.env);
    let g3 = Address::generate(&g.env);

    g.timelock.configure_guardians(
        &soroban_sdk::vec![&g.env, g1.clone(), g2.clone(), g3.clone()],
        &2,
    );
    assert_eq!(g.timelock.get_guardian_threshold(), 2);
    assert_eq!(g.timelock.get_guardians().len(), 3);

    let malicious_id = g.timelock.queue(
        &g.admin,
        &g.registry_id,
        &ProposalAction::Upgrade(hash(&g.env, 0xEE), 2),
        &hash(&g.env, 0xFF),
    );

    // 1-of-3 guardian signature is rejected when threshold is 2.
    let insufficient = g
        .timelock
        .try_veto_and_purge(&soroban_sdk::vec![&g.env, g1.clone()], &malicious_id)
        .unwrap_err()
        .unwrap();
    assert_eq!(
        insufficient,
        GovernanceError::InsufficientGuardianQuorum.into()
    );

    // Duplicate signer does not satisfy 2-of-3 quorum.
    let duplicate = g
        .timelock
        .try_veto_and_purge(
            &soroban_sdk::vec![&g.env, g1.clone(), g1.clone()],
            &malicious_id,
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(
        duplicate,
        GovernanceError::InsufficientGuardianQuorum.into()
    );

    // Non-member signer is rejected.
    let stranger = Address::generate(&g.env);
    let non_member = g
        .timelock
        .try_veto_and_purge(
            &soroban_sdk::vec![&g.env, g1.clone(), stranger],
            &malicious_id,
        )
        .unwrap_err()
        .unwrap();
    assert_eq!(
        non_member,
        GovernanceError::InsufficientGuardianQuorum.into()
    );

    // Valid 2-of-3 guardian quorum vetoes and purges the proposal prior to ETA.
    g.timelock.veto_and_purge(
        &soroban_sdk::vec![&g.env, g2.clone(), g3.clone()],
        &malicious_id,
    );
    assert!(g.timelock.is_purged(&malicious_id));
    assert!(!g.timelock.is_executable(&malicious_id));

    let get_err = g
        .timelock
        .try_get_proposal(&malicious_id)
        .unwrap_err()
        .unwrap();
    assert_eq!(get_err, GovernanceError::ProposalAlreadyPurged.into());

    // Advancing past ETA still refuses execution of the purged proposal.
    advance(&g.env, MIN_DELAY_SECONDS);
    let exec_err = g
        .timelock
        .try_execute(&g.admin, &malicious_id)
        .unwrap_err()
        .unwrap();
    assert_eq!(exec_err, GovernanceError::ProposalAlreadyPurged.into());
}

#[test]
fn test_configure_guardians_rejects_invalid_thresholds_and_duplicates() {
    let g = setup();
    let g1 = g.guardian.clone();
    let g2 = Address::generate(&g.env);

    // Empty set rejected.
    assert_eq!(
        g.timelock
            .try_configure_guardians(&soroban_sdk::vec![&g.env], &1)
            .unwrap_err()
            .unwrap(),
        GovernanceError::InvalidGuardianSet.into()
    );

    // Threshold 0 rejected.
    assert_eq!(
        g.timelock
            .try_configure_guardians(&soroban_sdk::vec![&g.env, g1.clone()], &0)
            .unwrap_err()
            .unwrap(),
        GovernanceError::InvalidGuardianSet.into()
    );

    // Threshold > count rejected.
    assert_eq!(
        g.timelock
            .try_configure_guardians(&soroban_sdk::vec![&g.env, g1.clone(), g2.clone()], &3)
            .unwrap_err()
            .unwrap(),
        GovernanceError::InvalidGuardianSet.into()
    );

    // Duplicate guardian address rejected.
    assert_eq!(
        g.timelock
            .try_configure_guardians(&soroban_sdk::vec![&g.env, g1.clone(), g1], &2)
            .unwrap_err()
            .unwrap(),
        GovernanceError::InvalidGuardianSet.into()
    );
}

#[test]
fn test_circuit_breaker_restricts_upgrades_to_at_most_one_per_thirty_day_epoch() {
    let g = setup();
    let mock_target = g.env.register(MockUpgradeTarget, ());

    let upgrade_1 = g.timelock.queue(
        &g.admin,
        &mock_target,
        &ProposalAction::Upgrade(hash(&g.env, 0x01), 2),
        &hash(&g.env, 0x10),
    );
    let upgrade_2 = g.timelock.queue(
        &g.admin,
        &mock_target,
        &ProposalAction::Upgrade(hash(&g.env, 0x02), 2),
        &hash(&g.env, 0x20),
    );

    // Advance 7 days to ETA: first upgrade executes and consumes the 30-day epoch quota.
    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(g.timelock.is_executable(&upgrade_1));
    g.timelock.execute(&g.admin, &upgrade_1);

    let cb_state = g.timelock.get_circuit_breaker_state();
    assert_eq!(cb_state.upgrades_in_epoch, 1);
    assert_eq!(cb_state.max_upgrades_per_epoch, MAX_UPGRADES_PER_EPOCH);
    assert_eq!(
        cb_state.epoch_duration_seconds,
        CIRCUIT_BREAKER_EPOCH_SECONDS
    );

    // Second upgrade within the same 30-day epoch is blocked by the circuit breaker.
    assert!(!g.timelock.is_executable(&upgrade_2));
    let tripped = g
        .timelock
        .try_execute(&g.admin, &upgrade_2)
        .unwrap_err()
        .unwrap();
    assert_eq!(tripped, GovernanceError::CircuitBreakerTripped.into());

    // Queue a third upgrade on day 25 of the epoch so its ETA lands after the 30-day window.
    advance(&g.env, 25 * 86_400);
    let upgrade_3 = g.timelock.queue(
        &g.admin,
        &mock_target,
        &ProposalAction::Upgrade(hash(&g.env, 0x03), 2),
        &hash(&g.env, 0x30),
    );

    // Advance 7 days (total 32 days since upgrade_1 execution): 30-day epoch has rolled over.
    advance(&g.env, MIN_DELAY_SECONDS);
    assert_eq!(g.timelock.get_circuit_breaker_state().upgrades_in_epoch, 0);
    assert!(g.timelock.is_executable(&upgrade_3));
    g.timelock.execute(&g.admin, &upgrade_3);
    assert_eq!(
        g.timelock.get_proposal(&upgrade_3).state,
        ProposalState::Executed
    );
}

#[test]
fn test_emergency_pause_and_time_decayed_post_pause_recovery_prevents_deadlock() {
    let g = setup();
    let mock_target = g.env.register(MockUpgradeTarget, ());

    // Queue a proposal before the emergency pause.
    let prop_id = g.timelock.queue(
        &g.admin,
        &mock_target,
        &ProposalAction::SetUpgradeAdmin(Address::generate(&g.env)),
        &hash(&g.env, 0x44),
    );

    // Guardian triggers emergency pause without admin keys.
    g.timelock
        .emergency_pause(&soroban_sdk::vec![&g.env, g.guardian.clone()]);
    let pause_state = g.timelock.get_pause_state();
    assert!(pause_state.paused);
    assert_eq!(pause_state.paused_at, START);
    assert_eq!(
        pause_state.unwind_starts_at,
        START + MAX_PAUSE_DURATION_SECONDS
    );
    assert_eq!(
        pause_state.recovery_ends_at,
        START + MAX_PAUSE_DURATION_SECONDS + UNWIND_RECOVERY_WINDOW_SECONDS
    );

    // Queueing new proposals during active pause is blocked.
    assert_eq!(
        g.timelock
            .try_queue(
                &g.admin,
                &mock_target,
                &ProposalAction::SetUpgradeAdmin(Address::generate(&g.env)),
                &hash(&g.env, 0x45),
            )
            .unwrap_err()
            .unwrap(),
        GovernanceError::ContractPaused.into()
    );

    // Advance past the 7-day proposal ETA while still inside the 14-day active pause window.
    advance(&g.env, MIN_DELAY_SECONDS);
    assert!(!g.timelock.is_executable(&prop_id));
    assert_eq!(
        g.timelock
            .try_execute(&g.admin, &prop_id)
            .unwrap_err()
            .unwrap(),
        GovernanceError::ContractPaused.into()
    );

    // Advance to the start of the post-pause unwinding window (day 14).
    // Even if the guardian never unpauses, time-decayed recovery begins automatically.
    advance(&g.env, MAX_PAUSE_DURATION_SECONDS - MIN_DELAY_SECONDS);
    assert_eq!(
        g.timelock.get_recovery_surcharge(),
        UNWIND_RECOVERY_WINDOW_SECONDS
    );

    // At the exact start of unwinding (0s waited vs 7d remaining surcharge), execution is
    // still held by the decaying recovery guard.
    assert!(!g.timelock.is_executable(&prop_id));
    assert_eq!(
        g.timelock
            .try_execute(&g.admin, &prop_id)
            .unwrap_err()
            .unwrap(),
        GovernanceError::PostPauseDecayNotElapsed.into()
    );

    // Queueing a new proposal 2 days into the 7-day recovery window receives the linearly
    // decayed surcharge (5 days remaining + 7 days base delay = 12 days).
    advance(&g.env, 2 * 86_400);
    let remaining_surcharge = g.timelock.get_recovery_surcharge();
    assert_eq!(
        remaining_surcharge,
        UNWIND_RECOVERY_WINDOW_SECONDS - 2 * 86_400
    );
    let recovery_prop = g.timelock.queue(
        &g.admin,
        &mock_target,
        &ProposalAction::SetUpgradeAdmin(Address::generate(&g.env)),
        &hash(&g.env, 0x46),
    );
    let queued = g.timelock.get_proposal(&recovery_prop);
    assert_eq!(
        queued.eta,
        queued.queued_at + MIN_DELAY_SECONDS + remaining_surcharge
    );

    // Advance another 1.5 days (total 3.5 days into the 7-day recovery window):
    // time waited since unwind_starts_at (3.5d) >= remaining surcharge (3.5d),
    // and proposal expiry was extended by the pause so `prop_id` executes cleanly.
    advance(&g.env, 86_400 + 43_200);
    assert!(g.timelock.is_executable(&prop_id));
    g.timelock.execute(&g.admin, &prop_id);
    assert_eq!(
        g.timelock.get_proposal(&prop_id).state,
        ProposalState::Executed
    );

    // Advance past the end of the recovery window: surcharge reaches 0.
    advance(&g.env, 4 * 86_400);
    assert_eq!(g.timelock.get_recovery_surcharge(), 0);
}

#[test]
fn test_cooperative_unpause_clears_emergency_pause_immediately() {
    let g = setup();
    g.timelock
        .emergency_pause(&soroban_sdk::vec![&g.env, g.guardian.clone()]);
    assert!(g.timelock.get_pause_state().paused);

    g.timelock.unpause();
    assert!(!g.timelock.get_pause_state().paused);

    // Calling unpause when not paused fails with ContractNotPaused.
    assert_eq!(
        g.timelock.try_unpause().unwrap_err().unwrap(),
        GovernanceError::ContractNotPaused.into()
    );
}

#[cfg(feature = "wasm-tests")]
mod wasm {
    use super::*;

    #[test]
    fn test_full_governance_path_upgrades_the_registry_after_seven_days() {
        let g = setup();

        // Real Phase B history that must survive the upgrade.
        let issuer = Address::generate(&g.env);
        let counterparty = Address::generate(&g.env);
        let commitment_id = g.registry.create_commitment(
            &issuer,
            &counterparty,
            &hash(&g.env, 0x11),
            &(START + 100_000),
            &g.arbitrator,
            &None,
            &None,
            &soroban_sdk::Vec::new(&g.env),
            &0,
        );
        g.registry.attest(
            &issuer,
            &commitment_id,
            &registry::commitments::CommitmentStatus::Fulfilled,
        );
        assert_eq!(g.registry.get_reputation(&issuer).fulfilled_count, 1);

        let id = queue_real_upgrade(&g);

        // Day 6: still refused.
        advance(&g.env, MIN_DELAY_SECONDS - 86_400);
        assert_eq!(
            g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap(),
            Error::TimelockNotElapsed.into()
        );
        assert_eq!(g.registry.schema_version(), 1);

        // Day 7: the upgrade lands.
        advance(&g.env, 86_400);
        g.timelock.execute(&g.admin, &id);
        assert_eq!(g.timelock.get_proposal(&id).state, ProposalState::Executed);

        // The registry's address now runs the new executable, and the Trust Score and
        // commitment written under the old one are both intact.
        let upgraded = fixture_contract::Client::new(&g.env, &g.registry_id);
        assert_eq!(upgraded.fixture_marker(), 0xC0FFEE);
        assert_eq!(upgraded.read_schema_version(), Some(2));
        assert_eq!(
            upgraded
                .read_v1(&issuer)
                .expect("trust score preserved")
                .fulfilled_count,
            1
        );
        assert!(upgraded.read_commitment(&commitment_id).is_some());
    }

    #[test]
    fn test_an_executed_proposal_cannot_be_replayed() {
        let g = setup();
        let id = queue_real_upgrade(&g);
        advance(&g.env, MIN_DELAY_SECONDS);
        g.timelock.execute(&g.admin, &id);

        let err = g.timelock.try_execute(&g.admin, &id).unwrap_err().unwrap();
        assert_eq!(err, Error::ProposalNotQueued.into());
    }

    #[test]
    fn test_an_executed_proposal_cannot_be_cancelled() {
        let g = setup();
        let id = queue_real_upgrade(&g);
        advance(&g.env, MIN_DELAY_SECONDS);
        g.timelock.execute(&g.admin, &id);

        let err = g
            .timelock
            .try_cancel(&g.guardian, &id)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, Error::ProposalNotQueued.into());
    }

    #[test]
    fn test_a_vetoed_upgrade_never_reaches_the_registry() {
        // End to end: the guardian's veto is what makes the review window actionable.
        let g = setup();
        let id = queue_real_upgrade(&g);
        g.timelock.cancel(&g.guardian, &id);

        advance(&g.env, MIN_DELAY_SECONDS);
        assert!(g.timelock.try_execute(&g.admin, &id).is_err());
        // The registry is still running its original executable.
        assert_eq!(g.registry.schema_version(), 1);
        assert_eq!(g.registry.get_arbitrator(), g.arbitrator);
    }
}
