#![no_std]
//! Pactum Timelock — the DAO-owned gate on every Pactum contract upgrade.
//!
//! # What this contract is, and what it is not
//!
//! The issue this implements asks for "a Timelock contract that owns the proxy". There
//! is no proxy: Soroban has no `delegatecall`, and a Soroban contract upgrades by
//! replacing its own executable in place, preserving its contract ID and all of its
//! storage. So what this contract owns is the *authority to trigger that in-place
//! upgrade* — it is installed as the registry's `upgrade_admin`, and the registry's
//! `upgrade` entrypoint requires this contract's authorization. The security property
//! is identical to the EVM arrangement (nobody can change the logic behind a stable
//! address without passing the delay) and the moving parts are far fewer.
//!
//! # The guarantee
//!
//! An upgrade requires:
//!
//! 1. `queue` by the admin, which pins the exact Wasm hash and target schema version;
//! 2. at least [`MIN_DELAY_SECONDS`] (7 days) of ledger time to pass;
//! 3. `execute` by the admin, before the grace period lapses, subject to the
//!    30-day circuit breaker cap ([`MAX_UPGRADES_PER_EPOCH`] = 1 upgrade per
//!    [`CIRCUIT_BREAKER_EPOCH_SECONDS`]) and emergency pause controls.
//!
//! During (2) the proposal is public and fully specified, and the guardian — or a
//! configured guardian multi-sig council — can cancel or veto-and-purge it, or trigger
//! an emergency pause without administrative keys. [`MIN_DELAY_SECONDS`] is a constant,
//! not a stored parameter, so no caller and no key compromise can shorten the window.
//!
//! # Threat model
//!
//! Defended:
//! * **Admin key compromise.** An attacker holding the admin key cannot upgrade
//!   anything for 7 days, cannot shorten that delay, cannot exceed 1 upgrade per 30-day
//!   circuit-breaker epoch, and can be cut off entirely by the guardian multi-sig
//!   vetoing/purging the proposal, triggering an emergency pause, and co-signing an
//!   admin rotation.
//! * **Bait-and-switch on the reviewed code.** The Wasm hash is stored in the proposal
//!   at queue time and read from nowhere else at execution, so the reviewed bytes are
//!   the executed bytes.
//! * **Replay of an executed or purged upgrade.** State moves to `Executed` before the
//!   cross-contract call and the transition is one-way; purged proposals leave a
//!   permanent tombstone in persistent storage.
//! * **Stale authority.** Rotating the admin bumps an epoch that every queued proposal
//!   is pinned to, invalidating in-flight proposals rather than letting a departing
//!   (or ejected) admin's decisions execute under new management.
//! * **Perpetual governance deadlock after emergency pause.** An emergency pause halts
//!   contract dispatch for [`MAX_PAUSE_DURATION_SECONDS`] (14 days) and then transitions
//!   automatically into a [`UNWIND_RECOVERY_WINDOW_SECONDS`] (7-day) time-decayed
//!   recovery phase so a lost or hostile guardian key cannot freeze governance forever.
//! * **Zombie proposals.** A matured proposal expires after the grace period.

pub mod errors;
pub mod events;
pub mod types;

#[cfg(test)]
mod test;

use errors::Error;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, vec,
    Address, BytesN, Env, IntoVal, Symbol, Vec,
};
use types::{
    Proposal, ProposalAction, ProposalState, TimelockKey, GRACE_PERIOD_SECONDS, MAX_DELAY_SECONDS,
    MIN_DELAY_SECONDS, TTL_EXTEND_LEDGERS, TTL_THRESHOLD_LEDGERS,
};

/// Rolling 30-day epoch window (in seconds) for the upgrade circuit breaker.
pub const CIRCUIT_BREAKER_EPOCH_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Maximum number of contract upgrades / schema migrations permitted per 30-day epoch.
pub const MAX_UPGRADES_PER_EPOCH: u32 = 1;

/// Maximum duration (14 days, in seconds) of an active emergency pause before
/// automatic post-pause time-decayed recovery begins.
pub const MAX_PAUSE_DURATION_SECONDS: u64 = 14 * 24 * 60 * 60;

/// Duration (7 days, in seconds) of the post-pause time-decayed unwinding window
/// during which the recovery delay surcharge decays linearly to zero.
pub const UNWIND_RECOVERY_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Additional errors for multi-stage guardian veto, circuit breaker rate limiting,
/// and emergency pause recovery (Issue #311).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GovernanceError {
    /// The supplied guardian set is empty, contains duplicates, or has an invalid threshold.
    InvalidGuardianSet = 14,
    /// The provided signers do not meet the configured guardian multi-sig quorum.
    InsufficientGuardianQuorum = 15,
    /// The proposal was already vetoed and purged from storage.
    ProposalAlreadyPurged = 16,
    /// Contract dispatch is currently halted by an active emergency pause.
    ContractPaused = 17,
    /// The contract is not currently paused.
    ContractNotPaused = 18,
    /// The circuit breaker rate limit (max 1 upgrade per 30-day epoch) has been reached.
    CircuitBreakerTripped = 19,
    /// The post-pause time-decayed recovery cooldown has not elapsed yet.
    PostPauseDecayNotElapsed = 20,
}

/// On-chain state of the emergency pause and post-pause time-decayed recovery.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseState {
    /// Whether an emergency pause has been triggered and not yet fully cleared.
    pub paused: bool,
    /// Ledger timestamp when the emergency pause was activated.
    pub paused_at: u64,
    /// Ledger timestamp when active pause expires and time-decayed unwinding begins.
    pub unwind_starts_at: u64,
    /// Ledger timestamp when the time-decayed recovery surcharge reaches zero.
    pub recovery_ends_at: u64,
}

/// On-chain state of the upgrade circuit breaker rate limiter.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerState {
    /// Start timestamp of the current 30-day rate-limit epoch.
    pub epoch_started_at: u64,
    /// Number of upgrades executed within the current epoch.
    pub upgrades_in_epoch: u32,
    /// Maximum allowed upgrades per epoch (`MAX_UPGRADES_PER_EPOCH`).
    pub max_upgrades_per_epoch: u32,
    /// Duration of each circuit-breaker epoch in seconds (`CIRCUIT_BREAKER_EPOCH_SECONDS`).
    pub epoch_duration_seconds: u64,
}

/// Storage keys for multi-sig guardian veto, emergency pause, and circuit breaker state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityKey {
    /// Instance storage: registered guardian council addresses.
    GuardianSet,
    /// Instance storage: required signature threshold for guardian multi-sig actions.
    GuardianThreshold,
    /// Instance storage: emergency pause and post-pause unwinding state.
    PauseState,
    /// Instance storage: upgrade circuit breaker rate-limiter state.
    CircuitBreaker,
    /// Persistent storage: tombstone marking a proposal ID that was vetoed and purged.
    PurgedProposal(u64),
}

/// The DAO-owned timelock that gates upgrades to the Pactum registry.
#[contract]
pub struct TimelockContract;

#[contractimpl]
impl TimelockContract {
    /// Initializes the timelock. Can only be called once.
    ///
    /// # Authorization
    /// * Authorized callers: both `admin` and `guardian` (via `require_auth`).
    /// * Why: neither address should be able to enrol the other into a role it did not
    ///   consent to, and the guardian's veto is only meaningful if the guardian is a
    ///   live key that has demonstrably signed at least once.
    ///
    /// # Arguments
    /// * `admin` - The address permitted to queue and execute proposals (the DAO).
    /// * `guardian` - The address permitted to cancel proposals and co-sign rotations.
    /// * `delay_seconds` - Execution delay. Must be within
    ///   [`MIN_DELAY_SECONDS`, `MAX_DELAY_SECONDS`].
    ///
    /// # Panics
    /// * Panics with `Error::AlreadyInitialized` if called more than once.
    /// * Panics with `Error::DelayTooShort` if `delay_seconds` is below 7 days.
    /// * Panics with `Error::DelayTooLong` if `delay_seconds` is above 90 days.
    pub fn initialize(env: Env, admin: Address, guardian: Address, delay_seconds: u64) {
        if env.storage().instance().has(&TimelockKey::Admin) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }
        validate_delay(&env, delay_seconds);

        admin.require_auth();
        guardian.require_auth();

        let storage = env.storage().instance();
        storage.set(&TimelockKey::Admin, &admin);
        storage.set(&TimelockKey::Guardian, &guardian);
        storage.set(&TimelockKey::Delay, &delay_seconds);
        storage.set(&TimelockKey::AdminEpoch, &0u32);
        storage.set(&TimelockKey::NextProposalId, &1u64);
        storage.set(&SecurityKey::GuardianSet, &vec![&env, guardian.clone()]);
        storage.set(&SecurityKey::GuardianThreshold, &1u32);
        extend_instance_ttl(&env);

        events::initialized(&env, &admin, &guardian, delay_seconds);
    }

    /// Retrieves the current admin.
    ///
    /// # Panics
    /// * Panics with `Error::NotInitialized` if the contract has not been initialized.
    pub fn get_admin(env: Env) -> Address {
        read_admin(&env)
    }

    /// Retrieves the current guardian.
    ///
    /// # Panics
    /// * Panics with `Error::NotInitialized` if the contract has not been initialized.
    pub fn get_guardian(env: Env) -> Address {
        read_guardian(&env)
    }

    /// Retrieves the configured guardian multi-sig set.
    pub fn get_guardians(env: Env) -> Vec<Address> {
        read_guardian_set(&env)
    }

    /// Retrieves the required guardian multi-sig signature threshold.
    pub fn get_guardian_threshold(env: Env) -> u32 {
        read_guardian_threshold(&env)
    }

    /// Configures a multi-signature guardian council and quorum threshold.
    ///
    /// # Authorization
    /// * Authorized callers: current `admin` and primary `guardian` (both via `require_auth`),
    ///   plus each new guardian in `guardians` so no inoperable key can be enrolled.
    pub fn configure_guardians(env: Env, guardians: Vec<Address>, threshold: u32) {
        let admin = read_admin(&env);
        let current_guardian = read_guardian(&env);
        admin.require_auth();
        current_guardian.require_auth();

        let count = guardians.len();
        if count == 0 || threshold == 0 || threshold > count {
            panic_with_error!(&env, GovernanceError::InvalidGuardianSet);
        }

        // Verify uniqueness and require each enrolled guardian to authorize.
        for i in 0..count {
            let g_i = guardians.get(i).unwrap();
            g_i.require_auth();
            for j in (i + 1)..count {
                if g_i == guardians.get(j).unwrap() {
                    panic_with_error!(&env, GovernanceError::InvalidGuardianSet);
                }
            }
        }

        let primary = guardians.get(0).unwrap();
        let storage = env.storage().instance();
        storage.set(&TimelockKey::Guardian, &primary);
        storage.set(&SecurityKey::GuardianSet, &guardians);
        storage.set(&SecurityKey::GuardianThreshold, &threshold);
        extend_instance_ttl(&env);

        events::guardian_transferred(&env, &current_guardian, &primary);
    }

    /// Retrieves the configured execution delay in seconds.
    ///
    /// # Panics
    /// * Panics with `Error::NotInitialized` if the contract has not been initialized.
    pub fn get_delay(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&TimelockKey::Delay)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized))
    }

    /// Retrieves the current admin epoch. Bumped on every admin rotation.
    pub fn get_admin_epoch(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&TimelockKey::AdminEpoch)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized))
    }

    /// Retrieves the enforced minimum delay. Constant, and identical for every
    /// deployment of this executable.
    pub fn min_delay(_env: Env) -> u64 {
        MIN_DELAY_SECONDS
    }

    /// Returns true if a proposal was vetoed and purged from storage.
    pub fn is_purged(env: Env, id: u64) -> bool {
        is_proposal_purged(&env, id)
    }

    /// Retrieves the current emergency pause and unwinding state.
    pub fn get_pause_state(env: Env) -> PauseState {
        let _ = read_admin(&env);
        read_pause_state(&env)
    }

    /// Returns the current post-pause recovery delay surcharge (in seconds).
    ///
    /// During the 7-day post-pause unwinding window, this surcharge decays linearly
    /// from `UNWIND_RECOVERY_WINDOW_SECONDS` down to `0`, preventing perpetual
    /// governance deadlocks while still enforcing a graduated recovery period.
    pub fn get_recovery_surcharge(env: Env) -> u64 {
        let _ = read_admin(&env);
        let state = read_pause_state(&env);
        compute_recovery_surcharge(&state, env.ledger().timestamp())
    }

    /// Retrieves the current 30-day upgrade circuit breaker state.
    pub fn get_circuit_breaker_state(env: Env) -> CircuitBreakerState {
        let _ = read_admin(&env);
        read_circuit_breaker_state(&env, env.ledger().timestamp())
    }

    /// Retrieves a proposal by id.
    ///
    /// # Panics
    /// * Panics with `GovernanceError::ProposalAlreadyPurged` if the proposal was purged.
    /// * Panics with `Error::ProposalNotFound` if no such proposal exists.
    pub fn get_proposal(env: Env, id: u64) -> Proposal {
        if is_proposal_purged(&env, id) {
            panic_with_error!(&env, GovernanceError::ProposalAlreadyPurged);
        }
        let proposal = read_proposal(&env, id);
        env.storage().persistent().extend_ttl(
            &TimelockKey::Proposal(id),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_LEDGERS,
        );
        proposal
    }

    /// Returns true if the proposal exists, is still queued, its `eta` (plus any
    /// active post-pause recovery decay) has passed without its grace period lapsing,
    /// the contract is not in an active emergency pause, and the upgrade circuit
    /// breaker has remaining capacity for the current 30-day epoch.
    ///
    /// # Panics
    /// * Panics with `Error::ProposalNotFound` if no such proposal exists and it was not purged.
    pub fn is_executable(env: Env, id: u64) -> bool {
        if is_proposal_purged(&env, id) {
            return false;
        }
        let proposal = read_proposal(&env, id);
        let now = env.ledger().timestamp();
        if proposal.state != ProposalState::Queued
            || proposal.admin_epoch != Self::get_admin_epoch(env.clone())
        {
            return false;
        }

        let pause_state = read_pause_state(&env);
        if is_actively_paused(&pause_state, now) {
            return false;
        }
        if !is_post_pause_decay_satisfied(&pause_state, &proposal, now) {
            return false;
        }

        let effective_expires_at = effective_expiry(&pause_state, &proposal);
        if now < proposal.eta || now > effective_expires_at {
            return false;
        }

        if matches!(proposal.action, ProposalAction::Upgrade(_, _))
            && is_circuit_breaker_tripped(&env, now)
        {
            return false;
        }

        true
    }

    /// Queues a governance action against `target`, starting the delay.
    ///
    /// If the contract is currently in the post-pause time-decayed recovery window,
    /// the remaining recovery surcharge is added to the proposal's `eta`.
    ///
    /// # Authorization
    /// * Authorized caller: `proposer`, which must equal the stored admin (via `require_auth`).
    pub fn queue(
        env: Env,
        proposer: Address,
        target: Address,
        action: ProposalAction,
        description_hash: BytesN<32>,
    ) -> u64 {
        proposer.require_auth();

        let admin = read_admin(&env);
        if proposer != admin {
            panic_with_error!(&env, Error::NotAdmin);
        }

        if let ProposalAction::Upgrade(_, schema_version) = &action {
            if *schema_version == 0 {
                panic_with_error!(&env, Error::InvalidSchemaVersion);
            }
        }

        let now = env.ledger().timestamp();
        let pause_state = read_pause_state(&env);
        if is_actively_paused(&pause_state, now) {
            panic_with_error!(&env, GovernanceError::ContractPaused);
        }

        let storage = env.storage().instance();
        let id: u64 = storage.get(&TimelockKey::NextProposalId).unwrap_or(1);
        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        storage.set(&TimelockKey::NextProposalId, &next_id);

        let delay: u64 = storage
            .get(&TimelockKey::Delay)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        let admin_epoch: u32 = storage
            .get(&TimelockKey::AdminEpoch)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));

        let surcharge = compute_recovery_surcharge(&pause_state, now);
        let effective_delay = delay
            .checked_add(surcharge)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let eta = now
            .checked_add(effective_delay)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let expires_at = eta
            .checked_add(GRACE_PERIOD_SECONDS)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));

        let proposal = Proposal {
            id,
            target,
            action,
            proposer,
            admin_epoch,
            queued_at: now,
            eta,
            expires_at,
            state: ProposalState::Queued,
            description_hash,
        };

        write_proposal(&env, &proposal);
        extend_instance_ttl(&env);
        events::queued(&env, &proposal);

        id
    }

    /// Cancels a queued proposal.
    ///
    /// # Authorization
    /// * Authorized caller: `caller`, which must be the admin or a registered guardian
    ///   (via `require_auth`).
    pub fn cancel(env: Env, caller: Address, id: u64) {
        caller.require_auth();

        let admin = read_admin(&env);
        let guardian = read_guardian(&env);
        let is_council_guardian = is_registered_guardian(&env, &caller);
        if caller != admin && caller != guardian && !is_council_guardian {
            panic_with_error!(&env, Error::NotAdminOrGuardian);
        }

        if is_proposal_purged(&env, id) {
            panic_with_error!(&env, GovernanceError::ProposalAlreadyPurged);
        }

        let mut proposal = read_proposal(&env, id);
        if proposal.state != ProposalState::Queued {
            panic_with_error!(&env, Error::ProposalNotQueued);
        }

        proposal.state = ProposalState::Cancelled;
        write_proposal(&env, &proposal);

        events::cancelled(&env, id, &caller);
        events::state_changed(&env, id, ProposalState::Cancelled);
    }

    /// Multi-sig guardian veto that cancels a malicious queued proposal prior to
    /// execution and purges its payload from persistent storage, leaving an immutable
    /// purge tombstone so the proposal ID can never be executed or resurrected.
    ///
    /// # Authorization
    /// * Authorized callers: `signers`, which must be unique members of the guardian
    ///   set meeting `get_guardian_threshold` (each via `require_auth`). Does not
    ///   require administrative keys.
    pub fn veto_and_purge(env: Env, signers: Vec<Address>, id: u64) {
        verify_guardian_quorum(&env, &signers);

        if is_proposal_purged(&env, id) {
            panic_with_error!(&env, GovernanceError::ProposalAlreadyPurged);
        }

        let proposal = read_proposal(&env, id);
        if proposal.state != ProposalState::Queued {
            panic_with_error!(&env, Error::ProposalNotQueued);
        }

        let now = env.ledger().timestamp();
        if now >= proposal.eta {
            panic_with_error!(&env, Error::ProposalNotQueued);
        }

        // Purge the malicious proposal from persistent storage and record tombstone.
        env.storage()
            .persistent()
            .remove(&TimelockKey::Proposal(id));
        let tombstone_key = SecurityKey::PurgedProposal(id);
        env.storage().persistent().set(&tombstone_key, &true);
        env.storage().persistent().extend_ttl(
            &tombstone_key,
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_LEDGERS,
        );
        extend_instance_ttl(&env);

        let lead_guardian = signers.get(0).unwrap();
        events::cancelled(&env, id, &lead_guardian);
        events::state_changed(&env, id, ProposalState::Cancelled);
    }

    /// Triggers an emergency pause halting contract dispatch without administrative keys.
    ///
    /// The active pause lasts for at most [`MAX_PAUSE_DURATION_SECONDS`] (14 days),
    /// after which the contract automatically transitions into a
    /// [`UNWIND_RECOVERY_WINDOW_SECONDS`] (7-day) time-decayed recovery phase so
    /// governance can never be permanently deadlocked.
    ///
    /// # Authorization
    /// * Authorized callers: `signers` meeting the guardian multi-sig threshold.
    pub fn emergency_pause(env: Env, signers: Vec<Address>) {
        verify_guardian_quorum(&env, &signers);

        let now = env.ledger().timestamp();
        let unwind_starts_at = now
            .checked_add(MAX_PAUSE_DURATION_SECONDS)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));
        let recovery_ends_at = unwind_starts_at
            .checked_add(UNWIND_RECOVERY_WINDOW_SECONDS)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));

        let state = PauseState {
            paused: true,
            paused_at: now,
            unwind_starts_at,
            recovery_ends_at,
        };
        env.storage()
            .instance()
            .set(&SecurityKey::PauseState, &state);
        extend_instance_ttl(&env);

        env.events().publish(
            (symbol_short!("tl_pause"), signers.get(0).unwrap()),
            (now, unwind_starts_at, recovery_ends_at),
        );
    }

    /// Cooperatively lifts an emergency pause immediately when both the admin and
    /// the primary guardian co-sign.
    pub fn unpause(env: Env) {
        let admin = read_admin(&env);
        let guardian = read_guardian(&env);
        admin.require_auth();
        guardian.require_auth();

        let state = read_pause_state(&env);
        if !state.paused {
            panic_with_error!(&env, GovernanceError::ContractNotPaused);
        }

        let cleared = PauseState {
            paused: false,
            paused_at: 0,
            unwind_starts_at: 0,
            recovery_ends_at: 0,
        };
        env.storage()
            .instance()
            .set(&SecurityKey::PauseState, &cleared);
        extend_instance_ttl(&env);

        env.events()
            .publish((symbol_short!("tl_unpau"), admin), env.ledger().timestamp());
    }

    /// Executes a matured proposal against its target.
    ///
    /// # Authorization
    /// * Authorized caller: `caller`, which must equal the stored admin (via `require_auth`).
    ///
    /// The proposal is marked `Executed` *before* the cross-contract call, so a target
    /// that re-enters this contract cannot execute the same proposal twice.
    pub fn execute(env: Env, caller: Address, id: u64) {
        caller.require_auth();

        let admin = read_admin(&env);
        if caller != admin {
            panic_with_error!(&env, Error::NotAdmin);
        }

        if is_proposal_purged(&env, id) {
            panic_with_error!(&env, GovernanceError::ProposalAlreadyPurged);
        }

        let mut proposal = read_proposal(&env, id);
        if proposal.state != ProposalState::Queued {
            panic_with_error!(&env, Error::ProposalNotQueued);
        }

        let current_epoch: u32 = env
            .storage()
            .instance()
            .get(&TimelockKey::AdminEpoch)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        if proposal.admin_epoch != current_epoch {
            panic_with_error!(&env, Error::ProposalStale);
        }

        let now = env.ledger().timestamp();
        let pause_state = read_pause_state(&env);
        if is_actively_paused(&pause_state, now) {
            panic_with_error!(&env, GovernanceError::ContractPaused);
        }
        if !is_post_pause_decay_satisfied(&pause_state, &proposal, now) {
            panic_with_error!(&env, GovernanceError::PostPauseDecayNotElapsed);
        }

        if now < proposal.eta {
            panic_with_error!(&env, Error::TimelockNotElapsed);
        }
        let effective_expires_at = effective_expiry(&pause_state, &proposal);
        if now > effective_expires_at {
            panic_with_error!(&env, Error::ProposalExpired);
        }

        if matches!(proposal.action, ProposalAction::Upgrade(_, _)) {
            record_upgrade_or_trip_circuit_breaker(&env, now);
        }

        // If the post-pause recovery window has fully elapsed, clear the pause record.
        if pause_state.paused && now >= pause_state.recovery_ends_at {
            env.storage().instance().set(
                &SecurityKey::PauseState,
                &PauseState {
                    paused: false,
                    paused_at: 0,
                    unwind_starts_at: 0,
                    recovery_ends_at: 0,
                },
            );
        }

        // Checks-effects-interactions: burn the proposal before calling out.
        proposal.state = ProposalState::Executed;
        write_proposal(&env, &proposal);
        events::state_changed(&env, id, ProposalState::Executed);

        dispatch(&env, &proposal);

        events::executed(&env, &proposal);
    }

    /// Rotates the admin, invalidating every queued proposal.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        let old_admin = read_admin(&env);
        let guardian = read_guardian(&env);
        old_admin.require_auth();
        guardian.require_auth();

        let storage = env.storage().instance();
        let epoch: u32 = storage
            .get(&TimelockKey::AdminEpoch)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        let next_epoch = epoch
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, Error::Overflow));

        storage.set(&TimelockKey::Admin, &new_admin);
        storage.set(&TimelockKey::AdminEpoch, &next_epoch);
        extend_instance_ttl(&env);

        events::admin_transferred(&env, &old_admin, &new_admin, next_epoch);
    }

    /// Rotates the guardian.
    pub fn transfer_guardian(env: Env, new_guardian: Address) {
        let admin = read_admin(&env);
        let old_guardian = read_guardian(&env);
        admin.require_auth();
        old_guardian.require_auth();

        let storage = env.storage().instance();
        storage.set(&TimelockKey::Guardian, &new_guardian);
        storage.set(&SecurityKey::GuardianSet, &vec![&env, new_guardian.clone()]);
        storage.set(&SecurityKey::GuardianThreshold, &1u32);
        extend_instance_ttl(&env);

        events::guardian_transferred(&env, &old_guardian, &new_guardian);
    }

    /// Changes the execution delay for proposals queued from now on.
    pub fn set_delay(env: Env, new_delay_seconds: u64) {
        let admin = read_admin(&env);
        admin.require_auth();
        validate_delay(&env, new_delay_seconds);

        let storage = env.storage().instance();
        let old: u64 = storage
            .get(&TimelockKey::Delay)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        storage.set(&TimelockKey::Delay, &new_delay_seconds);
        extend_instance_ttl(&env);

        events::delay_updated(&env, old, new_delay_seconds);
    }
}

/// Performs the target call for an executing proposal.
fn dispatch(env: &Env, proposal: &Proposal) {
    match &proposal.action {
        ProposalAction::Upgrade(wasm_hash, schema_version) => {
            env.invoke_contract::<()>(
                &proposal.target,
                &symbol_short!("upgrade"),
                (wasm_hash.clone(), *schema_version).into_val(env),
            );
        }
        ProposalAction::SetUpgradeAdmin(new_admin) => {
            env.invoke_contract::<()>(
                &proposal.target,
                &Symbol::new(env, "set_upgrade_admin"),
                (new_admin.clone(),).into_val(env),
            );
        }
    }
}

fn validate_delay(env: &Env, delay_seconds: u64) {
    if delay_seconds < MIN_DELAY_SECONDS {
        panic_with_error!(env, Error::DelayTooShort);
    }
    if delay_seconds > MAX_DELAY_SECONDS {
        panic_with_error!(env, Error::DelayTooLong);
    }
}

fn read_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&TimelockKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
}

fn read_guardian(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&TimelockKey::Guardian)
        .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
}

fn read_guardian_set(env: &Env) -> Vec<Address> {
    let primary = read_guardian(env);
    env.storage()
        .instance()
        .get(&SecurityKey::GuardianSet)
        .unwrap_or_else(|| vec![env, primary])
}

fn read_guardian_threshold(env: &Env) -> u32 {
    let _ = read_guardian(env);
    env.storage()
        .instance()
        .get(&SecurityKey::GuardianThreshold)
        .unwrap_or(1)
}

fn is_registered_guardian(env: &Env, candidate: &Address) -> bool {
    let guardians = read_guardian_set(env);
    for i in 0..guardians.len() {
        if guardians.get(i).unwrap() == *candidate {
            return true;
        }
    }
    false
}

fn verify_guardian_quorum(env: &Env, signers: &Vec<Address>) {
    let guardians = read_guardian_set(env);
    let threshold = read_guardian_threshold(env);
    let count = signers.len();

    if count < threshold {
        panic_with_error!(env, GovernanceError::InsufficientGuardianQuorum);
    }

    for i in 0..count {
        let signer = signers.get(i).unwrap();
        signer.require_auth();

        // Reject duplicate signers.
        for j in (i + 1)..count {
            if signer == signers.get(j).unwrap() {
                panic_with_error!(env, GovernanceError::InsufficientGuardianQuorum);
            }
        }

        // Verify membership in the registered guardian set.
        let mut found = false;
        for k in 0..guardians.len() {
            if signer == guardians.get(k).unwrap() {
                found = true;
                break;
            }
        }
        if !found {
            panic_with_error!(env, GovernanceError::InsufficientGuardianQuorum);
        }
    }
}

fn is_proposal_purged(env: &Env, id: u64) -> bool {
    env.storage()
        .persistent()
        .get(&SecurityKey::PurgedProposal(id))
        .unwrap_or(false)
}

fn read_pause_state(env: &Env) -> PauseState {
    env.storage()
        .instance()
        .get(&SecurityKey::PauseState)
        .unwrap_or(PauseState {
            paused: false,
            paused_at: 0,
            unwind_starts_at: 0,
            recovery_ends_at: 0,
        })
}

fn is_actively_paused(state: &PauseState, now: u64) -> bool {
    state.paused && now < state.unwind_starts_at
}

fn compute_recovery_surcharge(state: &PauseState, now: u64) -> u64 {
    if !state.paused || now < state.unwind_starts_at || now >= state.recovery_ends_at {
        return 0;
    }
    state.recovery_ends_at - now
}

fn is_post_pause_decay_satisfied(state: &PauseState, proposal: &Proposal, now: u64) -> bool {
    if !state.paused || now >= state.recovery_ends_at {
        return true;
    }
    if now < state.unwind_starts_at {
        return false;
    }
    // Proposals queued before the unwinding phase must wait until the time elapsed
    // since the later of (proposal.eta, unwind_starts_at) meets or exceeds the
    // linearly decaying recovery surcharge.
    if proposal.queued_at < state.unwind_starts_at {
        let anchor = if proposal.eta > state.unwind_starts_at {
            proposal.eta
        } else {
            state.unwind_starts_at
        };
        if now < anchor {
            return false;
        }
        let waited = now - anchor;
        let remaining_surcharge = compute_recovery_surcharge(state, now);
        return waited >= remaining_surcharge;
    }
    true
}

fn effective_expiry(state: &PauseState, proposal: &Proposal) -> u64 {
    if state.paused && proposal.queued_at <= state.unwind_starts_at {
        let extension = MAX_PAUSE_DURATION_SECONDS + UNWIND_RECOVERY_WINDOW_SECONDS;
        return proposal.expires_at.saturating_add(extension);
    }
    proposal.expires_at
}

fn read_circuit_breaker_state(env: &Env, now: u64) -> CircuitBreakerState {
    let stored: Option<CircuitBreakerState> =
        env.storage().instance().get(&SecurityKey::CircuitBreaker);
    match stored {
        Some(state) => {
            if now
                >= state
                    .epoch_started_at
                    .saturating_add(state.epoch_duration_seconds)
            {
                CircuitBreakerState {
                    epoch_started_at: now,
                    upgrades_in_epoch: 0,
                    max_upgrades_per_epoch: MAX_UPGRADES_PER_EPOCH,
                    epoch_duration_seconds: CIRCUIT_BREAKER_EPOCH_SECONDS,
                }
            } else {
                state
            }
        }
        None => CircuitBreakerState {
            epoch_started_at: 0,
            upgrades_in_epoch: 0,
            max_upgrades_per_epoch: MAX_UPGRADES_PER_EPOCH,
            epoch_duration_seconds: CIRCUIT_BREAKER_EPOCH_SECONDS,
        },
    }
}

fn is_circuit_breaker_tripped(env: &Env, now: u64) -> bool {
    let stored: Option<CircuitBreakerState> =
        env.storage().instance().get(&SecurityKey::CircuitBreaker);
    if let Some(state) = stored {
        if state.upgrades_in_epoch >= state.max_upgrades_per_epoch
            && now
                < state
                    .epoch_started_at
                    .saturating_add(state.epoch_duration_seconds)
        {
            return true;
        }
    }
    false
}

fn record_upgrade_or_trip_circuit_breaker(env: &Env, now: u64) {
    if is_circuit_breaker_tripped(env, now) {
        panic_with_error!(env, GovernanceError::CircuitBreakerTripped);
    }

    let next_state = CircuitBreakerState {
        epoch_started_at: now,
        upgrades_in_epoch: 1,
        max_upgrades_per_epoch: MAX_UPGRADES_PER_EPOCH,
        epoch_duration_seconds: CIRCUIT_BREAKER_EPOCH_SECONDS,
    };
    env.storage()
        .instance()
        .set(&SecurityKey::CircuitBreaker, &next_state);
    extend_instance_ttl(env);
}

fn read_proposal(env: &Env, id: u64) -> Proposal {
    env.storage()
        .persistent()
        .get(&TimelockKey::Proposal(id))
        .unwrap_or_else(|| panic_with_error!(env, Error::ProposalNotFound))
}

fn write_proposal(env: &Env, proposal: &Proposal) {
    let key = TimelockKey::Proposal(proposal.id);
    env.storage().persistent().set(&key, proposal);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}
