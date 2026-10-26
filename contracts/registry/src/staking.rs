//! Attestor staking vault (Issue 86, Phase 1).
//!
//! Replaces the single-arbitrator dispute model with a cryptoeconomic one:
//! attestors lock the staking asset into this contract, and their stake backs
//! the votes they cast on disputed commitments (voting arrives in a later
//! phase). This module implements the vault itself — deposit, a 14-day
//! unbonding period on unstake, and withdrawal — plus the `locked` flag the
//! voting phase sets while an attestor serves on an active dispute panel.

use crate::commitments::{DataKey, TTL_EXTEND_LEDGERS, TTL_THRESHOLD_LEDGERS};
use crate::errors::Error;
use crate::{events, reentrancy};
use soroban_sdk::{
    contracttype, panic_with_error, token::TokenClient, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

/// The unbonding period in seconds (14 days = 1,209,600 seconds). A requested
/// unstake becomes withdrawable only after this period has elapsed.
pub const UNBONDING_PERIOD_SECONDS: u64 = 14 * 24 * 60 * 60;

/// The staking record for a single attestor address.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestorStake {
    /// Total amount locked by the attestor, in units of the staking asset.
    pub staked: i128,
    /// Unix timestamp (seconds) after which a requested unstake can be
    /// finalized. `None` while no unstake has been requested.
    pub unbonding_until: Option<u64>,
    /// Set while the attestor serves on an active dispute panel; both
    /// unstake requests and withdrawals are rejected until the dispute
    /// resolves and the flag is cleared by the voting phase.
    pub locked: bool,
}

/// Loads the staking record for an attestor, defaulting to a zeroed record.
/// `pub(crate)` so the voting phase can check stake eligibility.
pub(crate) fn load_stake(env: &Env, attestor: &Address) -> AttestorStake {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(attestor.clone()))
        .unwrap_or(AttestorStake {
            staked: 0,
            unbonding_until: None,
            locked: false,
        })
}

/// Persists a staking record and extends its TTL.
fn save_stake(env: &Env, attestor: &Address, stake: &AttestorStake) {
    env.storage()
        .persistent()
        .set(&DataKey::Stake(attestor.clone()), stake);
    env.storage().persistent().extend_ttl(
        &DataKey::Stake(attestor.clone()),
        TTL_THRESHOLD_LEDGERS,
        TTL_EXTEND_LEDGERS,
    );
}

/// Sets the dispute-panel lock on an attestor's stake. Called by the voting
/// phase when the attestor joins an active dispute panel, and cleared again
/// when the dispute resolves. Missing records are left untouched.
pub(crate) fn set_locked(env: &Env, attestor: &Address, locked: bool) {
    let mut stake = load_stake(env, attestor);
    if stake.staked == 0 {
        return;
    }
    if stake.locked == locked {
        return;
    }
    stake.locked = locked;
    save_stake(env, attestor, &stake);
}

/// Reduces an attestor's staked amount by `percent` percent of its current
/// value, leaving the forfeited amount in the vault. Called by the voting
/// phase to slash dissenting attestors when a dispute resolves.
///
/// Arithmetic is delegated to [`crate::economics::slash_cut`] so the same
/// checked math is what Issue #192 formal proofs discharge.
pub(crate) fn slash(env: &Env, attestor: &Address, percent: u64) {
    let mut stake = load_stake(env, attestor);
    let Some(cut) = crate::economics::slash_cut(stake.staked, percent) else {
        panic_with_error!(env, Error::Overflow);
    };
    if cut.cut <= 0 {
        return;
    }
    stake.staked = cut.remaining;
    save_stake(env, attestor, &stake);
}

/// Returns the configured staking asset, or panics if none has been installed.
fn staking_token(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::StakingToken)
        .unwrap_or_else(|| panic_with_error!(env, Error::StakingTokenNotSet))
}

/// Installs the asset used for attestor staking. One-time, mirroring
/// `initialize`.
///
/// # Authorization
/// * Authorized caller: the designated `arbitrator` (via `require_auth`), the
///   current root authority of the contract (see `init_upgrade_admin`).
///
/// # Panics
/// * Panics with `Error::NotInitialized` if the contract has not been initialized.
/// * Panics with `Error::AlreadyInitialized` if a staking asset is already set.
pub fn set_staking_token(env: &Env, caller: Address, token: Address) {
    reentrancy::enter(env);
    caller.require_auth();

    let arbitrators = crate::commitments::arbitrators(env);
    if !arbitrators.contains(&caller) {
        panic_with_error!(env, Error::NotArbitrator);
    }
    if env.storage().instance().has(&DataKey::StakingToken) {
        panic_with_error!(env, Error::AlreadyInitialized);
    }

    env.storage().instance().set(&DataKey::StakingToken, &token);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);

    reentrancy::exit(env);
}

/// Locks `amount` of the staking asset from `attestor` into the contract vault.
///
/// # Authorization
/// * Authorized caller: `attestor` (via `require_auth`).
///
/// # Panics
/// * Panics with `Error::StakingTokenNotSet` if no staking asset is configured.
/// * Panics with `Error::ZeroAmount` if `amount` is not strictly positive.
/// * Panics with `Error::Overflow` if the attestor's stake would overflow.
pub fn stake_attestor(env: &Env, attestor: Address, amount: i128) {
    // 0. Enter the reentrancy guard before any external interaction (including
    //    the require_auth call below, which may invoke a custom account contract).
    reentrancy::enter(env);

    // 1. Require authorization from the attestor.
    attestor.require_auth();

    // 2. Reject non-positive amounts.
    if amount <= 0 {
        panic_with_error!(env, Error::ZeroAmount);
    }

    // 3. Resolve the staking asset.
    let token = staking_token(env);

    // 4. Update accounting before the external transfer (CEI): the transfer
    //    is the last interaction and can never observe half-updated state.
    let mut stake = load_stake(env, &attestor);
    stake.staked = stake
        .staked
        .checked_add(amount)
        .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
    save_stake(env, &attestor, &stake);
    register_in_staked_pool(env, &attestor);

    // 5. Transfer the asset from the attestor into the contract vault.
    let client = TokenClient::new(env, &token);
    client.transfer(&attestor, &env.current_contract_address(), &amount);

    // 6. Emit the staked event.
    events::staked(env, &attestor, amount);

    // 7. Release the reentrancy guard.
    reentrancy::exit(env);
}

/// Requests an unstake, starting the 14-day unbonding period.
///
/// While an attestor's stake is locked for an active dispute panel, unstakes
/// are rejected so the voting phase can rely on the locked balance.
///
/// # Authorization
/// * Authorized caller: `attestor` (via `require_auth`).
///
/// # Panics
/// * Panics with `Error::InsufficientStake` if the attestor has no stake.
/// * Panics with `Error::DisputeActive` if the attestor's stake is locked.
/// * Panics with `Error::UnbondingPending` if an unstake is already in progress.
/// * Panics with `Error::Overflow` on timestamp arithmetic overflow.
pub fn request_unstake(env: &Env, attestor: Address) {
    // 0. Enter the reentrancy guard before any external interaction.
    reentrancy::enter(env);

    // 1. Require authorization from the attestor.
    attestor.require_auth();

    // 2. Load the staking record and validate the request.
    let mut stake = load_stake(env, &attestor);
    if stake.staked <= 0 {
        panic_with_error!(env, Error::InsufficientStake);
    }
    if stake.locked {
        panic_with_error!(env, Error::DisputeActive);
    }
    if stake.unbonding_until.is_some() {
        panic_with_error!(env, Error::UnbondingPending);
    }

    // 3. Start the unbonding period.
    let now = env.ledger().timestamp();
    stake.unbonding_until = Some(
        now.checked_add(UNBONDING_PERIOD_SECONDS)
            .unwrap_or_else(|| panic_with_error!(env, Error::Overflow)),
    );
    save_stake(env, &attestor, &stake);

    // 4. Emit the unstake request event.
    events::unstake_requested(env, &attestor, stake.unbonding_until.unwrap());

    // 5. Release the reentrancy guard.
    reentrancy::exit(env);
}

/// Finalizes a requested unstake: withdraws the full staked balance back to
/// the attestor once the unbonding period has elapsed.
///
/// # Authorization
/// * Authorized caller: `attestor` (via `require_auth`).
///
/// # Panics
/// * Panics with `Error::InsufficientStake` if no unstake was requested.
/// * Panics with `Error::UnbondingNotElapsed` if the unbonding period has not
///   fully elapsed.
/// * Panics with `Error::DisputeActive` if the attestor's stake is locked.
pub fn finalize_unstake(env: &Env, attestor: Address) {
    // 0. Enter the reentrancy guard before any external interaction (including
    //    the token transfer below, which invokes the staking asset contract).
    reentrancy::enter(env);

    // 1. Require authorization from the attestor.
    attestor.require_auth();

    // 2. Load the staking record and validate the withdrawal.
    let stake = load_stake(env, &attestor);
    let unbonding_until = stake
        .unbonding_until
        .unwrap_or_else(|| panic_with_error!(env, Error::InsufficientStake));
    let now = env.ledger().timestamp();
    if now < unbonding_until {
        panic_with_error!(env, Error::UnbondingNotElapsed);
    }
    if stake.locked {
        panic_with_error!(env, Error::DisputeActive);
    }

    // 3. Clear the record before the external transfer (CEI): the transfer is
    //    the last interaction and can never observe half-updated state.
    let amount = stake.staked;
    env.storage()
        .persistent()
        .remove(&DataKey::Stake(attestor.clone()));
    unregister_from_staked_pool(env, &attestor);

    // 4. Transfer the asset from the contract vault back to the attestor.
    let token = staking_token(env);
    let client = TokenClient::new(env, &token);
    client.transfer(&env.current_contract_address(), &attestor, &amount);

    // 5. Emit the unstaked event.
    events::unstaked(env, &attestor, amount);

    // 6. Release the reentrancy guard.
    reentrancy::exit(env);
}

/// Retrieves the staking record for an attestor (zeroed if it has never staked).
pub fn get_stake_info(env: &Env, attestor: Address) -> AttestorStake {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Stake(attestor.clone()))
    {
        env.storage().persistent().extend_ttl(
            &DataKey::Stake(attestor.clone()),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_LEDGERS,
        );
    }
    load_stake(env, &attestor)
}

/// Ensures `attestor` is recorded in the ordered active staked attestor pool (`DataKey::StakedAttestorPool`).
fn register_in_staked_pool(env: &Env, attestor: &Address) {
    let mut pool: Vec<Address> = env
        .storage()
        .instance()
        .get(&DataKey::StakedAttestorPool)
        .unwrap_or_else(|| Vec::new(env));
    if !pool.contains(attestor) {
        pool.push_back(attestor.clone());
        env.storage()
            .instance()
            .set(&DataKey::StakedAttestorPool, &pool);
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
    }
}

/// Removes `attestor` from the ordered active staked attestor pool (`DataKey::StakedAttestorPool`).
fn unregister_from_staked_pool(env: &Env, attestor: &Address) {
    let pool: Vec<Address> = env
        .storage()
        .instance()
        .get(&DataKey::StakedAttestorPool)
        .unwrap_or_else(|| Vec::new(env));
    let mut updated = Vec::new(env);
    for addr in pool.iter() {
        if addr != *attestor {
            updated.push_back(addr);
        }
    }
    env.storage()
        .instance()
        .set(&DataKey::StakedAttestorPool, &updated);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}

/// Returns all currently eligible staked attestors `(address, staked_balance)` from the
/// registry pool who have positive stake, are not unbonding, and are not conflicted
/// commitment parties (`exclude_issuer` or `exclude_counterparty`).
pub fn active_staked_attestors(
    env: &Env,
    exclude_issuer: &Address,
    exclude_counterparty: &Address,
) -> Vec<(Address, i128)> {
    let pool: Vec<Address> = env
        .storage()
        .instance()
        .get(&DataKey::StakedAttestorPool)
        .unwrap_or_else(|| Vec::new(env));
    let mut active = Vec::new(env);
    for addr in pool.iter() {
        if addr == *exclude_issuer || addr == *exclude_counterparty {
            continue;
        }
        let stake = load_stake(env, &addr);
        if stake.staked > 0 && stake.unbonding_until.is_none() {
            active.push_back((addr, stake.staked));
        }
    }
    active
}

/// Derives a verifiable random function (VRF) seed for dispute committee selection
/// using Stellar ledger state (`sequence`, `timestamp`, `network_id`) combined with
/// commitment-specific dispute declaration parameters (`commitment_id`, `issuer`,
/// `counterparty`, `terms_hash`, `declaration_entropy`).
///
/// Because `env.ledger().sequence()` and `env.ledger().timestamp()` are fixed by
/// Stellar consensus only when the dispute transaction is included in a ledger block,
/// parties cannot pre-compute or manipulate the resulting committee prior to the
/// dispute declaration block sequence.
pub fn derive_vrf_dispute_seed(
    env: &Env,
    commitment_id: u64,
    issuer: &Address,
    counterparty: &Address,
    terms_hash: &BytesN<32>,
    declaration_entropy: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, b"PACTUM_VRF_DISPUTE_SEED_V1");
    preimage.extend_from_array(&env.ledger().sequence().to_be_bytes());
    preimage.extend_from_array(&env.ledger().timestamp().to_be_bytes());
    preimage.extend_from_array(&env.ledger().network_id().to_array());
    preimage.extend_from_array(&commitment_id.to_be_bytes());
    preimage.append(&issuer.to_xdr(env));
    preimage.append(&counterparty.to_xdr(env));
    preimage.extend_from_array(&terms_hash.to_array());
    preimage.extend_from_array(&declaration_entropy.to_array());
    env.crypto().sha256(&preimage).into()
}

/// Samples a uniform random integer in `[0, bound)` without modulo bias using
/// rejection sampling over SHA-256 counter-mode blocks derived from `vrf_seed`.
fn sample_unbiased_u128(env: &Env, vrf_seed: &BytesN<32>, round: u32, bound: u128) -> u128 {
    if bound <= 1 {
        return 0;
    }
    // Largest multiple of `bound` that fits in `u128::MAX` to eliminate modulo bias.
    let zone = u128::MAX - (u128::MAX % bound);
    let mut attempt: u32 = 0;
    loop {
        let mut block = Bytes::from_slice(env, b"PACTUM_VRF_DRAW_V1");
        block.extend_from_array(&vrf_seed.to_array());
        block.extend_from_array(&round.to_be_bytes());
        block.extend_from_array(&attempt.to_be_bytes());
        let digest: BytesN<32> = env.crypto().sha256(&block).into();
        let arr = digest.to_array();
        let mut raw_bytes = [0u8; 16];
        raw_bytes.copy_from_slice(&arr[0..16]);
        let candidate = u128::from_be_bytes(raw_bytes);
        if candidate < zone {
            return candidate % bound;
        }
        attempt = attempt.wrapping_add(1);
    }
}

/// Selects `panel_size` unique attestors from the active staked pool proportional
/// to their staked balance without replacement using the provided `vrf_seed`.
///
/// # Panics
/// * Panics with `Error::ThresholdInvalid` if `panel_size == 0`.
/// * Panics with `Error::InsufficientStake` if fewer than `panel_size` eligible
///   active staked attestors exist in the pool.
pub fn select_vrf_stake_weighted_panel(
    env: &Env,
    vrf_seed: &BytesN<32>,
    panel_size: u32,
    exclude_issuer: &Address,
    exclude_counterparty: &Address,
) -> Vec<Address> {
    if panel_size == 0 {
        panic_with_error!(env, Error::ThresholdInvalid);
    }

    let candidates = active_staked_attestors(env, exclude_issuer, exclude_counterparty);
    if candidates.len() < panel_size {
        panic_with_error!(env, Error::InsufficientStake);
    }

    let mut remaining = candidates;
    let mut selected = Vec::new(env);

    for round in 0..panel_size {
        let mut total_weight: u128 = 0;
        for (_, stake_amt) in remaining.iter() {
            let weight = u128::try_from(stake_amt)
                .unwrap_or_else(|_| panic_with_error!(env, Error::Overflow));
            total_weight = total_weight
                .checked_add(weight)
                .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
        }

        if total_weight == 0 {
            panic_with_error!(env, Error::InsufficientStake);
        }

        let target = sample_unbiased_u128(env, vrf_seed, round, total_weight);

        let mut cumulative: u128 = 0;
        let mut chosen_index: u32 = 0;
        for (idx, (_, stake_amt)) in remaining.iter().enumerate() {
            let weight = u128::try_from(stake_amt).unwrap_or(0);
            cumulative = cumulative.saturating_add(weight);
            if target < cumulative {
                chosen_index = idx as u32;
                break;
            }
        }

        let (chosen_addr, _) = remaining.get(chosen_index).unwrap();
        selected.push_back(chosen_addr);

        let mut next_remaining = Vec::new(env);
        for (idx, entry) in remaining.iter().enumerate() {
            if (idx as u32) != chosen_index {
                next_remaining.push_back(entry);
            }
        }
        remaining = next_remaining;
    }

    selected
}
