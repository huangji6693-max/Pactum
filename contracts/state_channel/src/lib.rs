#![no_std]
#![allow(clippy::too_many_arguments)]

pub mod storage;

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, panic_with_error, token,
    Address, Bytes, BytesN, Env, Symbol,
};
pub use storage::{DataKey, DynamicDisputeQuote, FeeEngineState};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    ChannelNotFound = 1,
    ChannelAlreadyClosed = 2,
    ChannelNotInDispute = 3,
    DisputeWindowActive = 4,
    DisputeWindowExpired = 5,
    Unauthorized = 6,
    InvalidNonce = 7,
    InvalidStateProof = 8,
    ZeroAmount = 9,
    InvalidConsensusRules = 10,
    InvalidStateTransition = 11,
    AlreadyDisputed = 12,
    DisputerCannotChallengeSelf = 13,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelStatus {
    Open,
    Disputed,
    Closed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub id: u64,
    pub party_a: Address,
    pub party_b: Address,
    pub token: Address,
    pub balance_a: i128,
    pub balance_b: i128,
    pub ruleset_contract: Address,
    pub status: ChannelStatus,
    pub dispute_window: u64,
    pub dispute_started_at: u64,
    pub disputer: Option<Address>,
    pub latest_nonce: u64,
    pub latest_balance_a: i128,
    pub latest_balance_b: i128,
    pub latest_state_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    pub channel_id: u64,
    pub nonce: u64,
    pub balance_a: i128,
    pub balance_b: i128,
    pub state_hash: BytesN<32>,
}

#[contractclient(name = "WasmConsensusRulesetClient")]
pub trait WasmConsensusRuleset {
    /// Validates an off-chain state transition against user-defined WASM consensus rules.
    /// Returns `true` if the state transition from `old_state_hash` to `new_state_hash`
    /// with state payload `state_data` and balance movement is valid according to the WASM ruleset.
    #[allow(clippy::too_many_arguments)]
    fn validate_transition(
        env: Env,
        old_state_hash: BytesN<32>,
        new_state_hash: BytesN<32>,
        state_data: Bytes,
        old_balance_a: i128,
        old_balance_b: i128,
        new_balance_a: i128,
        new_balance_b: i128,
    ) -> bool;
}

#[contract]
pub struct StateChannelContract;

#[contractimpl]
impl StateChannelContract {
    /// Opens a new L2 state channel with locked token collateral and assigned WASM consensus ruleset contract.
    #[allow(clippy::too_many_arguments)]
    pub fn open_channel(
        env: Env,
        party_a: Address,
        party_b: Address,
        token: Address,
        amount_a: i128,
        amount_b: i128,
        dispute_window: u64,
        ruleset_contract: Address,
    ) -> u64 {
        if amount_a <= 0 && amount_b <= 0 {
            panic_with_error!(&env, Error::ZeroAmount);
        }

        party_a.require_auth();
        party_b.require_auth();

        let client = token::Client::new(&env, &token);
        let contract_address = env.current_contract_address();

        if amount_a > 0 {
            client.transfer(&party_a, &contract_address, &amount_a);
        }
        if amount_b > 0 {
            client.transfer(&party_b, &contract_address, &amount_b);
        }

        let channel_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextChannelId)
            .unwrap_or(1);

        env.storage()
            .instance()
            .set(&DataKey::NextChannelId, &(channel_id + 1));

        let initial_state_hash = BytesN::from_array(&env, &[0u8; 32]);

        let channel = Channel {
            id: channel_id,
            party_a: party_a.clone(),
            party_b: party_b.clone(),
            token: token.clone(),
            balance_a: amount_a,
            balance_b: amount_b,
            ruleset_contract,
            status: ChannelStatus::Open,
            dispute_window,
            dispute_started_at: 0,
            disputer: None,
            latest_nonce: 0,
            latest_balance_a: amount_a,
            latest_balance_b: amount_b,
            latest_state_hash: initial_state_hash,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Channel(channel_id), &channel);

        env.events().publish(
            (Symbol::new(&env, "channel_opened"), channel_id),
            (party_a, party_b, amount_a, amount_b),
        );

        channel_id
    }

    /// Fetches details for a registered state channel.
    pub fn get_channel(env: Env, channel_id: u64) -> Channel {
        env.storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound))
    }

    /// Submits a signed state proof to open or escalate a dispute challenge window.
    pub fn dispute_channel(env: Env, caller: Address, channel_id: u64, proof: StateProof) {
        caller.require_auth();

        let mut channel: Channel = env
            .storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound));

        if channel.status == ChannelStatus::Closed {
            panic_with_error!(&env, Error::ChannelAlreadyClosed);
        }

        if caller != channel.party_a && caller != channel.party_b {
            panic_with_error!(&env, Error::Unauthorized);
        }

        if proof.channel_id != channel_id {
            panic_with_error!(&env, Error::InvalidStateProof);
        }

        if proof.nonce <= channel.latest_nonce {
            panic_with_error!(&env, Error::InvalidNonce);
        }

        // Conservation of balance check
        if proof.balance_a + proof.balance_b != channel.balance_a + channel.balance_b {
            panic_with_error!(&env, Error::InvalidStateProof);
        }

        let now = env.ledger().timestamp();

        // Check if existing dispute window expired
        if channel.status == ChannelStatus::Disputed
            && now >= channel.dispute_started_at + channel.dispute_window
        {
            panic_with_error!(&env, Error::DisputeWindowExpired);
        }

        channel.latest_nonce = proof.nonce;
        channel.latest_balance_a = proof.balance_a;
        channel.latest_balance_b = proof.balance_b;
        channel.latest_state_hash = proof.state_hash;
        channel.status = ChannelStatus::Disputed;
        channel.dispute_started_at = now;
        channel.disputer = Some(caller.clone());

        env.storage()
            .persistent()
            .set(&DataKey::Channel(channel_id), &channel);

        env.events().publish(
            (Symbol::new(&env, "channel_disputed"), channel_id),
            (caller, proof.nonce, proof.balance_a, proof.balance_b),
        );
    }

    /// Configures the EIP-1559 style adaptive fee engine parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn configure_fee_engine(
        env: Env,
        base_dispute_bond: i128,
        target_gas: u64,
        max_elasticity_bps: u64,
        decay_rate_bps: u64,
        quiet_window_secs: u64,
        variance_spike_multiplier_bps: u64,
        rebate_share_bps: u64,
    ) -> FeeEngineState {
        if base_dispute_bond <= 0 {
            panic_with_error!(&env, Error::ZeroAmount);
        }
        if target_gas == 0
            || max_elasticity_bps == 0
            || max_elasticity_bps > storage::BPS_DENOMINATOR
            || decay_rate_bps > storage::BPS_DENOMINATOR
            || quiet_window_secs == 0
            || rebate_share_bps > storage::BPS_DENOMINATOR
        {
            panic_with_error!(&env, Error::InvalidConsensusRules);
        }

        let now = env.ledger().timestamp();
        let state = FeeEngineState {
            base_dispute_bond,
            current_dispute_bond: base_dispute_bond,
            target_gas,
            moving_avg_gas: target_gas,
            historical_gas_variance: (target_gas / 5).max(1),
            variance_spike_multiplier_bps,
            max_elasticity_bps,
            decay_rate_bps,
            quiet_window_secs,
            consecutive_disputes: 0,
            last_updated_at: now,
            rebate_share_bps,
        };
        storage::save_fee_engine(&env, &state);
        state
    }

    /// Returns the active fee engine state after applying any elapsed quiet-period decay.
    pub fn get_fee_engine_state(env: Env) -> FeeEngineState {
        let mut state = storage::load_fee_engine(&env);
        storage::apply_quiet_decay(&mut state, env.ledger().timestamp());
        state
    }

    /// Quotes the dynamic dispute bond, fee surcharge, and effective challenge window
    /// for `channel_id` at `observed_gas` without mutating state.
    pub fn quote_dispute_bond(env: Env, channel_id: u64, observed_gas: u64) -> DynamicDisputeQuote {
        let channel: Channel = env
            .storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound));

        let mut state = storage::load_fee_engine(&env);
        storage::update_fee_engine_on_dispute(
            &mut state,
            env.ledger().timestamp(),
            channel.dispute_window,
            observed_gas,
        )
    }

    /// Returns the accumulated protocol security reserve for `token`.
    pub fn get_security_reserve(env: Env, token: Address) -> i128 {
        storage::get_security_reserve(&env, &token)
    }

    /// Submits a state proof with EIP-1559 adaptive dispute bond scaling, dynamic
    /// challenge window extension under fee spikes, and security reserve fee accrual.
    pub fn dispute_channel_with_gas(
        env: Env,
        caller: Address,
        channel_id: u64,
        proof: StateProof,
        observed_gas: u64,
    ) -> DynamicDisputeQuote {
        caller.require_auth();

        let mut channel: Channel = env
            .storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound));

        if channel.status == ChannelStatus::Closed {
            panic_with_error!(&env, Error::ChannelAlreadyClosed);
        }

        if caller != channel.party_a && caller != channel.party_b {
            panic_with_error!(&env, Error::Unauthorized);
        }

        if proof.channel_id != channel_id {
            panic_with_error!(&env, Error::InvalidStateProof);
        }

        if proof.nonce <= channel.latest_nonce {
            panic_with_error!(&env, Error::InvalidNonce);
        }

        if proof.balance_a + proof.balance_b != channel.balance_a + channel.balance_b {
            panic_with_error!(&env, Error::InvalidStateProof);
        }

        let now = env.ledger().timestamp();

        if channel.status == ChannelStatus::Disputed
            && now >= channel.dispute_started_at + channel.dispute_window
        {
            panic_with_error!(&env, Error::DisputeWindowExpired);
        }

        // If a prior disputer had a refundable bond escrowed on this channel, refund it
        // before locking the new disputer's bond.
        let prev_bond = storage::get_channel_dispute_bond(&env, channel_id);
        if prev_bond > 0 {
            if let Some(prev_disputer) = channel.disputer.clone() {
                let token_client = token::Client::new(&env, &channel.token);
                token_client.transfer(&env.current_contract_address(), &prev_disputer, &prev_bond);
                storage::set_channel_dispute_bond(&env, channel_id, 0);
            }
        }

        let mut fee_state = storage::load_fee_engine(&env);
        let quote = storage::update_fee_engine_on_dispute(
            &mut fee_state,
            now,
            channel.dispute_window,
            observed_gas,
        );
        storage::save_fee_engine(&env, &fee_state);

        if quote.total_bond > 0 {
            let token_client = token::Client::new(&env, &channel.token);
            token_client.transfer(&caller, &env.current_contract_address(), &quote.total_bond);
        }

        storage::set_channel_dispute_bond(&env, channel_id, quote.base_bond_component);
        if quote.dynamic_fee_surcharge > 0 {
            let current_reserve = storage::get_security_reserve(&env, &channel.token);
            storage::set_security_reserve(
                &env,
                &channel.token,
                current_reserve.saturating_add(quote.dynamic_fee_surcharge),
            );
        }

        if quote.effective_dispute_window > channel.dispute_window {
            channel.dispute_window = quote.effective_dispute_window;
        }

        channel.latest_nonce = proof.nonce;
        channel.latest_balance_a = proof.balance_a;
        channel.latest_balance_b = proof.balance_b;
        channel.latest_state_hash = proof.state_hash;
        channel.status = ChannelStatus::Disputed;
        channel.dispute_started_at = now;
        channel.disputer = Some(caller.clone());

        env.storage()
            .persistent()
            .set(&DataKey::Channel(channel_id), &channel);

        env.events().publish(
            (Symbol::new(&env, "channel_disputed_dynamic"), channel_id),
            (
                caller,
                proof.nonce,
                quote.total_bond,
                channel.dispute_window,
            ),
        );

        quote
    }

    /// Verifies off-chain state transitions against the custom WASM consensus ruleset.
    /// The challenge MUST verify the disputed state currently held in `channel.latest_*`.
    /// If `validate_transition` returns false, the disputer who submitted the invalid state proof is slashed,
    /// and 100% of collateral is awarded to `challenger`.
    pub fn verify_and_resolve_dispute(
        env: Env,
        challenger: Address,
        channel_id: u64,
        prior_state_hash: BytesN<32>,
        prior_balance_a: i128,
        prior_balance_b: i128,
        state_data: Bytes,
    ) {
        challenger.require_auth();

        let mut channel: Channel = env
            .storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound));

        if channel.status != ChannelStatus::Disputed {
            panic_with_error!(&env, Error::ChannelNotInDispute);
        }

        if challenger != channel.party_a && challenger != channel.party_b {
            panic_with_error!(&env, Error::Unauthorized);
        }

        let disputer = channel
            .disputer
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, Error::InvalidStateProof));

        if challenger == disputer {
            panic_with_error!(&env, Error::DisputerCannotChallengeSelf);
        }

        let ruleset_client = WasmConsensusRulesetClient::new(&env, &channel.ruleset_contract);

        let is_valid = ruleset_client.validate_transition(
            &prior_state_hash,
            &channel.latest_state_hash,
            &state_data,
            &prior_balance_a,
            &prior_balance_b,
            &channel.latest_balance_a,
            &channel.latest_balance_b,
        );

        let token_client = token::Client::new(&env, &channel.token);
        let total_collateral = channel.balance_a + channel.balance_b;
        let escrowed_bond = storage::get_channel_dispute_bond(&env, channel_id);

        if !is_valid {
            // Slashing branch: disputer submitted an invalid state transition!
            // Slashing offender (disputer) and awarding 100% collateral + escrowed dispute bond
            // + proportional protocol security reserve rebate to the honest challenger.
            storage::set_channel_dispute_bond(&env, channel_id, 0);

            let reserve = storage::get_security_reserve(&env, &channel.token);
            let fee_state = storage::load_fee_engine(&env);
            let rebate = if reserve > 0 {
                (reserve.saturating_mul(i128::from(fee_state.rebate_share_bps)))
                    / i128::from(storage::BPS_DENOMINATOR)
            } else {
                0
            };
            if rebate > 0 {
                storage::set_security_reserve(&env, &channel.token, reserve.saturating_sub(rebate));
            }

            let total_challenger_payout = total_collateral
                .saturating_add(escrowed_bond)
                .saturating_add(rebate);

            if total_challenger_payout > 0 {
                token_client.transfer(
                    &env.current_contract_address(),
                    &challenger,
                    &total_challenger_payout,
                );
            }

            channel.status = ChannelStatus::Closed;
            channel.latest_balance_a = if challenger == channel.party_a {
                total_collateral
            } else {
                0
            };
            channel.latest_balance_b = if challenger == channel.party_b {
                total_collateral
            } else {
                0
            };

            env.storage()
                .persistent()
                .set(&DataKey::Channel(channel_id), &channel);

            env.events().publish(
                (Symbol::new(&env, "offender_slashed"), channel_id),
                (disputer, challenger, total_challenger_payout),
            );
        } else {
            // Valid transition branch: state transition passed WASM consensus rules verification.
            // Refund any escrowed base dispute bond back to the honest disputer.
            if escrowed_bond > 0 {
                storage::set_channel_dispute_bond(&env, channel_id, 0);
                token_client.transfer(&env.current_contract_address(), &disputer, &escrowed_bond);
            }
            env.events().publish(
                (Symbol::new(&env, "transition_verified"), channel_id),
                (challenger, channel.latest_nonce),
            );
        }
    }

    /// Closes the channel and distributes remaining locked collateral.
    /// Can be called cooperatively when both parties sign, or after dispute window expiration.
    pub fn close_channel(env: Env, caller: Address, channel_id: u64) {
        caller.require_auth();

        let mut channel: Channel = env
            .storage()
            .persistent()
            .get(&DataKey::Channel(channel_id))
            .unwrap_or_else(|| panic_with_error!(&env, Error::ChannelNotFound));

        if channel.status == ChannelStatus::Closed {
            panic_with_error!(&env, Error::ChannelAlreadyClosed);
        }

        if caller != channel.party_a && caller != channel.party_b {
            panic_with_error!(&env, Error::Unauthorized);
        }

        let now = env.ledger().timestamp();

        if channel.status == ChannelStatus::Disputed {
            if now < channel.dispute_started_at + channel.dispute_window {
                panic_with_error!(&env, Error::DisputeWindowActive);
            }
        } else {
            // Cooperative close requires both signatures if not in dispute
            channel.party_a.require_auth();
            channel.party_b.require_auth();
        }

        let token_client = token::Client::new(&env, &channel.token);
        let contract_address = env.current_contract_address();

        if channel.latest_balance_a > 0 {
            token_client.transfer(
                &contract_address,
                &channel.party_a,
                &channel.latest_balance_a,
            );
        }

        if channel.latest_balance_b > 0 {
            token_client.transfer(
                &contract_address,
                &channel.party_b,
                &channel.latest_balance_b,
            );
        }

        let escrowed_bond = storage::get_channel_dispute_bond(&env, channel_id);
        if escrowed_bond > 0 {
            storage::set_channel_dispute_bond(&env, channel_id, 0);
            if let Some(disputer) = channel.disputer.clone() {
                token_client.transfer(&contract_address, &disputer, &escrowed_bond);
            }
        }

        channel.status = ChannelStatus::Closed;

        env.storage()
            .persistent()
            .set(&DataKey::Channel(channel_id), &channel);

        env.events().publish(
            (Symbol::new(&env, "channel_closed"), channel_id),
            (channel.latest_balance_a, channel.latest_balance_b),
        );
    }
}

#[cfg(test)]
mod test;
