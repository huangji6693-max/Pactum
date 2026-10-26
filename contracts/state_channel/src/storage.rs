use soroban_sdk::{contracttype, Address, Env};

/// Basis points denominator (100% = 10,000 bps).
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Default EIP-1559 max elasticity step in basis points (12.5% = 1,250 bps = 1/8).
pub const DEFAULT_MAX_ELASTICITY_BPS: u64 = 1_250;

/// Default exponential decay rate per quiet interval in basis points (12.5% = 1,250 bps).
pub const DEFAULT_DECAY_RATE_BPS: u64 = 1_250;

/// Default quiet interval duration in seconds (5 minutes = 300 seconds).
pub const DEFAULT_QUIET_WINDOW_SECS: u64 = 300;

/// Default target Soroban gas units per dispute operation.
pub const DEFAULT_TARGET_GAS: u64 = 100_000;

/// Default initial moving-average gas variance baseline.
pub const DEFAULT_INITIAL_VARIANCE: u64 = 15_000;

/// Default variance multiplier threshold in basis points (2.0x = 20,000 bps).
pub const DEFAULT_VARIANCE_SPIKE_MULTIPLIER_BPS: u64 = 20_000;

/// Default base dispute bond collateral in token units.
pub const DEFAULT_BASE_DISPUTE_BOND: i128 = 100;

/// Default slashing rebate share from the protocol security reserve (50% = 5,000 bps).
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 5_000;

/// Maximum challenge window extension multiplier (4x base dispute window).
pub const MAX_WINDOW_EXTENSION_MULTIPLIER: u64 = 4;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    NextChannelId,
    Channel(u64),
    FeeEngine,
    ChannelDisputeBond(u64),
    SecurityReserve(Address),
}

/// On-chain EIP-1559 style adaptive fee and gas-targeting state for state channel disputes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeEngineState {
    /// Minimum baseline dispute bond collateral when the network is quiet.
    pub base_dispute_bond: i128,
    /// Current dynamically scaled dispute bond collateral.
    pub current_dispute_bond: i128,
    /// Target Soroban gas consumption per dispute epoch.
    pub target_gas: u64,
    /// Exponential moving average (EMA) of recent Soroban gas consumption.
    pub moving_avg_gas: u64,
    /// Exponential moving average (EMA) of absolute gas deviation `|observed_gas - moving_avg_gas|`.
    pub historical_gas_variance: u64,
    /// Variance threshold multiplier in basis points above which challenge windows lengthen.
    pub variance_spike_multiplier_bps: u64,
    /// Maximum per-step EIP-1559 upward/downward elasticity in basis points.
    pub max_elasticity_bps: u64,
    /// Exponential decay rate per quiet interval in basis points.
    pub decay_rate_bps: u64,
    /// Quiet interval duration in seconds used to decay bond collateral toward `base_dispute_bond`.
    pub quiet_window_secs: u64,
    /// Count of consecutive disputes without a quiet recovery interval.
    pub consecutive_disputes: u32,
    /// Ledger timestamp of the most recent fee engine update.
    pub last_updated_at: u64,
    /// Share of protocol security reserve (in bps) rebated to honest challengers upon slashing.
    pub rebate_share_bps: u64,
}

/// Snapshot returned when quoting or applying a dynamic dispute fee update.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicDisputeQuote {
    /// Total dispute bond required from the disputer (`base_bond_component + dynamic_fee_surcharge`).
    pub total_bond: i128,
    /// Base refundable bond component escrowed for the channel.
    pub base_bond_component: i128,
    /// Dynamic congestion/elasticity fee surcharge accrued into the protocol security reserve.
    pub dynamic_fee_surcharge: i128,
    /// Effective dispute challenge window (lengthened automatically during gas spikes).
    pub effective_dispute_window: u64,
    /// Whether the observed gas triggered an anti-censorship challenge window extension.
    pub spike_detected: bool,
}

impl FeeEngineState {
    pub fn default_state(now: u64) -> Self {
        Self {
            base_dispute_bond: DEFAULT_BASE_DISPUTE_BOND,
            current_dispute_bond: DEFAULT_BASE_DISPUTE_BOND,
            target_gas: DEFAULT_TARGET_GAS,
            moving_avg_gas: DEFAULT_TARGET_GAS,
            historical_gas_variance: DEFAULT_INITIAL_VARIANCE,
            variance_spike_multiplier_bps: DEFAULT_VARIANCE_SPIKE_MULTIPLIER_BPS,
            max_elasticity_bps: DEFAULT_MAX_ELASTICITY_BPS,
            decay_rate_bps: DEFAULT_DECAY_RATE_BPS,
            quiet_window_secs: DEFAULT_QUIET_WINDOW_SECS,
            consecutive_disputes: 0,
            last_updated_at: now,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
        }
    }
}

/// Loads the current `FeeEngineState` from instance storage, or initializes defaults.
pub fn load_fee_engine(env: &Env) -> FeeEngineState {
    env.storage()
        .instance()
        .get(&DataKey::FeeEngine)
        .unwrap_or_else(|| FeeEngineState::default_state(env.ledger().timestamp()))
}

/// Saves the updated `FeeEngineState` to instance storage.
pub fn save_fee_engine(env: &Env, state: &FeeEngineState) {
    env.storage().instance().set(&DataKey::FeeEngine, state);
}

/// Applies exponential quiet-period decay to `state` based on elapsed time since `last_updated_at`.
pub fn apply_quiet_decay(state: &mut FeeEngineState, now: u64) {
    if now <= state.last_updated_at || state.quiet_window_secs == 0 {
        return;
    }

    let elapsed = now.saturating_sub(state.last_updated_at);
    let steps = elapsed / state.quiet_window_secs;
    if steps == 0 {
        return;
    }

    let capped_steps = steps.min(64);
    let retain_bps = i128::from(BPS_DENOMINATOR.saturating_sub(state.decay_rate_bps));
    let denom = i128::from(BPS_DENOMINATOR);

    for _ in 0..capped_steps {
        if state.current_dispute_bond > state.base_dispute_bond {
            let excess = state
                .current_dispute_bond
                .saturating_sub(state.base_dispute_bond);
            let decayed_excess = (excess.saturating_mul(retain_bps)) / denom;
            state.current_dispute_bond = state.base_dispute_bond.saturating_add(decayed_excess);
        }
        if state.moving_avg_gas > state.target_gas {
            let gas_excess = state.moving_avg_gas.saturating_sub(state.target_gas);
            let decayed_gas = (gas_excess
                .saturating_mul(BPS_DENOMINATOR.saturating_sub(state.decay_rate_bps)))
                / BPS_DENOMINATOR;
            state.moving_avg_gas = state.target_gas.saturating_add(decayed_gas);
        }
    }

    state.consecutive_disputes = state
        .consecutive_disputes
        .saturating_sub(capped_steps as u32);
    state.last_updated_at = now;
}

/// Computes the effective challenge window given a channel's base `dispute_window` and
/// the current `observed_gas`. Lengthens the challenge window when `observed_gas` spikes
/// beyond `moving_avg_gas + (historical_gas_variance * variance_spike_multiplier_bps) / 10_000`.
pub fn compute_effective_window(
    state: &FeeEngineState,
    base_dispute_window: u64,
    observed_gas: u64,
) -> (u64, bool) {
    let spike_margin = (state
        .historical_gas_variance
        .saturating_mul(state.variance_spike_multiplier_bps))
        / BPS_DENOMINATOR;
    let threshold = state.moving_avg_gas.saturating_add(spike_margin.max(1));

    if observed_gas <= threshold {
        return (base_dispute_window, false);
    }

    let overshoot = observed_gas.saturating_sub(threshold);
    let baseline = state.target_gas.max(1);
    // Exponential/proportional window extension bounded by MAX_WINDOW_EXTENSION_MULTIPLIER.
    // Every `target_gas` of overshoot adds +50% to the base dispute window, plus a minimum +25%
    // anti-censorship buffer as soon as the variance threshold is breached.
    let extra_bps = 2_500u64.saturating_add((overshoot.saturating_mul(5_000)) / baseline);
    let max_extra_bps = (MAX_WINDOW_EXTENSION_MULTIPLIER.saturating_sub(1)) * BPS_DENOMINATOR;
    let clamped_extra_bps = extra_bps.min(max_extra_bps);

    let extension = (base_dispute_window.saturating_mul(clamped_extra_bps)) / BPS_DENOMINATOR;
    let effective = base_dispute_window.saturating_add(extension.max(1));
    (effective, true)
}

/// Updates the EIP-1559 fee engine state for a new dispute with `observed_gas` at timestamp `now`,
/// returning the resulting `DynamicDisputeQuote`.
pub fn update_fee_engine_on_dispute(
    state: &mut FeeEngineState,
    now: u64,
    base_dispute_window: u64,
    observed_gas: u64,
) -> DynamicDisputeQuote {
    // 1. Decay toward base fee if quiet intervals have elapsed since last dispute.
    apply_quiet_decay(state, now);

    // 2. Evaluate challenge window extension against the pre-update variance baseline
    //    so sudden network fee spikes immediately lengthen the challenge window.
    let (effective_dispute_window, spike_detected) =
        compute_effective_window(state, base_dispute_window, observed_gas);

    // 3. Increment consecutive dispute counter.
    state.consecutive_disputes = state.consecutive_disputes.saturating_add(1);

    // 4. Update moving average gas and historical variance (EMA alpha = 0.25).
    let abs_dev = observed_gas.abs_diff(state.moving_avg_gas);
    state.historical_gas_variance = (state
        .historical_gas_variance
        .saturating_mul(3)
        .saturating_add(abs_dev))
        / 4;
    state.moving_avg_gas = (state
        .moving_avg_gas
        .saturating_mul(3)
        .saturating_add(observed_gas))
        / 4;

    // 5. EIP-1559 adaptive bond scaling:
    //    - Scale up when observed/EMA gas exceeds `target_gas` or during consecutive disputes.
    //    - Scale down toward `base_dispute_bond` when observed gas is below `target_gas` and
    //      disputes are isolated (`consecutive_disputes == 1`).
    let target = state.target_gas.max(1);
    let effective_gas = observed_gas.max(state.moving_avg_gas);

    if effective_gas > target || state.consecutive_disputes > 1 {
        let gas_over_bps = if effective_gas > target {
            ((effective_gas - target).saturating_mul(state.max_elasticity_bps)) / target
        } else {
            0
        };
        let streak_surge_bps = u64::from(state.consecutive_disputes.saturating_sub(1))
            .saturating_mul(state.max_elasticity_bps)
            / 2;
        let total_up_bps = gas_over_bps
            .saturating_add(streak_surge_bps)
            .min(BPS_DENOMINATOR);

        if total_up_bps > 0 {
            let delta = (state
                .current_dispute_bond
                .saturating_mul(i128::from(total_up_bps)))
                / i128::from(BPS_DENOMINATOR);
            state.current_dispute_bond = state.current_dispute_bond.saturating_add(delta.max(1));
        }
    } else if observed_gas < target && state.current_dispute_bond > state.base_dispute_bond {
        let gas_under_bps =
            ((target - observed_gas).saturating_mul(state.max_elasticity_bps)) / target;
        let delta = (state
            .current_dispute_bond
            .saturating_mul(i128::from(gas_under_bps)))
            / i128::from(BPS_DENOMINATOR);
        state.current_dispute_bond =
            (state.current_dispute_bond.saturating_sub(delta.max(1))).max(state.base_dispute_bond);
    }

    state.last_updated_at = now;

    let total_bond = state.current_dispute_bond;
    let base_bond_component = state.base_dispute_bond.min(total_bond);
    let dynamic_fee_surcharge = total_bond.saturating_sub(base_bond_component);

    DynamicDisputeQuote {
        total_bond,
        base_bond_component,
        dynamic_fee_surcharge,
        effective_dispute_window,
        spike_detected,
    }
}

/// Reads the escrowed dispute bond for `channel_id`.
pub fn get_channel_dispute_bond(env: &Env, channel_id: u64) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::ChannelDisputeBond(channel_id))
        .unwrap_or(0)
}

/// Sets the escrowed dispute bond for `channel_id`.
pub fn set_channel_dispute_bond(env: &Env, channel_id: u64, amount: i128) {
    if amount <= 0 {
        env.storage()
            .persistent()
            .remove(&DataKey::ChannelDisputeBond(channel_id));
    } else {
        env.storage()
            .persistent()
            .set(&DataKey::ChannelDisputeBond(channel_id), &amount);
    }
}

/// Reads the accumulated protocol security reserve for `token`.
pub fn get_security_reserve(env: &Env, token: &Address) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::SecurityReserve(token.clone()))
        .unwrap_or(0)
}

/// Sets the accumulated protocol security reserve for `token`.
pub fn set_security_reserve(env: &Env, token: &Address, amount: i128) {
    env.storage()
        .instance()
        .set(&DataKey::SecurityReserve(token.clone()), &amount);
}
