use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
    Address, Bytes, BytesN, Env,
};

#[contract]
pub struct MockWasmRuleset;

#[contractimpl]
impl MockWasmRuleset {
    #[allow(clippy::too_many_arguments)]
    pub fn validate_transition(
        _env: Env,
        _old_state_hash: BytesN<32>,
        _new_state_hash: BytesN<32>,
        state_data: Bytes,
        _old_balance_a: i128,
        _old_balance_b: i128,
        _new_balance_a: i128,
        _new_balance_b: i128,
    ) -> bool {
        // If state_data contains a single byte equal to 0, reject transition as invalid
        state_data.is_empty() || state_data.get(0).unwrap() != 0
    }
}

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, StellarAssetClient<'a>) {
    let sac = e.register_stellar_asset_contract_v2(admin.clone());
    (
        token::Client::new(e, &sac.address()),
        StellarAssetClient::new(e, &sac.address()),
    )
}

#[test]
fn test_cooperative_channel_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &1000);
    sac_client.mint(&party_b, &1000);

    let ruleset_id = env.register(MockWasmRuleset, ());

    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &3600,
        &ruleset_id,
    );

    assert_eq!(channel_id, 1);
    let channel = channel_client.get_channel(&channel_id);
    assert_eq!(channel.balance_a, 500);
    assert_eq!(channel.balance_b, 500);
    assert_eq!(channel.status, ChannelStatus::Open);
    assert_eq!(token_client.balance(&channel_contract_id), 1000);

    // Cooperative close
    channel_client.close_channel(&party_a, &channel_id);

    let closed_channel = channel_client.get_channel(&channel_id);
    assert_eq!(closed_channel.status, ChannelStatus::Closed);
    assert_eq!(token_client.balance(&party_a), 1000);
    assert_eq!(token_client.balance(&party_b), 1000);
}

#[test]
fn test_dispute_and_wasm_verification_valid_transition() {
    let env = Env::default();
    env.mock_all_auths();

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &1000);
    sac_client.mint(&party_b, &1000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &3600,
        &ruleset_id,
    );

    let state_hash = BytesN::from_array(&env, &[1u8; 32]);
    let proof = StateProof {
        channel_id,
        nonce: 1,
        balance_a: 700,
        balance_b: 300,
        state_hash: state_hash.clone(),
    };

    channel_client.dispute_channel(&party_a, &channel_id, &proof);

    let disputed_channel = channel_client.get_channel(&channel_id);
    assert_eq!(disputed_channel.status, ChannelStatus::Disputed);
    assert_eq!(disputed_channel.latest_nonce, 1);

    // Party B challenges Party A's dispute proof with valid state data
    let prior_hash = BytesN::from_array(&env, &[0u8; 32]);
    let mut state_data = Bytes::new(&env);
    state_data.push_back(1); // valid payload

    channel_client.verify_and_resolve_dispute(
        &party_b,
        &channel_id,
        &prior_hash,
        &500,
        &500,
        &state_data,
    );

    let verified_channel = channel_client.get_channel(&channel_id);
    assert_eq!(verified_channel.latest_balance_a, 700);
    assert_eq!(verified_channel.latest_balance_b, 300);
}

#[test]
fn test_dispute_and_wasm_slashing_invalid_transition() {
    let env = Env::default();
    env.mock_all_auths();

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &1000);
    sac_client.mint(&party_b, &1000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &3600,
        &ruleset_id,
    );

    let invalid_state_hash = BytesN::from_array(&env, &[9u8; 32]);
    let proof = StateProof {
        channel_id,
        nonce: 5,
        balance_a: 1000,
        balance_b: 0,
        state_hash: invalid_state_hash.clone(),
    };

    // Malicious Party A submits invalid dispute proof
    channel_client.dispute_channel(&party_a, &channel_id, &proof);

    // Party B challenges Party A's submission with invalid payload state_data = [0]
    let prior_hash = BytesN::from_array(&env, &[0u8; 32]);
    let mut invalid_state_data = Bytes::new(&env);
    invalid_state_data.push_back(0); // mock ruleset returns false for 0

    channel_client.verify_and_resolve_dispute(
        &party_b,
        &channel_id,
        &prior_hash,
        &500,
        &500,
        &invalid_state_data,
    );

    // Party A (offender) is slashed! Party B gets 100% of collateral (1000) + original uncommitted balance (500) = 1500
    assert_eq!(token_client.balance(&party_a), 500); // initial 1000 - 500 deposited, 0 awarded
    assert_eq!(token_client.balance(&party_b), 1500); // initial 1000 - 500 deposited + 1000 slashed collateral

    let slashed_channel = channel_client.get_channel(&channel_id);
    assert_eq!(slashed_channel.status, ChannelStatus::Closed);
    assert_eq!(slashed_channel.latest_balance_a, 0);
    assert_eq!(slashed_channel.latest_balance_b, 1000);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #13)")]
fn test_disputer_cannot_challenge_self() {
    let env = Env::default();
    env.mock_all_auths();

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &1000);
    sac_client.mint(&party_b, &1000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &3600,
        &ruleset_id,
    );

    let proof = StateProof {
        channel_id,
        nonce: 1,
        balance_a: 700,
        balance_b: 300,
        state_hash: BytesN::from_array(&env, &[1u8; 32]),
    };

    channel_client.dispute_channel(&party_a, &channel_id, &proof);

    let prior_hash = BytesN::from_array(&env, &[0u8; 32]);
    let mut invalid_state_data = Bytes::new(&env);
    invalid_state_data.push_back(0);

    // Party A (disputer) tries to challenge self to steal collateral — must panic with Error #13
    channel_client.verify_and_resolve_dispute(
        &party_a,
        &channel_id,
        &prior_hash,
        &500,
        &500,
        &invalid_state_data,
    );
}

#[test]
fn test_close_channel_after_dispute_timeout() {
    let env = Env::default();
    env.mock_all_auths();

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &1000);
    sac_client.mint(&party_b, &1000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let dispute_window = 1000;
    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &dispute_window,
        &ruleset_id,
    );

    let proof = StateProof {
        channel_id,
        nonce: 2,
        balance_a: 600,
        balance_b: 400,
        state_hash: BytesN::from_array(&env, &[3u8; 32]),
    };

    channel_client.dispute_channel(&party_a, &channel_id, &proof);

    // Advance ledger timestamp beyond dispute window
    env.ledger().set_timestamp(dispute_window + 10);

    channel_client.close_channel(&party_b, &channel_id);

    assert_eq!(token_client.balance(&party_a), 1100); // 500 remaining + 600
    assert_eq!(token_client.balance(&party_b), 900); // 500 remaining + 400
}

#[test]
fn test_eip1559_adaptive_bond_scaling_on_consecutive_disputes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &10_000);
    sac_client.mint(&party_b, &10_000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    channel_client.configure_fee_engine(
        &100,     // base_dispute_bond
        &100_000, // target_gas
        &1_250,   // max_elasticity_bps (12.5%)
        &1_250,   // decay_rate_bps (12.5%)
        &300,     // quiet_window_secs
        &20_000,  // variance_spike_multiplier_bps (2.0x)
        &5_000,   // rebate_share_bps (50%)
    );

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &3600,
        &ruleset_id,
    );

    // Consecutive dispute 1 at elevated gas (160,000 > 100,000 target)
    let q1 = channel_client.dispute_channel_with_gas(
        &party_a,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 1,
            balance_a: 550,
            balance_b: 450,
            state_hash: BytesN::from_array(&env, &[1u8; 32]),
        },
        &160_000,
    );

    // Consecutive dispute 2 within the same window (no quiet decay)
    env.ledger().set_timestamp(1_050);
    let q2 = channel_client.dispute_channel_with_gas(
        &party_b,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 2,
            balance_a: 520,
            balance_b: 480,
            state_hash: BytesN::from_array(&env, &[2u8; 32]),
        },
        &180_000,
    );

    // Consecutive dispute 3 within the same window
    env.ledger().set_timestamp(1_100);
    let q3 = channel_client.dispute_channel_with_gas(
        &party_a,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 3,
            balance_a: 580,
            balance_b: 420,
            state_hash: BytesN::from_array(&env, &[3u8; 32]),
        },
        &200_000,
    );

    assert!(q1.total_bond > 100);
    assert!(q2.total_bond > q1.total_bond);
    assert!(q3.total_bond > q2.total_bond);

    let state = channel_client.get_fee_engine_state();
    assert_eq!(state.consecutive_disputes, 3);
    assert_eq!(state.current_dispute_bond, q3.total_bond);

    let reserve = channel_client.get_security_reserve(&token_client.address);
    assert_eq!(
        reserve,
        q1.dynamic_fee_surcharge + q2.dynamic_fee_surcharge + q3.dynamic_fee_surcharge
    );
}

#[test]
fn test_exponential_decay_toward_base_fee_when_quiet() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &10_000);
    sac_client.mint(&party_b, &10_000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    channel_client.configure_fee_engine(&100, &100_000, &2_000, &2_500, &300, &20_000, &5_000);

    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &7200,
        &ruleset_id,
    );

    // Trigger two consecutive high-gas disputes to drive current_dispute_bond well above 100.
    let _ = channel_client.dispute_channel_with_gas(
        &party_a,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 1,
            balance_a: 600,
            balance_b: 400,
            state_hash: BytesN::from_array(&env, &[1u8; 32]),
        },
        &220_000,
    );
    let peak = channel_client.dispute_channel_with_gas(
        &party_b,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 2,
            balance_a: 500,
            balance_b: 500,
            state_hash: BytesN::from_array(&env, &[2u8; 32]),
        },
        &240_000,
    );
    assert!(peak.total_bond > 140);

    // Advance 1 quiet window (300s): bond decays partially toward 100.
    env.ledger().set_timestamp(10_300);
    let after_one_window = channel_client.get_fee_engine_state();
    assert!(after_one_window.current_dispute_bond < peak.total_bond);
    assert!(after_one_window.current_dispute_bond > 100);
    assert_eq!(after_one_window.consecutive_disputes, 1);

    // Advance 50 quiet windows (15,000s): bond and moving_avg_gas decay smoothly all the way back to baseline.
    env.ledger().set_timestamp(25_000);
    let fully_decayed = channel_client.get_fee_engine_state();
    assert_eq!(fully_decayed.current_dispute_bond, 100);
    assert_eq!(fully_decayed.moving_avg_gas, 100_000);
    assert_eq!(fully_decayed.consecutive_disputes, 0);
}

#[test]
fn test_dynamic_challenge_window_extension_under_fee_spike() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(5_000);

    let party_a = Address::generate(&env);
    let party_b = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&party_a, &10_000);
    sac_client.mint(&party_b, &10_000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    let base_window = 1_000u64;
    let channel_id = channel_client.open_channel(
        &party_a,
        &party_b,
        &token_client.address,
        &500,
        &500,
        &base_window,
        &ruleset_id,
    );

    // Normal gas observation (105_000 within 100_000 + 2.0 * 15_000 = 130_000 threshold): no extension
    let normal_quote = channel_client.quote_dispute_bond(&channel_id, &105_000);
    assert!(!normal_quote.spike_detected);
    assert_eq!(normal_quote.effective_dispute_window, base_window);

    // Sudden network gas spike (300_000 >> 130_000 variance threshold): automatically extends window
    let spike_quote = channel_client.dispute_channel_with_gas(
        &party_a,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 1,
            balance_a: 800,
            balance_b: 200,
            state_hash: BytesN::from_array(&env, &[7u8; 32]),
        },
        &300_000,
    );
    assert!(spike_quote.spike_detected);
    assert!(spike_quote.effective_dispute_window > base_window);

    let updated_channel = channel_client.get_channel(&channel_id);
    assert_eq!(
        updated_channel.dispute_window,
        spike_quote.effective_dispute_window
    );

    // Attempting to close after the original base_window (5_000 + 1_000 + 10) must fail
    // because the anti-censorship dynamic window extension is still active.
    env.ledger().set_timestamp(5_000 + base_window + 10);
    let premature_close = channel_client.try_close_channel(&party_a, &channel_id);
    assert_eq!(premature_close, Err(Ok(Error::DisputeWindowActive.into())));

    // Once the extended challenge window expires, close succeeds and refunds the escrowed base bond.
    env.ledger()
        .set_timestamp(5_000 + spike_quote.effective_dispute_window + 10);
    channel_client.close_channel(&party_a, &channel_id);
    assert_eq!(
        channel_client.get_channel(&channel_id).status,
        ChannelStatus::Closed
    );
}

#[test]
fn test_sandwich_griefing_resistance_and_slashing_rebates_to_honest_challenger() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(20_000);

    let attacker = Address::generate(&env);
    let honest_party = Address::generate(&env);
    let admin = Address::generate(&env);

    let (token_client, sac_client) = create_token_contract(&env, &admin);
    sac_client.mint(&attacker, &5_000);
    sac_client.mint(&honest_party, &5_000);

    let ruleset_id = env.register(MockWasmRuleset, ());
    let channel_contract_id = env.register(StateChannelContract, ());
    let channel_client = StateChannelContractClient::new(&env, &channel_contract_id);

    channel_client.configure_fee_engine(&100, &100_000, &2_000, &1_250, &300, &20_000, &5_000);

    let channel_id = channel_client.open_channel(
        &attacker,
        &honest_party,
        &token_client.address,
        &500,
        &500,
        &1_200,
        &ruleset_id,
    );

    // Sandwich / griefing simulation:
    // Attacker rapidly submits consecutive high-gas disputes to bloat fees and attempt to censor honest_party.
    let g1 = channel_client.dispute_channel_with_gas(
        &attacker,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 1,
            balance_a: 600,
            balance_b: 400,
            state_hash: BytesN::from_array(&env, &[0xA1; 32]),
        },
        &250_000,
    );
    env.ledger().set_timestamp(20_030);
    let g2 = channel_client.dispute_channel_with_gas(
        &attacker,
        &channel_id,
        &StateProof {
            channel_id,
            nonce: 2,
            balance_a: 1_000,
            balance_b: 0,
            state_hash: BytesN::from_array(&env, &[0xA2; 32]),
        },
        &320_000,
    );

    // 1. Dynamic fee elasticity penalizes consecutive griefing disputes (`g2.total_bond > g1.total_bond`).
    assert!(g2.total_bond > g1.total_bond);
    // 2. Dynamic challenge window automatically extended under the gas spike.
    let channel_during_attack = channel_client.get_channel(&channel_id);
    assert!(channel_during_attack.dispute_window > 1_200);

    // 3. Dynamic fee surcharges accumulated in the protocol security reserve.
    let reserve_before_slash = channel_client.get_security_reserve(&token_client.address);
    let expected_reserve = g1.dynamic_fee_surcharge + g2.dynamic_fee_surcharge;
    assert_eq!(reserve_before_slash, expected_reserve);
    assert!(reserve_before_slash > 0);

    let honest_balance_before = token_client.balance(&honest_party);

    // 4. Honest challenger submits fraud proof (`invalid_state_data = [0]`) within the extended window
    //    and receives 100% channel collateral (1,000) + escrowed base bond (100) + 50% security reserve rebate!
    let prior_hash = BytesN::from_array(&env, &[0xA1; 32]);
    let mut invalid_state_data = Bytes::new(&env);
    invalid_state_data.push_back(0);

    channel_client.verify_and_resolve_dispute(
        &honest_party,
        &channel_id,
        &prior_hash,
        &600,
        &400,
        &invalid_state_data,
    );

    let expected_rebate = reserve_before_slash / 2;
    let honest_balance_after = token_client.balance(&honest_party);
    assert_eq!(
        honest_balance_after - honest_balance_before,
        1_000 + g2.base_bond_component + expected_rebate
    );
    assert_eq!(
        channel_client.get_security_reserve(&token_client.address),
        reserve_before_slash - expected_rebate
    );
}
