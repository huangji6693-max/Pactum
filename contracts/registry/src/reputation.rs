//! Per-address compliance score aggregation (Phase 4), and the V1 → V2 schema
//! migration that Phase C (Attestors) requires.
//!
//! # Two schemas, one contract ID
//!
//! * **V1** ([`Reputation`], key [`ReputationKey::Reputation`]) is the Phase B layout:
//!   three outcome counters and nothing else.
//! * **V2** ([`ReputationV2`], key [`ReputationKey::ReputationV2`]) adds the fields a
//!   Phase C scorer needs in order to weight a party-attested history differently
//!   from an Attestor-corroborated one.
//!
//! Adding `ReputationV2` as a *new variant* of the existing `ReputationKey` enum does
//! not disturb the encoding of already-written keys: `#[contracttype]` encodes an enum
//! variant as its name (an `ScVal::Symbol`), not as an ordinal, so existing
//! `Reputation(addr)` entries remain byte-identical and readable after the upgrade.
//!
//! # Why migration is not performed inside the upgrade transaction
//!
//! Rewriting every stored row during the upgrade invocation would make the cost of an
//! upgrade proportional to the number of addresses Pactum has ever scored. On any
//! ledger with real data that exceeds Soroban's per-transaction resource limits, so an
//! "iterate everything atomically" migration is a design that only works while the
//! contract is empty. What *is* made atomic is the schema switch itself: `upgrade`
//! flips the stored schema version and swaps the executable in one invocation, so
//! every read after that transaction is served under V2 semantics regardless of which
//! rows have physically been rewritten.
//!
//! Physical rewrites then happen by two complementary routes:
//!
//! 1. **Lazily**, when a row is next written ([`update_reputation`] migrates the row
//!    it is about to mutate).
//! 2. **In bounded batches**, via [`migrate_reputation_batch`], so a DAO can drain the
//!    backlog proactively instead of waiting for organic writes.
//!
//! Reads never depend on which route got there first: [`get_reputation_v2`] projects
//! an un-migrated V1 row up to V2 on the fly, so a caller cannot observe the
//! difference between a migrated and an un-migrated address.
//!
//! # Archived entries
//!
//! A persistent entry whose TTL has lapsed is archived, and an archived entry is *not*
//! readable as absent: the host aborts the invocation the moment it is touched. On the
//! network the transaction is rejected before the contract runs at all, because every
//! key an invocation reads must be live and in its footprint. This was verified
//! against the SDK's test host rather than assumed — see
//! `test_upgrade::test_archived_row_aborts_the_invocation`.
//!
//! Two consequences shape the code below:
//!
//! * The `None` branch on a storage read means "never written", and only that. It is
//!   not, and cannot be, an archived-entry fallback.
//! * Migration therefore cannot heal an archived row on its own. The operator must
//!   include `RestoreFootprint` for those keys in the same transaction as the
//!   migration call; the runbook in `docs/upgradeability.md` covers how to find them.
//!
//! What the contract *does* guarantee is that it never fabricates history: an address
//! with no live row is left alone rather than being written as an all-zero V2 row,
//! so a later restore-then-migrate still recovers the true counters.

use crate::commitments::CommitmentStatus;
use crate::errors::Error;
use crate::events;
use crate::trust_score::{
    BASE_SCORE, BREACH_WEIGHT, BUCKET_SIZE_LEDGERS, FULFILLED_WEIGHT, LATE_WEIGHT, MAX_DECAY_STEPS,
    SCALE,
};
use crate::upgrade::{schema_version, MAX_MIGRATION_BATCH, SCHEMA_VERSION_V2};
use soroban_sdk::{contracttype, panic_with_error, Address, Bytes, Env, Vec};

#[path = "storage.rs"]
pub mod storage;
pub use storage::*;

/// Represents the aggregate reputation of an address as an issuer (V1 / Phase B).
///
/// Note: Reputation only reflects an address's role as `issuer` (the party who
/// made the commitment). It does not count counterparty-side stats.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reputation {
    pub fulfilled_count: u32,
    pub late_count: u32,
    pub breached_count: u32,
}

/// Attestor-enabled aggregate reputation (V2 / Phase C).
///
/// The three outcome counters carry over from V1 unchanged so that existing Trust
/// Scores are preserved exactly. The remaining fields describe *how* that history was
/// established, which is the distinction Phase C introduces.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationV2 {
    /// Commitments this address issued and fulfilled on time.
    pub fulfilled_count: u32,
    /// Commitments this address issued and fulfilled after the due date.
    pub late_count: u32,
    /// Commitments this address issued and breached.
    pub breached_count: u32,
    /// Outcomes established by a commitment party or by the arbitrator.
    ///
    /// Every Phase B outcome was established this way — there were no Attestors — so
    /// migrating a V1 row sets this to the sum of its three counters. Widened to `u64`
    /// so the sum of three `u32` counters is always exact.
    pub direct_count: u64,
    /// Outcomes corroborated by a registered Attestor. Always `0` for a row migrated
    /// from V1, because no Attestor existed when that history was recorded.
    pub attested_count: u64,
    /// Ledger timestamp at which this row was last written under the V2 schema.
    pub updated_at: u64,
    /// Schema version this row was last written under.
    pub version: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReputationKey {
    /// V1 (Phase B) row. Retained so pre-upgrade entries stay readable.
    Reputation(Address),
    /// V2 (Phase C) row.
    ReputationV2(Address),
}

/// Maps a V1 row onto the V2 schema.
///
/// This is the whole of the V1 → V2 field mapping, kept in one place so it can be
/// audited and tested in isolation from the storage plumbing.
pub fn project_v1_to_v2(v1: &Reputation, now: u64) -> ReputationV2 {
    ReputationV2 {
        fulfilled_count: v1.fulfilled_count,
        late_count: v1.late_count,
        breached_count: v1.breached_count,
        // Exact: three u32 values cannot overflow a u64 sum.
        direct_count: v1.fulfilled_count as u64 + v1.late_count as u64 + v1.breached_count as u64,
        attested_count: 0,
        updated_at: now,
        version: SCHEMA_VERSION_V2,
    }
}

/// Projects a V2 row back down to the V1 shape returned by `get_reputation`.
///
/// Existing integrators (the indexer, the JS SDK, `get_reputation`) keep receiving the
/// V1 struct across the upgrade; only the new `get_reputation_v2` entrypoint exposes
/// the additional fields.
pub fn project_v2_to_v1(v2: &ReputationV2) -> Reputation {
    Reputation {
        fulfilled_count: v2.fulfilled_count,
        late_count: v2.late_count,
        breached_count: v2.breached_count,
    }
}

fn zero_v1() -> Reputation {
    Reputation {
        fulfilled_count: 0,
        late_count: 0,
        breached_count: 0,
    }
}

fn zero_v2(now: u64) -> ReputationV2 {
    ReputationV2 {
        fulfilled_count: 0,
        late_count: 0,
        breached_count: 0,
        direct_count: 0,
        attested_count: 0,
        updated_at: now,
        version: SCHEMA_VERSION_V2,
    }
}

fn bump_ttl(env: &Env, key: &ReputationKey) {
    env.storage().persistent().extend_ttl(
        key,
        crate::commitments::TTL_THRESHOLD_LEDGERS,
        crate::commitments::TTL_EXTEND_LEDGERS,
    );
}

/// Reads the raw V1 row if one is present, extending its TTL.
fn read_v1(env: &Env, address: &Address) -> Option<Reputation> {
    let key = ReputationKey::Reputation(address.clone());
    let rep: Option<Reputation> = env.storage().persistent().get(&key);
    if rep.is_some() {
        bump_ttl(env, &key);
    }
    rep
}

/// Reads the raw V2 row if one is present, extending its TTL.
fn read_v2(env: &Env, address: &Address) -> Option<ReputationV2> {
    let key = ReputationKey::ReputationV2(address.clone());
    let rep: Option<ReputationV2> = env.storage().persistent().get(&key);
    if rep.is_some() {
        bump_ttl(env, &key);
    }
    rep
}

/// Returns the reputation for an address in the V1 shape.
///
/// Behaviour is stable across the upgrade: under V1 this reads the V1 row directly,
/// and under V2 it projects the V2 row (or an un-migrated V1 row) back down to the
/// same three counters. An address that has never been scored reads as all-zero.
pub fn get_reputation(env: &Env, address: Address) -> Reputation {
    if schema_version(env) < SCHEMA_VERSION_V2 {
        return read_v1(env, &address).unwrap_or_else(zero_v1);
    }
    project_v2_to_v1(&get_reputation_v2(env, address))
}

/// Returns the reputation for an address in the V2 (Attestor-enabled) shape.
///
/// Serves the correct V2 view whether or not the row has physically been migrated:
/// a V2 row is returned as stored, an un-migrated V1 row is projected up on the fly,
/// and an absent (never-written or archived) row reads as all-zero.
///
/// This function does not write. Migration is performed by [`update_reputation`] and
/// [`migrate_reputation_batch`], so a read-only simulation never mutates state beyond
/// the TTL extensions the contract already performs on every access.
pub fn get_reputation_v2(env: &Env, address: Address) -> ReputationV2 {
    let now = env.ledger().timestamp();

    if let Some(v2) = read_v2(env, &address) {
        return v2;
    }
    match read_v1(env, &address) {
        Some(v1) => project_v1_to_v2(&v1, now),
        None => zero_v2(now),
    }
}

/// Returns true if `address` still has a V1 row that has not been rewritten as V2.
///
/// Always false while the contract is on the V1 schema: nothing is pending until the
/// schema switch has happened.
pub fn migration_pending(env: &Env, address: Address) -> bool {
    if schema_version(env) < SCHEMA_VERSION_V2 {
        return false;
    }
    let has_v2 = env
        .storage()
        .persistent()
        .has(&ReputationKey::ReputationV2(address.clone()));
    if has_v2 {
        return false;
    }
    env.storage()
        .persistent()
        .has(&ReputationKey::Reputation(address))
}

/// Physically rewrites one address's V1 row as a V2 row.
///
/// Returns `true` if a row was migrated, `false` if there was nothing to do — either
/// the address is already on V2, or it was never scored. Idempotent, and safe to call
/// on an address that does not exist.
///
/// An *archived* row is a different case entirely: touching one aborts the invocation
/// before this function can observe it, so a batch containing an archived address
/// fails rather than silently skipping it. Restore those keys in the same transaction.
///
/// The V1 entry is removed once the V2 entry is written, so the row is stored once
/// rather than twice and the contract can never serve a stale V1 value. This makes
/// migration one-way: an executable rolled back to a V1-only build would read a
/// migrated address as all-zero. That is why rollback is handled by re-upgrading
/// forward rather than by reverting the Wasm — see `docs/upgradeability.md`.
///
/// # Panics
/// * [`Error::MigrationNotEnabled`] if the contract is still on the V1 schema.
pub fn migrate_reputation(env: &Env, address: Address) -> bool {
    if schema_version(env) < SCHEMA_VERSION_V2 {
        panic_with_error!(env, Error::MigrationNotEnabled);
    }

    let v2_key = ReputationKey::ReputationV2(address.clone());
    if env.storage().persistent().has(&v2_key) {
        return false;
    }

    let v1_key = ReputationKey::Reputation(address.clone());
    let v1: Reputation = match env.storage().persistent().get(&v1_key) {
        Some(v1) => v1,
        // Never written. (An archived row would have aborted the invocation on the
        // read above, so it cannot reach this branch.) Writing a zeroed V2 row here
        // would fabricate history, so do nothing.
        None => return false,
    };

    let v2 = project_v1_to_v2(&v1, env.ledger().timestamp());
    env.storage().persistent().set(&v2_key, &v2);
    bump_ttl(env, &v2_key);
    env.storage().persistent().remove(&v1_key);

    events::reputation_migrated(env, &address, &v2);
    true
}

/// Migrates a bounded batch of addresses from V1 to V2. Returns how many rows moved.
///
/// # Authorization
/// * Authorized caller: none — this entrypoint is permissionless.
/// * Why: migration is idempotent, cannot change any counter's value, and the caller
///   pays the fees. Leaving it open means any integrator can drain the backlog for
///   addresses it cares about instead of the DAO being a liveness bottleneck. There is
///   no state a caller can reach this way that [`update_reputation`] would not reach
///   anyway on the address's next write.
///
/// # Panics
/// * [`Error::MigrationNotEnabled`] if the contract is still on the V1 schema.
/// * [`Error::BatchTooLarge`] if `addresses` exceeds [`MAX_MIGRATION_BATCH`].
pub fn migrate_reputation_batch(env: &Env, addresses: Vec<Address>) -> u32 {
    if schema_version(env) < SCHEMA_VERSION_V2 {
        panic_with_error!(env, Error::MigrationNotEnabled);
    }
    if addresses.len() > MAX_MIGRATION_BATCH {
        panic_with_error!(env, Error::BatchTooLarge);
    }

    let mut migrated: u32 = 0;
    for address in addresses.iter() {
        if migrate_reputation(env, address) {
            migrated += 1;
        }
    }
    migrated
}

/// Restores an archived reputation entry for `address` and extends its TTL.
///
/// In the Soroban host the contract cannot call `RestoreFootprint` for a
/// persistent entry by itself — the caller must include the key in the
/// transaction's `RestoreFootprint` operation *before* invoking this function.
/// What this function does is:
///
/// 1. Touch both the V2 and V1 reputation keys so the host registers them in
///    the footprint (a required prerequisite for `RestoreFootprint`).
/// 2. Extend their TTL to the full [`TTL_EXTEND_LEDGERS`] so the restored data
///    survives long after the call returns.
/// 3. Also restore the matching [`crate::trust_score::TrustKey::TrustHistory`]
///    entry so `get_trust_score` keeps working without a separate call.
///
/// The function is **permissionless**: anyone — the indexer, a lending protocol,
/// an end user — may pay the fee to unarchive another address's data.
///
/// # Returns
/// * `true`  if at least one live entry was found and its TTL extended.
/// * `false` if no live row exists for this address (never written, or the
///   `RestoreFootprint` operation in the same transaction was omitted and the
///   host silently made the entry inaccessible).
///
/// # Usage pattern (off-chain)
/// ```text
/// // 1. Build a transaction with:
/// //      - Operation: RestoreFootprint (keys: ReputationKey::ReputationV2(address),
/// //                                          ReputationKey::Reputation(address),
/// //                                          TrustKey::TrustHistory(address))
/// //      - Operation: InvokeContractFunction restore_reputation(address)
/// // 2. Sign and submit.
/// // 3. Now get_trust_score / get_reputation work again.
/// ```
pub fn restore_reputation(env: &Env, address: Address) -> bool {
    let v2_key = ReputationKey::ReputationV2(address.clone());
    let v1_key = ReputationKey::Reputation(address.clone());
    let trust_key = crate::trust_score::TrustKey::TrustHistory(address.clone());

    let mut restored = false;

    // Touch and extend the V2 row if it is live (post-RestoreFootprint).
    if env.storage().persistent().has(&v2_key) {
        bump_ttl(env, &v2_key);
        restored = true;
    }

    // Touch and extend the legacy V1 row if it is still present (not yet
    // migrated, or the contract is still on schema V1).
    if env.storage().persistent().has(&v1_key) {
        bump_ttl(env, &v1_key);
        restored = true;
    }

    // Extend the trust-history entry so get_trust_score keeps working.
    if env.storage().persistent().has(&trust_key) {
        env.storage().persistent().extend_ttl(
            &trust_key,
            crate::commitments::TTL_THRESHOLD_LEDGERS,
            crate::commitments::TTL_EXTEND_LEDGERS,
        );
        restored = true;
    }

    let restored_v2 = env.storage().persistent().has(&v2_key);
    events::reputation_restored(env, &address, restored_v2);

    restored
}

/// Applies `outcome` to `issuer`'s reputation.
///
/// `increment` is true when adding an outcome (e.g., in `attest` or `resolve_dispute`),
/// and false when removing an outcome (e.g., when a dispute is raised).
///
/// Under the V2 schema this is also the lazy-migration point: the row is rewritten in
/// the V2 layout before being mutated, so an address that is still on V1 migrates on
/// its next scored outcome without any operator involvement.
pub fn update_reputation(env: &Env, issuer: Address, outcome: CommitmentStatus, increment: bool) {
    if schema_version(env) < SCHEMA_VERSION_V2 {
        update_reputation_v1(env, issuer, outcome, increment);
    } else {
        update_reputation_v2(env, issuer, outcome, increment);
    }
}

fn update_reputation_v1(env: &Env, issuer: Address, outcome: CommitmentStatus, increment: bool) {
    let mut rep = read_v1(env, &issuer).unwrap_or_else(zero_v1);

    apply_outcome(
        &mut rep.fulfilled_count,
        &mut rep.late_count,
        &mut rep.breached_count,
        outcome,
        increment,
    );

    let key = ReputationKey::Reputation(issuer);
    env.storage().persistent().set(&key, &rep);
    bump_ttl(env, &key);
}

fn update_reputation_v2(env: &Env, issuer: Address, outcome: CommitmentStatus, increment: bool) {
    // Lazy migration: fold any un-migrated V1 row into the V2 layout, then drop it.
    migrate_reputation(env, issuer.clone());

    let now = env.ledger().timestamp();
    let mut rep = read_v2(env, &issuer).unwrap_or_else(|| zero_v2(now));

    let counted = apply_outcome(
        &mut rep.fulfilled_count,
        &mut rep.late_count,
        &mut rep.breached_count,
        outcome,
        increment,
    );

    if counted {
        // Every outcome this executable records is established by a commitment party
        // or the arbitrator; Attestor-sourced outcomes arrive with the Phase C
        // executable and increment `attested_count` instead.
        rep.direct_count = if increment {
            rep.direct_count.saturating_add(1)
        } else {
            rep.direct_count.saturating_sub(1)
        };
    }
    rep.updated_at = now;
    rep.version = SCHEMA_VERSION_V2;

    let key = ReputationKey::ReputationV2(issuer);
    env.storage().persistent().set(&key, &rep);
    bump_ttl(env, &key);
}

/// Applies an outcome to the three shared counters. Returns whether it counted.
fn apply_outcome(
    fulfilled: &mut u32,
    late: &mut u32,
    breached: &mut u32,
    outcome: CommitmentStatus,
    increment: bool,
) -> bool {
    let slot = match outcome {
        CommitmentStatus::Fulfilled => fulfilled,
        CommitmentStatus::Late => late,
        CommitmentStatus::Breached => breached,
        _ => return false,
    };
    *slot = if increment {
        slot.saturating_add(1)
    } else {
        slot.saturating_sub(1)
    };
    true
}

// =============================================================================
// Time-Weighted Average Reputation (TWAR) Segment Tree (Issue #295)
// =============================================================================

/// Fixed-point scale factor applied to raw outcome weights inside [`TWARSegmentTree`].
pub const TWAR_OUTCOME_SCALE: i64 = 1_000_000;

/// Three-point Lagrange quadratic coefficient $A = 3.5 - 2\sqrt{2} \approx 0.67157287525$
/// in Q32 (`floor((3.5 - 2 * sqrt(2)) * 2^32)`), chosen so the polynomial
/// $W(x) = 1 - A\,x + B\,x^2$ matches $2^{-x}$ at $x = 0$, $x = 0.5$, and $x = 1.0$.
const LIN_DECAY_Q32: u64 = 2_884_383_281;

/// Quadratic interpolation coefficient $B = A - \frac{1}{2}$ in Q32 so that
/// $W(0) = 1.0$, $W(0.5) = 2^{-0.5}$, and $W(1.0) = 0.5$ with strict monotonicity on $[0, 1]$.
const QUAD_DECAY_Q32: u64 = LIN_DECAY_Q32 - (SCALE >> 1);

/// Computes the Q32 fixed-point exponential half-life decay weight
/// $W(\Delta L) = \lfloor 2^{32} \cdot 2^{-\Delta L / H} \rfloor \in [0, 2^{32}]$
/// for a ledger sequence delta `delta_ledgers` and half-life `half_life_ledgers`.
///
/// * At exact multiples $\Delta L = k \cdot H$, returns `SCALE >> k` (exact power-of-two halving).
/// * Between multiples, uses a 3-point quadratic interpolation on the fractional remainder
///   $x = (\Delta L \bmod H) / H \in [0, 1)$ with zero floating-point operations.
/// * At or beyond `MAX_DECAY_STEPS` (32 half-lives), floors cleanly to `0`.
#[inline]
pub fn decay_weight_q32(delta_ledgers: u32, half_life_ledgers: u32) -> u64 {
    if delta_ledgers == 0 {
        return SCALE;
    }
    let half_life = if half_life_ledgers == 0 {
        TWAR_DEFAULT_HALF_LIFE_LEDGERS
    } else {
        half_life_ledgers
    };

    let steps = delta_ledgers / half_life;
    if steps >= MAX_DECAY_STEPS {
        return 0;
    }

    let rem = (delta_ledgers % half_life) as u64;
    if rem == 0 {
        return SCALE >> steps;
    }

    // Fractional position u = floor((rem << 32) / half_life) in [0, 2^32).
    let u = (rem << 32) / (half_life as u64);
    let linear = ((LIN_DECAY_Q32 as u128 * u as u128) >> 32) as u64;
    let u_sq = ((u as u128 * u as u128) >> 32) as u64;
    let quad = ((QUAD_DECAY_Q32 as u128 * u_sq as u128) >> 32) as u64;
    let frac_weight = SCALE.saturating_sub(linear).saturating_add(quad);

    frac_weight >> steps
}

/// Applies exponential half-life decay to a signed reputation score `value` over
/// `delta_ledgers` ledgers with half-life `half_life_ledgers`.
///
/// Truncates magnitude toward zero so positive and negative reputation deltas
/// decay symmetrically and eventually reach `0` at `>= 32` half-lives without
/// leaving a `-1` arithmetic shift residual.
#[inline]
pub fn half_life_decay(value: i64, delta_ledgers: u32, half_life_ledgers: u32) -> i64 {
    if value == 0 || delta_ledgers == 0 {
        return value;
    }
    let weight = decay_weight_q32(delta_ledgers, half_life_ledgers);
    if weight == 0 {
        return 0;
    }
    if weight >= SCALE {
        return value;
    }

    let abs_val = value.unsigned_abs() as u128;
    let decayed_abs = ((abs_val * (weight as u128)) >> 32) as u64;
    if value < 0 {
        if decayed_abs > i64::MAX as u64 {
            i64::MIN
        } else {
            -(decayed_abs as i64)
        }
    } else {
        decayed_abs.min(i64::MAX as u64) as i64
    }
}

/// Merges two child [`TwarNode`]s in $O(1)$ by decaying the older child to the
/// newer child's `anchor_ledger` before summing with saturation.
#[inline]
fn merge_twar_nodes(left: TwarNode, right: TwarNode, half_life_ledgers: u32) -> TwarNode {
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let anchor_ledger = left.anchor_ledger.max(right.anchor_ledger);
    let left_delta = anchor_ledger.saturating_sub(left.anchor_ledger);
    let right_delta = anchor_ledger.saturating_sub(right.anchor_ledger);

    let left_decayed = half_life_decay(left.weighted_score, left_delta, half_life_ledgers);
    let right_decayed = half_life_decay(right.weighted_score, right_delta, half_life_ledgers);

    TwarNode {
        weighted_score: left_decayed.saturating_add(right_decayed),
        anchor_ledger,
        event_count: left.event_count.saturating_add(right.event_count),
    }
}

/// Updatable Time-Weighted Average Reputation (TWAR) Segment Tree backed by a
/// single contiguous 1,024-byte slice (`[u8; TWAR_PACKED_BYTES_LEN]`).
///
/// * **$O(\log N)$ Point Updates**: Updates one of the `TWAR_LEAF_CAPACITY` (32)
///   leaves and recomputes only its $\log_2(32) = 5$ ancestors in place without
///   tree rebalancing or heap allocation.
/// * **$O(\log N)$ Range Aggregation Queries**: Decomposes `[start_bucket, end_bucket]`
///   into at most $2 \log_2(32) = 10$ canonical segment tree nodes and decays each
///   visited node to `query_ledger`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TWARSegmentTree {
    buf: [u8; TWAR_PACKED_BYTES_LEN],
}

impl Default for TWARSegmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl TWARSegmentTree {
    /// Creates an empty `TWARSegmentTree` with [`TWAR_DEFAULT_HALF_LIFE_LEDGERS`].
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: init_packed_buffer(TWAR_DEFAULT_HALF_LIFE_LEDGERS),
        }
    }

    /// Creates an empty `TWARSegmentTree` with a custom `half_life_ledgers` period.
    #[inline]
    pub fn with_half_life(half_life_ledgers: u32) -> Self {
        Self {
            buf: init_packed_buffer(half_life_ledgers),
        }
    }

    /// Unpacks a `TWARSegmentTree` from a Soroban [`Bytes`] slice in $O(1)$.
    #[inline]
    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            buf: unpack_tree_bytes(bytes),
        }
    }

    /// Packs this `TWARSegmentTree` into a contiguous Soroban [`Bytes`] slice.
    #[inline]
    pub fn to_bytes(&self, env: &Env) -> Bytes {
        pack_tree_bytes(env, &self.buf)
    }

    /// Loads `address`'s `TWARSegmentTree` from Soroban instance storage, or returns
    /// an initialized empty tree if none has been stored yet.
    pub fn load(env: &Env, address: &Address) -> Self {
        match load_packed_twar_bytes(env, address) {
            Some(bytes) => Self::from_bytes(&bytes),
            None => Self::new(),
        }
    }

    /// Persists this `TWARSegmentTree` into Soroban instance storage under `address`.
    pub fn save(&self, env: &Env, address: &Address) {
        let bytes = self.to_bytes(env);
        save_packed_twar_bytes(env, address, &bytes);
    }

    /// Returns the decoded [`TwarHeader`] from slot `0`.
    #[inline]
    pub fn header(&self) -> TwarHeader {
        decode_header(&self.buf)
    }

    /// Returns the configured half-life in ledgers.
    #[inline]
    pub fn half_life_ledgers(&self) -> u32 {
        decode_header(&self.buf).half_life_ledgers
    }

    /// Returns the highest ledger sequence observed by this tree.
    #[inline]
    pub fn last_ledger(&self) -> u32 {
        decode_header(&self.buf).last_ledger
    }

    /// Returns the saturating total number of point updates applied to this tree.
    #[inline]
    pub fn total_updates(&self) -> u32 {
        decode_header(&self.buf).total_updates
    }

    /// Returns a reference to the raw 1,024-byte packed slice.
    #[inline]
    pub fn as_packed_slice(&self) -> &[u8; TWAR_PACKED_BYTES_LEN] {
        &self.buf
    }

    /// Decodes a single segment tree node at 1-based index `node_idx` (`1..64`).
    #[inline]
    pub fn node(&self, node_idx: usize) -> TwarNode {
        decode_node(&self.buf, node_idx)
    }

    /// Decodes a leaf bucket node (`0..TWAR_LEAF_CAPACITY`).
    #[inline]
    pub fn leaf_node(&self, bucket_idx: u32) -> TwarNode {
        let idx = (bucket_idx as usize) & (TWAR_LEAF_CAPACITY - 1);
        decode_node(&self.buf, TWAR_LEAF_CAPACITY + idx)
    }

    /// Applies an $O(\log N)$ point update to `bucket_idx` at `ledger_seq`.
    ///
    /// If `bucket_idx >= TWAR_LEAF_CAPACITY`, wraps modulo `TWAR_LEAF_CAPACITY`
    /// while decaying the existing slot's score forward to `ledger_seq` so
    /// older historical weight is folded losslessly without growing the tree.
    pub fn update_point(&mut self, bucket_idx: u32, delta_score: i64, ledger_seq: u32) {
        self.apply_point_delta(bucket_idx, delta_score, ledger_seq, true);
    }

    /// Retracts a previously recorded `delta_score` from `bucket_idx` at `ledger_seq`,
    /// decrementing the leaf's `event_count` with `saturating_sub(1)`.
    pub fn retract_point(&mut self, bucket_idx: u32, delta_score: i64, ledger_seq: u32) {
        self.apply_point_delta(bucket_idx, delta_score.saturating_neg(), ledger_seq, false);
    }

    fn apply_point_delta(
        &mut self,
        bucket_idx: u32,
        delta_score: i64,
        ledger_seq: u32,
        increment_count: bool,
    ) {
        let mut hdr = decode_header(&self.buf);
        let half_life = hdr.half_life_ledgers;

        let leaf_offset = (bucket_idx as usize) & (TWAR_LEAF_CAPACITY - 1);
        let leaf_idx = TWAR_LEAF_CAPACITY + leaf_offset;

        let prev_leaf = decode_node(&self.buf, leaf_idx);
        let target_ledger = if prev_leaf.is_empty() {
            ledger_seq
        } else {
            prev_leaf.anchor_ledger.max(ledger_seq)
        };
        let delta_ledgers = target_ledger.saturating_sub(prev_leaf.anchor_ledger);
        let decayed_prev = half_life_decay(prev_leaf.weighted_score, delta_ledgers, half_life);

        let updated_score = decayed_prev.saturating_add(delta_score);
        let updated_count = if increment_count {
            prev_leaf.event_count.saturating_add(1)
        } else {
            prev_leaf.event_count.saturating_sub(1)
        };

        let new_leaf = TwarNode {
            weighted_score: updated_score,
            anchor_ledger: target_ledger,
            event_count: updated_count,
        };
        encode_node(&mut self.buf, leaf_idx, new_leaf);

        // Recompute the O(log N) ancestor path up to root (index 1).
        let mut parent = leaf_idx >> 1;
        while parent >= 1 {
            let left = decode_node(&self.buf, parent << 1);
            let right = decode_node(&self.buf, (parent << 1) | 1);
            let merged = merge_twar_nodes(left, right, half_life);
            encode_node(&mut self.buf, parent, merged);
            parent >>= 1;
        }

        hdr.last_ledger = hdr.last_ledger.max(target_ledger);
        hdr.total_updates = if increment_count {
            hdr.total_updates.saturating_add(1)
        } else {
            hdr.total_updates.saturating_sub(1)
        };
        encode_header(&mut self.buf, hdr);
    }

    /// Queries a single leaf bucket `bucket_idx` decayed to `query_ledger`.
    #[inline]
    pub fn query_point(&self, bucket_idx: u32, query_ledger: u32) -> i64 {
        let leaf = self.leaf_node(bucket_idx);
        if leaf.weighted_score == 0 {
            return 0;
        }
        let delta = query_ledger.saturating_sub(leaf.anchor_ledger);
        half_life_decay(leaf.weighted_score, delta, self.half_life_ledgers())
    }

    /// Executes an $O(\log N)$ inclusive range aggregation query over leaf buckets
    /// `[start_bucket, end_bucket]`, decaying each canonical segment node to `query_ledger`.
    pub fn query_range(&self, start_bucket: u32, end_bucket: u32, query_ledger: u32) -> i64 {
        if start_bucket > end_bucket || start_bucket >= TWAR_LEAF_CAPACITY as u32 {
            return 0;
        }
        let half_life = self.half_life_ledgers();
        let start = start_bucket as usize;
        let end = (end_bucket as usize).min(TWAR_LEAF_CAPACITY - 1);

        let mut l = TWAR_LEAF_CAPACITY + start;
        let mut r = TWAR_LEAF_CAPACITY + end;
        let mut acc: i64 = 0;

        while l <= r {
            if (l & 1) == 1 {
                let node = decode_node(&self.buf, l);
                if node.weighted_score != 0 {
                    let delta = query_ledger.saturating_sub(node.anchor_ledger);
                    let decayed = half_life_decay(node.weighted_score, delta, half_life);
                    acc = acc.saturating_add(decayed);
                }
                l += 1;
            }
            if (r & 1) == 0 {
                let node = decode_node(&self.buf, r);
                if node.weighted_score != 0 {
                    let delta = query_ledger.saturating_sub(node.anchor_ledger);
                    let decayed = half_life_decay(node.weighted_score, delta, half_life);
                    acc = acc.saturating_add(decayed);
                }
                r -= 1;
            }
            l >>= 1;
            r >>= 1;
        }

        acc
    }

    /// Queries the total decayed weighted score across all buckets at `query_ledger`
    /// in $O(1)$ by reading the root node (`node_idx = 1`).
    #[inline]
    pub fn query_total(&self, query_ledger: u32) -> i64 {
        let root = decode_node(&self.buf, 1);
        if root.weighted_score == 0 {
            return 0;
        }
        let delta = query_ledger.saturating_sub(root.anchor_ledger);
        half_life_decay(root.weighted_score, delta, self.half_life_ledgers())
    }

    /// Records a [`CommitmentStatus`] settlement outcome at `ledger_seq`, mapping
    /// `bucket = (ledger_seq / BUCKET_SIZE_LEDGERS) % TWAR_LEAF_CAPACITY`.
    pub fn record_outcome(&mut self, outcome: CommitmentStatus, increment: bool, ledger_seq: u32) {
        let base_delta: i64 = match outcome {
            CommitmentStatus::Fulfilled => (FULFILLED_WEIGHT as i64) * TWAR_OUTCOME_SCALE,
            CommitmentStatus::Late => -(LATE_WEIGHT as i64) * TWAR_OUTCOME_SCALE,
            CommitmentStatus::Breached => -(BREACH_WEIGHT as i64) * TWAR_OUTCOME_SCALE,
            _ => return,
        };
        let bucket_idx = (ledger_seq / BUCKET_SIZE_LEDGERS) % (TWAR_LEAF_CAPACITY as u32);
        if increment {
            self.update_point(bucket_idx, base_delta, ledger_seq);
        } else {
            self.retract_point(bucket_idx, base_delta, ledger_seq);
        }
    }

    /// Computes the normalized `0..=100` Time-Weighted Average Reputation (TWAR)
    /// score at `query_ledger` anchored around [`BASE_SCORE`] (50).
    #[inline]
    pub fn twar_score(&self, query_ledger: u32) -> u32 {
        let total_scaled = self.query_total(query_ledger);
        let net_points = total_scaled / TWAR_OUTCOME_SCALE;
        let raw = (BASE_SCORE as i64).saturating_add(net_points);
        if raw <= 0 {
            0
        } else if raw >= 100 {
            100
        } else {
            raw as u32
        }
    }
}

/// Performs a storage-backed point update on `address`'s packed `TWARSegmentTree`
/// in Soroban instance storage.
pub fn update_twar_point(
    env: &Env,
    address: &Address,
    bucket_idx: u32,
    delta_score: i64,
    ledger_seq: u32,
) {
    let mut tree = TWARSegmentTree::load(env, address);
    tree.update_point(bucket_idx, delta_score, ledger_seq);
    tree.save(env, address);
}

/// Performs a storage-backed range query `[start_bucket, end_bucket]` on `address`'s
/// packed `TWARSegmentTree` decayed to `query_ledger`.
pub fn query_twar_range(
    env: &Env,
    address: &Address,
    start_bucket: u32,
    end_bucket: u32,
    query_ledger: u32,
) -> i64 {
    let tree = TWARSegmentTree::load(env, address);
    tree.query_range(start_bucket, end_bucket, query_ledger)
}

/// Computes `address`'s `0..=100` TWAR score at the current ledger sequence.
pub fn get_twar_score(env: &Env, address: &Address) -> u32 {
    let tree = TWARSegmentTree::load(env, address);
    tree.twar_score(env.ledger().sequence())
}
