use soroban_sdk::{
    contracttype, panic_with_error, xdr::ToXdr, Address, Bytes, BytesN, Env, Map, Symbol,
    TryFromVal, TryIntoVal, Val, Vec,
};

/// The default dispute window in seconds (7 days = 604,800 seconds).
/// A party may raise a dispute within this duration after an attestation occurs.
pub const DISPUTE_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;

/// The threshold in ledgers below which we extend the TTL. (Approx 14 days at 5s/ledger = 241,920)
pub const TTL_THRESHOLD_LEDGERS: u32 = 14 * 17280;

/// The amount in ledgers to extend the TTL to. (Approx 30 days at 5s/ledger = 518,400)
pub const TTL_EXTEND_LEDGERS: u32 = 30 * 17280;

/// The largest number of milestones a single commitment may be split into.
pub const MAX_MILESTONES: u32 = 256;

/// Amount of the dispute token required to raise a dispute (10 XLM in stroops).
pub const DISPUTE_STAKE_AMOUNT: i128 = 100_000_000; // 10 XLM (1 XLM = 10_000_000 stroops)

/// Represents the current lifecycle state of a commitment.
///
/// # Variants
/// * `Pending` - The commitment has been created and is awaiting fulfillment or breach.
/// * `Fulfilled` - The commitment was successfully fulfilled.
/// * `Late` - The commitment was fulfilled after the due date.
/// * `Breached` - The commitment was breached or defaulted upon.
/// * `Disputed` - The commitment outcome is disputed by one of the parties.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentStatus {
    /// Commitment has been created and is awaiting fulfillment or breach.
    Pending,
    /// Commitment was successfully fulfilled.
    Fulfilled,
    /// Commitment was fulfilled after the due date.
    Late,
    /// Commitment was breached or defaulted upon.
    Breached,
    /// Commitment outcome is disputed by one of the parties.
    Disputed,
}

/// A registered recurring or ongoing commitment between two parties on Stellar.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// Unique identifier for this commitment.
    pub id: u64,
    /// The party making the commitment.
    pub issuer: Address,
    /// The party the commitment is owed to.
    pub counterparty: Address,
    /// Hash of the off-chain terms/description.
    pub terms_hash: BytesN<32>,
    /// Unix timestamp (seconds) when the commitment is due.
    pub due_at: u64,
    /// Current lifecycle status of the commitment.
    pub status: CommitmentStatus,
    /// Unix timestamp (seconds) when the commitment was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the commitment was attested, if it has been attested.
    ///
    /// For a milestone commitment this is the timestamp of the attestation that
    /// resolved the whole commitment, not of an individual milestone.
    pub attested_at: Option<u64>,
    /// The address of the custom resolver delegated to resolve disputes for this commitment.
    pub resolver_address: Address,
    /// Optional designated oracle for automated attestation.
    pub oracle: Option<Address>,
    /// Optional identifier for the schema used to generate terms_hash.
    pub schema_id: Option<u32>,
    /// The panel of staked attestors that vote on disputes for this commitment.
    /// An empty panel keeps the commitment on the single-resolver dispute path.
    pub attestors: Vec<Address>,
    /// Bitpacked `(milestone_count, milestones_attested, late_milestones,
    /// vote_threshold)`, each a 16-bit lane, in that order from the
    /// least-significant bits up. Packing these four small counters into a
    /// single storage field (instead of four separate `u32` struct fields)
    /// shrinks every `Commitment`'s footprint in persistent storage, which is
    /// read and rewritten on every `create`/`attest` call. Use the
    /// [`Commitment::milestone_count`] family of accessors rather than
    /// unpacking this field directly.
    pub counters: u64,
}

/// Bit width of each lane packed into [`Commitment::counters`].
const COUNTER_LANE_BITS: u32 = 16;
const COUNTER_LANE_MASK: u64 = (1u64 << COUNTER_LANE_BITS) - 1;

impl Commitment {
    /// Packs the four milestone/vote counters into a single `u64`.
    ///
    /// Panics with [`crate::errors::Error::Overflow`] if any value exceeds
    /// `u16::MAX`; in practice `milestone_count` is already capped at
    /// [`MAX_MILESTONES`] and `vote_threshold` at the (similarly small) size
    /// of the attestor panel, so this only guards against a future caller
    /// raising those caps without revisiting the packed width.
    pub fn pack_counters(
        env: &soroban_sdk::Env,
        milestone_count: u32,
        milestones_attested: u32,
        late_milestones: u32,
        vote_threshold: u32,
    ) -> u64 {
        for v in [
            milestone_count,
            milestones_attested,
            late_milestones,
            vote_threshold,
        ] {
            if v > u16::MAX as u32 {
                soroban_sdk::panic_with_error!(env, crate::errors::Error::Overflow);
            }
        }
        (milestone_count as u64)
            | ((milestones_attested as u64) << COUNTER_LANE_BITS)
            | ((late_milestones as u64) << (2 * COUNTER_LANE_BITS))
            | ((vote_threshold as u64) << (3 * COUNTER_LANE_BITS))
    }

    /// How many milestones the commitment is split into. A single-shot
    /// commitment has exactly one.
    pub fn milestone_count(&self) -> u32 {
        (self.counters & COUNTER_LANE_MASK) as u32
    }

    /// How many milestones have been attested so far.
    pub fn milestones_attested(&self) -> u32 {
        ((self.counters >> COUNTER_LANE_BITS) & COUNTER_LANE_MASK) as u32
    }

    /// How many of the attested milestones came in `Late`.
    pub fn late_milestones(&self) -> u32 {
        ((self.counters >> (2 * COUNTER_LANE_BITS)) & COUNTER_LANE_MASK) as u32
    }

    /// How many matching attestor votes are required to resolve a dispute.
    /// Must be between 1 and `attestors.len()` when a panel is configured,
    /// and zero when it is not.
    pub fn vote_threshold(&self) -> u32 {
        ((self.counters >> (3 * COUNTER_LANE_BITS)) & COUNTER_LANE_MASK) as u32
    }

    /// Records one more attested milestone, and one more late milestone if
    /// `late` is set.
    pub fn record_milestone_attested(&mut self, env: &soroban_sdk::Env, late: bool) {
        self.counters = Self::pack_counters(
            env,
            self.milestone_count(),
            self.milestones_attested().saturating_add(1),
            self.late_milestones() + u32::from(late),
            self.vote_threshold(),
        );
    }
}

/// Legacy representation of a Commitment prior to custom resolver support.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCommitment {
    /// Unique identifier for this commitment.
    pub id: u64,
    /// The party making the commitment.
    pub issuer: Address,
    /// The party the commitment is owed to.
    pub counterparty: Address,
    /// Hash of the off-chain terms/description.
    pub terms_hash: BytesN<32>,
    /// Unix timestamp (seconds) when the commitment is due.
    pub due_at: u64,
    /// Current lifecycle status of the commitment.
    pub status: CommitmentStatus,
    /// Unix timestamp (seconds) when the commitment was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the commitment was attested, if it has been attested.
    pub attested_at: Option<u64>,
    /// Optional designated oracle for automated attestation.
    pub oracle: Option<Address>,
    /// Optional identifier for the schema used to generate terms_hash.
    pub schema_id: Option<u32>,
}

/// Storage keys used for persisting commitments and contract state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Persistent storage key for a Commitment by its unique ID.
    Commitment(u64),
    /// Persistent storage key for the attested outcome of a single milestone,
    /// keyed by commitment ID and zero-based milestone index.
    Milestone(u64, u32),
    /// Instance storage key for the incrementing counter of IDs.
    NextId,
    /// Instance storage key for the set of designated arbitrators.
    ///
    /// A `Vec<Address>` so disputes can be settled by a majority of the
    /// committee instead of a single point of trust.
    ArbitratorSet,
    /// Legacy instance storage key for a single designated arbitrator.
    ///
    /// Only written by pre-multi-arbitrator deployments; read once to lazily
    /// migrate into [`DataKey::ArbitratorSet`].
    Arbitrator,
    /// Instance storage key for the protocol paused (emergency halt) flag.
    Paused,
    /// Persistent storage key for the running vote tally of a disputed
    /// commitment, keyed by commitment ID.
    Votes(u64),
    /// Persistent storage key for an attestor's staking record.
    Stake(Address),
    /// Instance storage key for the address of the staking (vault) token.
    StakingToken,
    /// Persistent storage key for a single attestor's vote on a disputed
    /// commitment, keyed by commitment ID and attestor address.
    VoteRecord(u64, Address),
    /// Persistent storage key for the running vote tally of a disputed
    /// commitment.
    DisputeTally(u64),
    /// Persistent storage key for the escrowed dispute stake, keyed by
    /// commitment ID. Stores the i128 amount locked at dispute time.
    DisputeStake(u64),
    /// Instance storage key for the address of the token used for
    /// dispute staking (defaults to native XLM).
    DisputeToken,
    /// Instance storage key for the contract admin address.
    Admin,
    /// Instance storage key for the ordered pool of staked attestor addresses.
    StakedAttestorPool,
    /// Persistent storage key for the cryptographically bound VRF dispute panel
    /// record assigned to a commitment ID.
    DisputePanel(u64),
}

/// Cryptographically bound VRF dispute panel assignment for a commitment (Issue #308).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputePanelRecord {
    /// Commitment ID that this panel is bound to.
    pub commitment_id: u64,
    /// Deterministic VRF seed derived at the dispute declaration ledger sequence.
    pub vrf_seed: BytesN<32>,
    /// Ledger sequence at which the dispute panel was derived and locked.
    pub ledger_sequence: u32,
    /// Ledger timestamp at which the dispute panel was derived and locked.
    pub ledger_timestamp: u64,
    /// Selected unique active staked attestors ordered by VRF sampling round.
    pub panel: Vec<Address>,
    /// Required M-of-N vote threshold for panel resolution.
    pub vote_threshold: u32,
    /// SHA-256 commitment binding `(commitment_id, vrf_seed, ledger_sequence, vote_threshold, panel)`.
    pub binding_hash: BytesN<32>,
}

/// Running tally of arbitrator votes on a single disputed commitment.
///
/// Votes are keyed by voter address so each arbitrator can vote at most once,
/// and the per-outcome counters make the majority check O(1) on every vote
/// rather than scanning prior votes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeVotes {
    /// Votes cast for `Fulfilled`.
    pub fulfilled: u32,
    /// Votes cast for `Late`.
    pub late: u32,
    /// Votes cast for `Breached`.
    pub breached: u32,
    /// Arbitrators that have already voted, mapped to the outcome they chose.
    pub voters: Map<Address, CommitmentStatus>,
}

impl DisputeVotes {
    /// Creates an empty tally for a new dispute.
    pub fn new(env: &Env) -> Self {
        Self {
            fulfilled: 0,
            late: 0,
            breached: 0,
            voters: Map::new(env),
        }
    }

    /// Returns the number of votes currently cast for `outcome`.
    pub fn count(&self, outcome: CommitmentStatus) -> u32 {
        match outcome {
            CommitmentStatus::Fulfilled => self.fulfilled,
            CommitmentStatus::Late => self.late,
            CommitmentStatus::Breached => self.breached,
            // Pending / Disputed are rejected before a vote is ever recorded.
            _ => 0,
        }
    }

    /// Records one vote for `outcome` by `voter`.
    ///
    /// Callers must check [`DisputeVotes::voters`] for an existing vote first;
    /// this method does not guard against double voting.
    pub fn record(&mut self, voter: &Address, outcome: CommitmentStatus) {
        self.voters.set(voter.clone(), outcome);
        match outcome {
            CommitmentStatus::Fulfilled => self.fulfilled = self.fulfilled.saturating_add(1),
            CommitmentStatus::Late => self.late = self.late.saturating_add(1),
            CommitmentStatus::Breached => self.breached = self.breached.saturating_add(1),
            _ => {}
        }
    }
}

/// Loads the arbitrator set, panicking with [`crate::errors::Error::NotInitialized`]
/// if the contract has not been initialized.
///
/// Lazily migrates a pre-multi-arbitrator deployment: a contract initialized
/// under the old single-arbitrator model stored a bare `Address` under
/// [`DataKey::Arbitrator`]. It is wrapped into a one-member set and persisted
/// on first read, mirroring the lazy-migration pattern used for commitments
/// and reputation rows.
pub fn arbitrators(env: &Env) -> Vec<Address> {
    if let Some(set) = env
        .storage()
        .instance()
        .get::<DataKey, Vec<Address>>(&DataKey::ArbitratorSet)
    {
        return set;
    }

    let legacy: Address = env
        .storage()
        .instance()
        .get(&DataKey::Arbitrator)
        .unwrap_or_else(|| panic_with_error!(env, crate::errors::Error::NotInitialized));

    let set = soroban_sdk::vec![env, legacy];
    env.storage().instance().set(&DataKey::ArbitratorSet, &set);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
    set
}

/// Loads the admin address, panicking with [`crate::errors::Error::NotInitialized`]
/// if the contract has not been initialized.
pub fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, crate::errors::Error::NotInitialized))
}

/// Verifies that the caller is the admin, panicking with [`crate::errors::Error::NotAdmin`]
/// if they are not.
pub fn require_admin(env: &Env, caller: &Address) {
    let admin_address = admin(env);
    if admin_address != *caller {
        panic_with_error!(env, crate::errors::Error::NotAdmin);
    }
}

/// Loads a commitment from persistent storage, transparently migrating legacy records
/// that were stored before `resolver_address` or the milestone counters were added,
/// or before the milestone/vote counters were bitpacked into [`Commitment::counters`].
/// Legacy records inherit the contract's designated arbitrator address as their
/// fallback `resolver_address`, and become single-milestone commitments whose
/// milestone is already attested if the record was resolved.
pub fn get_commitment_record(env: &soroban_sdk::Env, id: u64) -> Option<Commitment> {
    let val: Val = env.storage().persistent().get(&DataKey::Commitment(id))?;

    let map = Map::<Symbol, Val>::try_from_val(env, &val).ok()?;
    let counters_sym = Symbol::new(env, "counters");

    if map.contains_key(counters_sym) {
        return Commitment::try_from_val(env, &val).ok();
    }

    let resolver_sym = Symbol::new(env, "resolver_address");
    let milestone_sym = Symbol::new(env, "milestone_count");
    let attestors_sym = Symbol::new(env, "attestors");
    let threshold_sym = Symbol::new(env, "vote_threshold");

    // Intermediate record: written after milestone/attestor-voting support was
    // added but before those counters were bitpacked. All four counter fields
    // are present as separate `u32`s; repack them.
    if map.contains_key(resolver_sym.clone())
        && map.contains_key(milestone_sym.clone())
        && map.contains_key(attestors_sym.clone())
        && map.contains_key(threshold_sym.clone())
    {
        let stored_id: u64 = map.get(Symbol::new(env, "id"))?.try_into_val(env).ok()?;
        if stored_id != id {
            return None;
        }
        let issuer: Address = map
            .get(Symbol::new(env, "issuer"))?
            .try_into_val(env)
            .ok()?;
        let counterparty: Address = map
            .get(Symbol::new(env, "counterparty"))?
            .try_into_val(env)
            .ok()?;
        let terms_hash: BytesN<32> = map
            .get(Symbol::new(env, "terms_hash"))?
            .try_into_val(env)
            .ok()?;
        let due_at: u64 = map
            .get(Symbol::new(env, "due_at"))?
            .try_into_val(env)
            .ok()?;
        let status: CommitmentStatus = map
            .get(Symbol::new(env, "status"))?
            .try_into_val(env)
            .ok()?;
        let created_at: u64 = map
            .get(Symbol::new(env, "created_at"))?
            .try_into_val(env)
            .ok()?;
        let attested_at: Option<u64> = match map.get(Symbol::new(env, "attested_at")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let oracle: Option<Address> = match map.get(Symbol::new(env, "oracle")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let schema_id: Option<u32> = match map.get(Symbol::new(env, "schema_id")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let resolver_address: Address = map.get(resolver_sym)?.try_into_val(env).ok()?;
        let milestone_count: u32 = map.get(milestone_sym)?.try_into_val(env).ok()?;
        let milestones_attested: u32 = map
            .get(Symbol::new(env, "milestones_attested"))?
            .try_into_val(env)
            .ok()?;
        let late_milestones: u32 = map
            .get(Symbol::new(env, "late_milestones"))?
            .try_into_val(env)
            .ok()?;
        let attestors: Vec<Address> = map.get(attestors_sym)?.try_into_val(env).ok()?;
        let vote_threshold: u32 = map.get(threshold_sym)?.try_into_val(env).ok()?;

        let migrated = Commitment {
            id,
            issuer,
            counterparty,
            terms_hash,
            due_at,
            status,
            created_at,
            attested_at,
            resolver_address,
            oracle,
            schema_id,
            attestors,
            counters: Commitment::pack_counters(
                env,
                milestone_count,
                milestones_attested,
                late_milestones,
                vote_threshold,
            ),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Commitment(id), &migrated);

        return Some(migrated);
    }

    // Mid-tier record: written after milestone support (`milestone_count` /
    // `milestones_attested` / `late_milestones` / `resolver_address`) landed
    // but before attestor-panel voting (`attestors` / `vote_threshold`) did.
    // Preserve the real milestone counters instead of collapsing them to a
    // single milestone, and default the not-yet-invented voting fields to
    // "no panel configured".
    if map.contains_key(resolver_sym.clone()) && map.contains_key(milestone_sym.clone()) {
        let stored_id: u64 = map.get(Symbol::new(env, "id"))?.try_into_val(env).ok()?;
        if stored_id != id {
            return None;
        }
        let issuer: Address = map
            .get(Symbol::new(env, "issuer"))?
            .try_into_val(env)
            .ok()?;
        let counterparty: Address = map
            .get(Symbol::new(env, "counterparty"))?
            .try_into_val(env)
            .ok()?;
        let terms_hash: BytesN<32> = map
            .get(Symbol::new(env, "terms_hash"))?
            .try_into_val(env)
            .ok()?;
        let due_at: u64 = map
            .get(Symbol::new(env, "due_at"))?
            .try_into_val(env)
            .ok()?;
        let status: CommitmentStatus = map
            .get(Symbol::new(env, "status"))?
            .try_into_val(env)
            .ok()?;
        let created_at: u64 = map
            .get(Symbol::new(env, "created_at"))?
            .try_into_val(env)
            .ok()?;
        let attested_at: Option<u64> = match map.get(Symbol::new(env, "attested_at")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let oracle: Option<Address> = match map.get(Symbol::new(env, "oracle")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let schema_id: Option<u32> = match map.get(Symbol::new(env, "schema_id")) {
            Some(v) => v.try_into_val(env).ok()?,
            None => None,
        };
        let resolver_address: Address = map.get(resolver_sym)?.try_into_val(env).ok()?;
        let milestone_count: u32 = map.get(milestone_sym)?.try_into_val(env).ok()?;
        let milestones_attested: u32 = map
            .get(Symbol::new(env, "milestones_attested"))?
            .try_into_val(env)
            .ok()?;
        let late_milestones: u32 = map
            .get(Symbol::new(env, "late_milestones"))?
            .try_into_val(env)
            .ok()?;

        let migrated = Commitment {
            id,
            issuer,
            counterparty,
            terms_hash,
            due_at,
            status,
            created_at,
            attested_at,
            resolver_address,
            oracle,
            schema_id,
            // Pre-attestor-voting record: no panel existed yet.
            attestors: Vec::new(env),
            counters: Commitment::pack_counters(
                env,
                milestone_count,
                milestones_attested,
                late_milestones,
                0,
            ),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Commitment(id), &migrated);

        return Some(migrated);
    }

    // Legacy record: parse the fields it does carry and fill in the rest.
    let stored_id: u64 = map.get(Symbol::new(env, "id"))?.try_into_val(env).ok()?;
    if stored_id != id {
        return None;
    }
    let issuer: Address = map
        .get(Symbol::new(env, "issuer"))?
        .try_into_val(env)
        .ok()?;
    let counterparty: Address = map
        .get(Symbol::new(env, "counterparty"))?
        .try_into_val(env)
        .ok()?;
    let terms_hash: BytesN<32> = map
        .get(Symbol::new(env, "terms_hash"))?
        .try_into_val(env)
        .ok()?;
    let due_at: u64 = map
        .get(Symbol::new(env, "due_at"))?
        .try_into_val(env)
        .ok()?;
    let status: CommitmentStatus = map
        .get(Symbol::new(env, "status"))?
        .try_into_val(env)
        .ok()?;
    let created_at: u64 = map
        .get(Symbol::new(env, "created_at"))?
        .try_into_val(env)
        .ok()?;
    let attested_at: Option<u64> = match map.get(Symbol::new(env, "attested_at")) {
        Some(v) => v.try_into_val(env).ok()?,
        None => None,
    };
    let oracle: Option<Address> = match map.get(Symbol::new(env, "oracle")) {
        Some(v) => v.try_into_val(env).ok()?,
        None => None,
    };
    let schema_id: Option<u32> = match map.get(Symbol::new(env, "schema_id")) {
        Some(v) => v.try_into_val(env).ok()?,
        None => None,
    };

    let resolver_address: Address = match map.get(resolver_sym) {
        Some(v) => v.try_into_val(env).ok()?,
        // Pre-resolver record: fall back to the first member of the arbitrator
        // set. Naming an arbitrator as the resolver routes the dispute through
        // the committee's majority vote, exactly like a fresh commitment that
        // delegates to the committee.
        None => arbitrators(env).first().unwrap_or_else(|| {
            soroban_sdk::panic_with_error!(env, crate::errors::Error::NotInitialized)
        }),
    };

    // A pre-milestone record is one milestone, already attested if it resolved.
    let resolved = status != CommitmentStatus::Pending;
    let migrated = Commitment {
        id,
        issuer,
        counterparty,
        terms_hash,
        due_at,
        status,
        created_at,
        attested_at,
        resolver_address,
        oracle,
        schema_id,
        // A legacy record predates attestor voting: it has no panel and stays
        // on the single-resolver dispute path.
        attestors: Vec::new(env),
        counters: Commitment::pack_counters(
            env,
            1,
            u32::from(resolved),
            u32::from(status == CommitmentStatus::Late),
            0,
        ),
    };

    env.storage()
        .persistent()
        .set(&DataKey::Commitment(id), &migrated);

    Some(migrated)
}

/// Registers a new commitment split into `milestone_count` milestones.
///
/// # Authorization
/// * Authorized caller: `issuer` (via `require_auth`).
/// * Why: Only the party issuing (promising) the commitment should be able to
///   create and bind themselves to a new commitment on-chain.
pub fn create(
    env: &soroban_sdk::Env,
    issuer: Address,
    counterparty: Address,
    terms_hash: BytesN<32>,
    due_at: u64,
    resolver_address: Address,
    milestone_count: u32,
    oracle: Option<Address>,
    schema_id: Option<u32>,
    attestors: Vec<Address>,
    vote_threshold: u32,
) -> u64 {
    // 0. Enter the reentrancy guard before any external interaction (including
    //    the require_auth call below, which may invoke a custom account contract).
    crate::reentrancy::enter(env);

    // 1. Require authorization from the issuer.
    issuer.require_auth();

    // 2. Validate parameters using shared validation rules.
    let now = env.ledger().timestamp();
    if let Err(err) = pactum_validation::validate_commitment_creation(due_at, now, milestone_count)
    {
        match err {
            pactum_validation::ValidationError::DueAtInPast => {
                soroban_sdk::panic_with_error!(env, crate::errors::Error::DueAtInPast);
            }
            pactum_validation::ValidationError::InvalidMilestoneCount => {
                soroban_sdk::panic_with_error!(env, crate::errors::Error::InvalidMilestoneCount);
            }
        }
    }

    // 4. Validate the attestor voting panel: a threshold is only meaningful
    //    together with a non-empty panel, and must not exceed the panel size.
    let has_panel = !attestors.is_empty();
    if has_panel != (vote_threshold > 0) || vote_threshold > attestors.len() {
        soroban_sdk::panic_with_error!(env, crate::errors::Error::ThresholdInvalid);
    }

    // 5. Assign the next available ID.
    let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
    let next_id = id
        .checked_add(1)
        .unwrap_or_else(|| soroban_sdk::panic_with_error!(env, crate::errors::Error::Overflow));
    env.storage().instance().set(&DataKey::NextId, &next_id);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);

    // 6. Create the Commitment object with Pending status.
    let commitment = Commitment {
        id,
        issuer: issuer.clone(),
        counterparty: counterparty.clone(),
        terms_hash,
        due_at,
        status: CommitmentStatus::Pending,
        created_at: now,
        attested_at: None,
        resolver_address,
        oracle,
        schema_id,
        counters: Commitment::pack_counters(env, milestone_count, 0, 0, vote_threshold),
        attestors,
    };

    // 7. Store in persistent storage keyed by id and extend TTL.
    env.storage()
        .persistent()
        .set(&DataKey::Commitment(id), &commitment);
    env.storage().persistent().extend_ttl(
        &DataKey::Commitment(id),
        TTL_THRESHOLD_LEDGERS,
        TTL_EXTEND_LEDGERS,
    );

    // 8. Emit Created event.
    crate::events::commitment_created(
        env,
        id,
        &issuer,
        &counterparty,
        &commitment.oracle,
        commitment.schema_id,
    );

    // 9. Release the reentrancy guard.
    crate::reentrancy::exit(env);

    id
}

/// Parameters for creating a commitment in batch
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentParams {
    pub issuer: Address,
    pub counterparty: Address,
    pub terms_hash: BytesN<32>,
    pub due_at: u64,
    pub resolver_address: Address,
    pub oracle: Option<Address>,
    pub schema_id: Option<u32>,
    pub attestors: Vec<Address>,
    pub vote_threshold: u32,
}

/// Creates multiple commitments in a single transaction.
///
/// # Authorization
/// * Each `issuer` in the batch must authorize individually via `require_auth`.
///
/// # Arguments
/// * `env` - The Soroban execution environment.
/// * `params` - A vector of `CommitmentParams`.
///
/// # Returns
/// * `Vec<u64>` - The unique identifiers assigned to each created commitment.
///
/// # Panics
/// * Panics with `Error::BatchTooLarge` if batch size > 50.
/// * Panics with `Error::DueAtInPast` if any `due_at` is in the past.
pub fn create_batch(env: &soroban_sdk::Env, params: Vec<CommitmentParams>) -> Vec<u64> {
    crate::reentrancy::enter(env);

    let batch_size = params.len();
    if batch_size > 50 {
        soroban_sdk::panic_with_error!(env, crate::errors::Error::BatchTooLarge);
    }

    let mut ids = Vec::new(env);
    let now = env.ledger().timestamp();

    for param in params.iter() {
        param.issuer.require_auth();

        if param.due_at <= now {
            soroban_sdk::panic_with_error!(env, crate::errors::Error::DueAtInPast);
        }

        let has_panel = !param.attestors.is_empty();
        if has_panel != (param.vote_threshold > 0) || param.vote_threshold > param.attestors.len() {
            soroban_sdk::panic_with_error!(env, crate::errors::Error::ThresholdInvalid);
        }

        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(1);
        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| soroban_sdk::panic_with_error!(env, crate::errors::Error::Overflow));
        env.storage().instance().set(&DataKey::NextId, &next_id);
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);

        let commitment = Commitment {
            id,
            issuer: param.issuer.clone(),
            counterparty: param.counterparty.clone(),
            terms_hash: param.terms_hash.clone(),
            due_at: param.due_at,
            status: CommitmentStatus::Pending,
            created_at: now,
            attested_at: None,
            resolver_address: param.resolver_address.clone(),
            oracle: param.oracle.clone(),
            schema_id: param.schema_id,
            counters: Commitment::pack_counters(env, 1, 0, 0, param.vote_threshold),
            attestors: param.attestors.clone(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Commitment(id), &commitment);
        env.storage().persistent().extend_ttl(
            &DataKey::Commitment(id),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_LEDGERS,
        );

        crate::events::commitment_created(
            env,
            id,
            &param.issuer,
            &param.counterparty,
            &param.oracle,
            param.schema_id,
        );

        ids.push_back(id);
    }

    crate::reentrancy::exit(env);
    ids
}

/// Computes the deterministic SHA-256 cryptographic binding digest over a commitment's
/// VRF dispute panel assignment parameters and selected attestor addresses.
pub fn compute_panel_binding_hash(
    env: &soroban_sdk::Env,
    commitment_id: u64,
    vrf_seed: &BytesN<32>,
    ledger_sequence: u32,
    vote_threshold: u32,
    panel: &Vec<Address>,
) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, b"PACTUM_PANEL_BINDING_V1");
    preimage.extend_from_array(&commitment_id.to_be_bytes());
    preimage.extend_from_array(&vrf_seed.to_array());
    preimage.extend_from_array(&ledger_sequence.to_be_bytes());
    preimage.extend_from_array(&vote_threshold.to_be_bytes());
    preimage.extend_from_array(&panel.len().to_be_bytes());
    for attestor in panel.iter() {
        preimage.append(&attestor.to_xdr(env));
    }
    env.crypto().sha256(&preimage).into()
}

/// Derives a deterministic VRF seed at the current dispute ledger sequence, samples
/// `panel_size` unique active staked attestors proportional to their stake weights
/// (excluding the commitment's `issuer` and `counterparty`), locks their stakes if
/// the commitment is in `Disputed` state, and cryptographically binds the panel to
/// both `DataKey::Commitment(commitment_id)` and `DataKey::DisputePanel(commitment_id)`.
pub fn assign_vrf_dispute_panel(
    env: &soroban_sdk::Env,
    commitment_id: u64,
    panel_size: u32,
    vote_threshold: u32,
    declaration_entropy: &BytesN<32>,
) -> DisputePanelRecord {
    if panel_size == 0 || vote_threshold == 0 || vote_threshold > panel_size {
        panic_with_error!(env, crate::errors::Error::ThresholdInvalid);
    }

    let mut commitment = get_commitment_record(env, commitment_id)
        .unwrap_or_else(|| panic_with_error!(env, crate::errors::Error::CommitmentNotFound));

    let vrf_seed = crate::staking::derive_vrf_dispute_seed(
        env,
        commitment_id,
        &commitment.issuer,
        &commitment.counterparty,
        &commitment.terms_hash,
        declaration_entropy,
    );

    let panel = crate::staking::select_vrf_stake_weighted_panel(
        env,
        &vrf_seed,
        panel_size,
        &commitment.issuer,
        &commitment.counterparty,
    );

    if commitment.status == CommitmentStatus::Disputed {
        for attestor in panel.iter() {
            crate::staking::set_locked(env, &attestor, true);
        }
    }

    commitment.attestors = panel.clone();
    commitment.counters = Commitment::pack_counters(
        env,
        commitment.milestone_count(),
        commitment.milestones_attested(),
        commitment.late_milestones(),
        vote_threshold,
    );

    env.storage()
        .persistent()
        .set(&DataKey::Commitment(commitment_id), &commitment);
    env.storage().persistent().extend_ttl(
        &DataKey::Commitment(commitment_id),
        TTL_THRESHOLD_LEDGERS,
        TTL_EXTEND_LEDGERS,
    );

    let ledger_sequence = env.ledger().sequence();
    let ledger_timestamp = env.ledger().timestamp();
    let binding_hash = compute_panel_binding_hash(
        env,
        commitment_id,
        &vrf_seed,
        ledger_sequence,
        vote_threshold,
        &panel,
    );

    let record = DisputePanelRecord {
        commitment_id,
        vrf_seed,
        ledger_sequence,
        ledger_timestamp,
        panel,
        vote_threshold,
        binding_hash,
    };

    env.storage()
        .persistent()
        .set(&DataKey::DisputePanel(commitment_id), &record);
    env.storage().persistent().extend_ttl(
        &DataKey::DisputePanel(commitment_id),
        TTL_THRESHOLD_LEDGERS,
        TTL_EXTEND_LEDGERS,
    );

    record
}

/// Retrieves the stored VRF dispute panel assignment record for `commitment_id`.
pub fn get_dispute_panel_record(
    env: &soroban_sdk::Env,
    commitment_id: u64,
) -> Option<DisputePanelRecord> {
    env.storage()
        .persistent()
        .get(&DataKey::DisputePanel(commitment_id))
}

/// Verifies that a commitment's active voting panel matches its cryptographically
/// bound `DisputePanelRecord` in persistent storage.
pub fn verify_dispute_panel_binding(env: &soroban_sdk::Env, commitment_id: u64) -> bool {
    let Some(commitment) = get_commitment_record(env, commitment_id) else {
        return false;
    };
    let Some(record) = get_dispute_panel_record(env, commitment_id) else {
        return false;
    };
    if commitment.attestors != record.panel || commitment.vote_threshold() != record.vote_threshold
    {
        return false;
    }
    let expected = compute_panel_binding_hash(
        env,
        record.commitment_id,
        &record.vrf_seed,
        record.ledger_sequence,
        record.vote_threshold,
        &record.panel,
    );
    expected == record.binding_hash
}
