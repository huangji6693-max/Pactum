//! Packed ledger storage primitives for the Time-Weighted Average Reputation
//! (TWAR) Segment Tree (Issue #295).
//!
//! # Storage Layout
//!
//! To minimize Soroban ledger read/write footprint and avoid per-node storage
//! entry overhead, the entire binary segment tree for an address is packed into
//! a single contiguous [`soroban_sdk::Bytes`] slice stored in Soroban instance
//! storage under [`TwarStorageKey::TwarTree`].
//!
//! * **Capacity**: [`TWAR_LEAF_CAPACITY`] = 32 leaf buckets, yielding
//!   `2 * TWAR_LEAF_CAPACITY` = 64 slots (`0..64`).
//! * **Slot 0 (16 bytes)**: Tree metadata header:
//!   - `bytes[0..4]`: Magic/version tag (`TWAR_STORAGE_MAGIC` = `0x5457_4152`).
//!   - `bytes[4..8]`: Configured half-life in ledgers (`u32`, big-endian).
//!   - `bytes[8..12]`: Last updated ledger sequence (`u32`, big-endian).
//!   - `bytes[12..16]`: Total saturating update counter (`u32`, big-endian).
//! * **Slots 1..64 (16 bytes each)**: 1-indexed binary segment tree nodes
//!   (`1` = root, `2i` = left child, `2i + 1` = right child, `32..64` = leaves):
//!   - `bytes[0..8]`: `weighted_score` (`i64`, big-endian) anchored at `anchor_ledger`.
//!   - `bytes[8..12]`: `anchor_ledger` (`u32`, big-endian).
//!   - `bytes[12..16]`: `event_count` (`u32`, big-endian, saturating).
//!
//! Total contiguous buffer size is `64 * 16 = 1,024` bytes ([`TWAR_PACKED_BYTES_LEN`]).

use crate::commitments::{TTL_EXTEND_LEDGERS, TTL_THRESHOLD_LEDGERS};
use soroban_sdk::{contracttype, Address, Bytes, Env};

/// Number of leaf buckets in the fixed-size segment tree (power of two).
pub const TWAR_LEAF_CAPACITY: usize = 32;

/// Total number of 16-byte slots in the packed segment tree buffer (`2 * N`).
pub const TWAR_NODE_SLOTS: usize = TWAR_LEAF_CAPACITY * 2;

/// Byte width of each packed header/node slot.
pub const TWAR_SLOT_BYTES: usize = 16;

/// Total byte length of a packed `TWARSegmentTree` in Soroban storage (1,024 bytes).
pub const TWAR_PACKED_BYTES_LEN: usize = TWAR_NODE_SLOTS * TWAR_SLOT_BYTES;

/// Magic header tag (`"TWAR"` in ASCII big-endian).
pub const TWAR_STORAGE_MAGIC: u32 = 0x5457_4152;

/// Default half-life in ledgers (64 buckets * 10,000 ledgers = 640,000 ledgers, ~37 days).
pub const TWAR_DEFAULT_HALF_LIFE_LEDGERS: u32 = 640_000;

/// Storage key for packed TWAR segment trees in Soroban storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TwarStorageKey {
    /// Packed `Bytes` slice holding the contiguous segment tree for an address.
    TwarTree(Address),
}

/// Decoded header stored in slot `0` of the packed segment tree buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwarHeader {
    pub magic: u32,
    pub half_life_ledgers: u32,
    pub last_ledger: u32,
    pub total_updates: u32,
}

/// Decoded segment tree node stored in slots `1..64` of the packed buffer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TwarNode {
    /// Time-weighted reputation score sum anchored at `anchor_ledger`.
    pub weighted_score: i64,
    /// Ledger sequence at which `weighted_score` was last anchored.
    pub anchor_ledger: u32,
    /// Saturating count of reputation updates folded into this subtree.
    pub event_count: u32,
}

impl TwarNode {
    /// Returns an empty (all-zero) segment tree node.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            weighted_score: 0,
            anchor_ledger: 0,
            event_count: 0,
        }
    }

    /// Returns `true` if this node has no accumulated score and no recorded events.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.weighted_score == 0 && self.anchor_ledger == 0 && self.event_count == 0
    }
}

/// Initializes a raw 1,024-byte buffer with the default header and zeroed nodes.
#[inline]
pub fn init_packed_buffer(half_life_ledgers: u32) -> [u8; TWAR_PACKED_BYTES_LEN] {
    let mut buf = [0u8; TWAR_PACKED_BYTES_LEN];
    let effective_half_life = if half_life_ledgers == 0 {
        TWAR_DEFAULT_HALF_LIFE_LEDGERS
    } else {
        half_life_ledgers
    };
    encode_header(
        &mut buf,
        TwarHeader {
            magic: TWAR_STORAGE_MAGIC,
            half_life_ledgers: effective_half_life,
            last_ledger: 0,
            total_updates: 0,
        },
    );
    buf
}

/// Encodes the tree metadata header into slot `0` (`buf[0..16]`).
#[inline]
pub fn encode_header(buf: &mut [u8; TWAR_PACKED_BYTES_LEN], header: TwarHeader) {
    buf[0..4].copy_from_slice(&header.magic.to_be_bytes());
    buf[4..8].copy_from_slice(&header.half_life_ledgers.to_be_bytes());
    buf[8..12].copy_from_slice(&header.last_ledger.to_be_bytes());
    buf[12..16].copy_from_slice(&header.total_updates.to_be_bytes());
}

/// Decodes the tree metadata header from slot `0` (`buf[0..16]`).
#[inline]
pub fn decode_header(buf: &[u8; TWAR_PACKED_BYTES_LEN]) -> TwarHeader {
    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let raw_half_life = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let half_life_ledgers = if magic != TWAR_STORAGE_MAGIC || raw_half_life == 0 {
        TWAR_DEFAULT_HALF_LIFE_LEDGERS
    } else {
        raw_half_life
    };
    let last_ledger = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let total_updates = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    TwarHeader {
        magic: TWAR_STORAGE_MAGIC,
        half_life_ledgers,
        last_ledger,
        total_updates,
    }
}

/// Encodes a [`TwarNode`] into slot `node_idx` (`1..TWAR_NODE_SLOTS`) in big-endian layout.
#[inline]
pub fn encode_node(buf: &mut [u8; TWAR_PACKED_BYTES_LEN], node_idx: usize, node: TwarNode) {
    debug_assert!(node_idx > 0 && node_idx < TWAR_NODE_SLOTS);
    let offset = node_idx * TWAR_SLOT_BYTES;
    buf[offset..offset + 8].copy_from_slice(&node.weighted_score.to_be_bytes());
    buf[offset + 8..offset + 12].copy_from_slice(&node.anchor_ledger.to_be_bytes());
    buf[offset + 12..offset + 16].copy_from_slice(&node.event_count.to_be_bytes());
}

/// Decodes a [`TwarNode`] from slot `node_idx` (`1..TWAR_NODE_SLOTS`).
#[inline]
pub fn decode_node(buf: &[u8; TWAR_PACKED_BYTES_LEN], node_idx: usize) -> TwarNode {
    debug_assert!(node_idx > 0 && node_idx < TWAR_NODE_SLOTS);
    let offset = node_idx * TWAR_SLOT_BYTES;
    let weighted_score = i64::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]);
    let anchor_ledger = u32::from_be_bytes([
        buf[offset + 8],
        buf[offset + 9],
        buf[offset + 10],
        buf[offset + 11],
    ]);
    let event_count = u32::from_be_bytes([
        buf[offset + 12],
        buf[offset + 13],
        buf[offset + 14],
        buf[offset + 15],
    ]);
    TwarNode {
        weighted_score,
        anchor_ledger,
        event_count,
    }
}

/// Packs a contiguous 1,024-byte tree buffer into a Soroban [`Bytes`] value.
#[inline]
pub fn pack_tree_bytes(env: &Env, buf: &[u8; TWAR_PACKED_BYTES_LEN]) -> Bytes {
    Bytes::from_slice(env, buf)
}

/// Unpacks a Soroban [`Bytes`] slice into a contiguous 1,024-byte buffer.
///
/// If the stored byte slice is absent or does not match [`TWAR_PACKED_BYTES_LEN`],
/// returns a freshly initialized buffer with [`TWAR_DEFAULT_HALF_LIFE_LEDGERS`].
#[inline]
pub fn unpack_tree_bytes(bytes: &Bytes) -> [u8; TWAR_PACKED_BYTES_LEN] {
    if bytes.len() as usize != TWAR_PACKED_BYTES_LEN {
        return init_packed_buffer(TWAR_DEFAULT_HALF_LIFE_LEDGERS);
    }
    let mut buf = [0u8; TWAR_PACKED_BYTES_LEN];
    bytes.copy_into_slice(&mut buf);
    let hdr = decode_header(&buf);
    if hdr.magic != TWAR_STORAGE_MAGIC {
        return init_packed_buffer(TWAR_DEFAULT_HALF_LIFE_LEDGERS);
    }
    buf
}

/// Loads the packed [`Bytes`] representation of `address`'s TWAR segment tree
/// from Soroban instance storage.
pub fn load_packed_twar_bytes(env: &Env, address: &Address) -> Option<Bytes> {
    let key = TwarStorageKey::TwarTree(address.clone());
    env.storage().instance().get(&key)
}

/// Writes the packed [`Bytes`] representation of `address`'s TWAR segment tree
/// into Soroban instance storage and extends the instance TTL.
pub fn save_packed_twar_bytes(env: &Env, address: &Address, bytes: &Bytes) {
    let key = TwarStorageKey::TwarTree(address.clone());
    env.storage().instance().set(&key, bytes);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_LEDGERS);
}
