//! Memory-bounded, zero-allocation Cuckoo Filter and SPV inclusion verifier (#301).
//!
//! Uses a fixed-capacity array `[u16; NUM_BUCKETS * BUCKET_CAPACITY]` in static/stack
//! memory so lookups and insertions perform zero heap allocations and execute in < 1ms.

use sha2::{Digest, Sha256};

/// Number of buckets (must be a power of two).
pub const NUM_BUCKETS: usize = 1024;
/// Number of 16-bit fingerprints stored per bucket.
pub const BUCKET_CAPACITY: usize = 4;
/// Maximum Cuckoo relocation kicks before declaring the filter full.
pub const MAX_CUCKOO_KICKS: usize = 128;

/// Fixed-size, zero-allocation Cuckoo Filter storing non-zero 16-bit fingerprints.
#[derive(Clone, Debug)]
pub struct ZeroAllocCuckooFilter {
    buckets: [[u16; BUCKET_CAPACITY]; NUM_BUCKETS],
    count: usize,
}

impl Default for ZeroAllocCuckooFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
pub fn fnv1a_hash32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[inline]
pub fn fingerprint16(bytes: &[u8]) -> u16 {
    let h = fnv1a_hash32(bytes);
    let fp = ((h >> 16) ^ (h & 0xffff)) as u16;
    if fp == 0 {
        1
    } else {
        fp
    }
}

#[inline]
pub fn primary_bucket(bytes: &[u8]) -> usize {
    (fnv1a_hash32(bytes) as usize) & (NUM_BUCKETS - 1)
}

#[inline]
pub fn alt_bucket(bucket_idx: usize, fp: u16) -> usize {
    let fp_bytes = fp.to_le_bytes();
    let h = fnv1a_hash32(&fp_bytes) as usize;
    (bucket_idx ^ h) & (NUM_BUCKETS - 1)
}

impl ZeroAllocCuckooFilter {
    pub const fn new() -> Self {
        Self {
            buckets: [[0u16; BUCKET_CAPACITY]; NUM_BUCKETS],
            count: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn clear(&mut self) {
        self.buckets = [[0u16; BUCKET_CAPACITY]; NUM_BUCKETS];
        self.count = 0;
    }

    pub fn insert(&mut self, item: &[u8]) -> bool {
        if self.contains(item) {
            return true;
        }
        let fp = fingerprint16(item);
        let i1 = primary_bucket(item);
        let i2 = alt_bucket(i1, fp);

        for slot in &mut self.buckets[i1] {
            if *slot == 0 {
                *slot = fp;
                self.count += 1;
                return true;
            }
        }
        for slot in &mut self.buckets[i2] {
            if *slot == 0 {
                *slot = fp;
                self.count += 1;
                return true;
            }
        }

        let mut cur_idx = i1;
        let mut cur_fp = fp;
        for kick in 0..MAX_CUCKOO_KICKS {
            let victim_slot = kick % BUCKET_CAPACITY;
            core::mem::swap(&mut self.buckets[cur_idx][victim_slot], &mut cur_fp);
            cur_idx = alt_bucket(cur_idx, cur_fp);

            for slot in &mut self.buckets[cur_idx] {
                if *slot == 0 {
                    *slot = cur_fp;
                    self.count += 1;
                    return true;
                }
            }
        }
        false
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        let fp = fingerprint16(item);
        let i1 = primary_bucket(item);
        if self.buckets[i1].contains(&fp) {
            return true;
        }
        let i2 = alt_bucket(i1, fp);
        self.buckets[i2].contains(&fp)
    }

    pub fn delete(&mut self, item: &[u8]) -> bool {
        let fp = fingerprint16(item);
        let i1 = primary_bucket(item);
        for slot in &mut self.buckets[i1] {
            if *slot == fp {
                *slot = 0;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        let i2 = alt_bucket(i1, fp);
        for slot in &mut self.buckets[i2] {
            if *slot == fp {
                *slot = 0;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}

/// Verifies a SHA-256 Merkle inclusion branch from `leaf_hash` to `expected_root`.
/// `siblings_concat` is a sequence of 32-byte sibling hashes, and `orientations`
/// indicates for each level whether the sibling is on the left (`1`) or right (`0`).
pub fn verify_sha256_merkle_branch(
    leaf_hash: &[u8; 32],
    siblings_concat: &[u8],
    orientations: &[u8],
    expected_root: &[u8; 32],
) -> bool {
    if siblings_concat.len() != orientations.len() * 32 {
        return false;
    }
    let mut current = *leaf_hash;
    for (level, &is_left) in orientations.iter().enumerate() {
        let offset = level * 32;
        let sibling = &siblings_concat[offset..offset + 32];
        let mut hasher = Sha256::new();
        if is_left == 1 {
            hasher.update(sibling);
            hasher.update(current);
        } else {
            hasher.update(current);
            hasher.update(sibling);
        }
        let digest = hasher.finalize();
        current.copy_from_slice(&digest);
    }
    &current == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_alloc_cuckoo_filter_insert_contains_delete() {
        let mut filter = ZeroAllocCuckooFilter::new();
        assert!(filter.is_empty());

        for i in 0..500u32 {
            let key = [
                b'c',
                b'm',
                b't',
                b'_',
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ];
            assert!(filter.insert(&key));
            assert!(filter.contains(&key));
        }

        assert_eq!(filter.len(), 500);

        let target = [b'c', b'm', b't', b'_', 0, 0, 0, 42];
        assert!(filter.delete(&target));
        assert!(!filter.contains(&target));
    }

    #[test]
    fn test_verify_sha256_merkle_branch() {
        let leaf = [0x11u8; 32];
        let sibling0 = [0x22u8; 32];
        let sibling1 = [0x33u8; 32];

        let mut h0 = Sha256::new();
        h0.update(leaf);
        h0.update(sibling0);
        let mid: [u8; 32] = h0.finalize().into();

        let mut h1 = Sha256::new();
        h1.update(sibling1);
        h1.update(mid);
        let root: [u8; 32] = h1.finalize().into();

        let mut siblings_concat = [0u8; 64];
        siblings_concat[..32].copy_from_slice(&sibling0);
        siblings_concat[32..].copy_from_slice(&sibling1);
        let orientations = [0u8, 1u8];

        assert!(verify_sha256_merkle_branch(
            &leaf,
            &siblings_concat,
            &orientations,
            &root
        ));

        let wrong_root = [0x99u8; 32];
        assert!(!verify_sha256_merkle_branch(
            &leaf,
            &siblings_concat,
            &orientations,
            &wrong_root
        ));
    }
}
