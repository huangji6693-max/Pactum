#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(any(feature = "std", feature = "wasm", test))]
extern crate alloc;

#[cfg(any(feature = "std", feature = "wasm", test))]
pub mod ast;

#[cfg(any(feature = "std", feature = "wasm", test))]
pub use ast::*;

pub mod cuckoo;
pub use cuckoo::*;

/// The largest number of milestones a single commitment may be split into.
pub const MAX_MILESTONES: u32 = 256;

/// Standard validation errors corresponding to Soroban contract error representations.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ValidationError {
    /// The specified due date is in the past relative to the current ledger timestamp.
    DueAtInPast = 1,
    /// The requested milestone count is zero or above `MAX_MILESTONES`.
    InvalidMilestoneCount = 20,
}

/// Validates that `due_at` is strictly in the future relative to `current_time`.
pub fn validate_due_at(due_at: u64, current_time: u64) -> Result<(), ValidationError> {
    if due_at <= current_time {
        Err(ValidationError::DueAtInPast)
    } else {
        Ok(())
    }
}

/// Validates that `milestone_count` is between 1 and `MAX_MILESTONES` inclusive.
pub fn validate_milestone_count(milestone_count: u32) -> Result<(), ValidationError> {
    if milestone_count == 0 || milestone_count > MAX_MILESTONES {
        Err(ValidationError::InvalidMilestoneCount)
    } else {
        Ok(())
    }
}

/// Validates all parameters required when creating a commitment.
pub fn validate_commitment_creation(
    due_at: u64,
    current_time: u64,
    milestone_count: u32,
) -> Result<(), ValidationError> {
    validate_due_at(due_at, current_time)?;
    validate_milestone_count(milestone_count)?;
    Ok(())
}

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn validate_commitment_params(
    due_at: u64,
    current_time: u64,
    milestone_count: u32,
) -> Result<(), JsValue> {
    match validate_commitment_creation(due_at, current_time, milestone_count) {
        Ok(()) => Ok(()),
        Err(ValidationError::DueAtInPast) => {
            Err(JsValue::from_str("Due date must be set in the future."))
        }
        Err(ValidationError::InvalidMilestoneCount) => Err(JsValue::from_str(
            "Milestone count must be between 1 and 256.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_due_at_in_future_passes() {
        assert_eq!(validate_due_at(1000, 500), Ok(()));
    }

    #[test]
    fn test_due_at_equal_or_past_fails() {
        assert_eq!(validate_due_at(500, 500), Err(ValidationError::DueAtInPast));
        assert_eq!(validate_due_at(400, 500), Err(ValidationError::DueAtInPast));
    }

    #[test]
    fn test_milestone_count_valid() {
        assert_eq!(validate_milestone_count(1), Ok(()));
        assert_eq!(validate_milestone_count(256), Ok(()));
    }

    #[test]
    fn test_milestone_count_invalid() {
        assert_eq!(
            validate_milestone_count(0),
            Err(ValidationError::InvalidMilestoneCount)
        );
        assert_eq!(
            validate_milestone_count(257),
            Err(ValidationError::InvalidMilestoneCount)
        );
    }
}
