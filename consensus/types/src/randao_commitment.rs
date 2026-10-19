use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{Epoch, ForkName, Hash256};

/// A hash-chain RANDAO commitment waiting for its activation epoch.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/_features/eip8321/beacon-chain.md>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Default, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize, Encode, Decode,
    TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct PendingRandaoCommitment {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub commitment: Hash256,
    pub activation_epoch: Epoch,
}

/// A validator's registration of a hash-chain RANDAO tip.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Default, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize, Encode, Decode,
    TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct RandaoCommitmentRegistration {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub commitment: Hash256,
}

// The registration domain is fork-agnostic (`compute_domain` with the genesis fork version), so
// `SignedRoot` is implemented manually at the call site instead of deriving the fork-aware root.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedRandaoCommitmentRegistration {
    pub message: RandaoCommitmentRegistration,
    pub signature: Signature,
}

impl SignedRandaoCommitmentRegistration {
    pub fn empty() -> Self {
        Self {
            message: RandaoCommitmentRegistration::default(),
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PendingRandaoCommitment);
    ssz_and_tree_hash_tests!(RandaoCommitmentRegistration);
    ssz_and_tree_hash_tests!(SignedRandaoCommitmentRegistration);
}
