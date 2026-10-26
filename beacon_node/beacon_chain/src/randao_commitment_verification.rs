use std::time::Duration;

use state_processing::per_block_processing::{
    VerifySignatures, verify_randao_commitment_registration,
};
use types::{SignedRandaoCommitmentRegistration, consts::heze::UNSET_RANDAO_COMMITMENT};

use crate::{BeaconChain, BeaconChainTypes};
use state_processing::per_block_processing::errors::BlockProcessingError;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Validate a gossip `SignedRandaoCommitmentRegistration` against the current head state.
    ///
    /// [New in Eip8321: EIP-8321]
    pub fn verify_randao_commitment_registration_for_gossip(
        &self,
        signed_registration: &SignedRandaoCommitmentRegistration,
        _seen_timestamp: Duration,
    ) -> Result<(), BlockProcessingError> {
        let head = self.head();
        let state = &head.snapshot.beacon_state;

        // This topic only exists from Eip8321 onwards. Check the fork version as well as the
        // variant, so a head state that has not activated the fork yet is ignored.
        if !state.fork_name_unchecked().eip8321_enabled()
            || state.fork().current_version != self.spec.eip8321_fork_version
        {
            return Err(BlockProcessingError::IncorrectStateType);
        }

        verify_randao_commitment_registration(
            state,
            signed_registration,
            VerifySignatures::True,
            &self.spec,
        )
    }

    /// Returns `true` if `validator_index` has no commitment and no pending registration.
    pub fn randao_commitment_is_unset(&self, validator_index: u64) -> bool {
        let head = self.head();
        let state = &head.snapshot.beacon_state;
        let Ok(commitments) = state.randao_commitments() else {
            return false;
        };
        commitments
            .get(validator_index as usize)
            .copied()
            .unwrap_or(UNSET_RANDAO_COMMITMENT)
            == UNSET_RANDAO_COMMITMENT
    }
}
