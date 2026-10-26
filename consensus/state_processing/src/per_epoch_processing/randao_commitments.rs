use super::errors::EpochProcessingError as Error;
use milhouse::ProgressiveList;
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec};

/// Apply queued EIP-8321 hash-chain RANDAO commitments that have reached their activation epoch.
///
/// Called immediately after `process_registry_updates` and before `process_slashings`.
pub fn process_pending_randao_commitments<E: EthSpec>(
    state: &mut BeaconState<E>,
    _spec: &ChainSpec,
) -> Result<(), Error> {
    if !state.fork_name_unchecked().eip8321_enabled() {
        return Ok(());
    }

    let next_epoch = state.current_epoch().safe_add(1)?;
    let pending: Vec<_> = state
        .pending_randao_commitments()?
        .iter()
        .cloned()
        .collect();

    let mut applied = 0usize;
    {
        let commitments = state.randao_commitments_mut()?;
        for entry in &pending {
            if entry.activation_epoch > next_epoch {
                break;
            }
            if let Some(commitment) = commitments.get_mut(entry.validator_index as usize) {
                *commitment = entry.commitment;
            }
            applied = applied.safe_add(1)?;
        }
    }

    if applied > 0 {
        let remaining: Vec<_> = pending.into_iter().skip(applied).collect();
        *state.pending_randao_commitments_mut()? = ProgressiveList::try_from_iter(remaining)?;
    }

    Ok(())
}
