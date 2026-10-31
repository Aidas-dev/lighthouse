//! Submits hash-chain RANDAO commitment registrations to the beacon node.
//!
//! [New in Eip8321: EIP-8321]
//!
//! A validator with an EIP-8321 hash chain registers the tip of the chain once, then reveals
//! preimages when it proposes. This service submits the registration when no registration is known
//! locally, retrying on each epoch transition until a beacon node accepts it, and persists the
//! submission and activation epochs so a restart does not re-register.
//!
//! Remote signers are gated: `web3signer` has no message type for a hash-chain RANDAO
//! registration, so [`ValidatorStore::sign_randao_commitment_registration`] fails for those keys
//! and the service logs and skips them (see `SigningMethod::RandaoCommitmentRegistration`).

use beacon_node_fallback::{ApiTopic, BeaconNodeFallback};
use randao_chain::RandaoChainStore;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use types::{ChainSpec, Epoch, EthSpec, RandaoCommitmentRegistration, Slot};
use validator_store::{DoppelgangerStatus, ValidatorStore};

/// Maximum number of registrations sent to a beacon node in a single request.
const REGISTRATION_BATCH_SIZE: usize = 256;

/// Builds a `RandaoRegistrationService`.
pub struct RandaoRegistrationServiceBuilder<S: ValidatorStore, T: SlotClock + 'static> {
    validator_store: Option<Arc<S>>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: Option<TaskExecutor>,
    spec: Option<Arc<ChainSpec>>,
    randao_chain: Option<Arc<RandaoChainStore>>,
}

impl<S: ValidatorStore, T: SlotClock + 'static> Default for RandaoRegistrationServiceBuilder<S, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: ValidatorStore, T: SlotClock + 'static> RandaoRegistrationServiceBuilder<S, T> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            executor: None,
            spec: None,
            randao_chain: None,
        }
    }

    pub fn validator_store(mut self, store: Arc<S>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn executor(mut self, executor: TaskExecutor) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn spec(mut self, spec: Arc<ChainSpec>) -> Self {
        self.spec = Some(spec);
        self
    }

    pub fn randao_chain(mut self, randao_chain: Arc<RandaoChainStore>) -> Self {
        self.randao_chain = Some(randao_chain);
        self
    }

    pub fn build(self) -> Result<RandaoRegistrationService<S, T>, String> {
        Ok(RandaoRegistrationService {
            inner: Arc::new(Inner {
                validator_store: self
                    .validator_store
                    .ok_or("Cannot build RandaoRegistrationService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build RandaoRegistrationService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build RandaoRegistrationService without beacon_nodes")?,
                executor: self
                    .executor
                    .ok_or("Cannot build RandaoRegistrationService without executor")?,
                spec: self
                    .spec
                    .ok_or("Cannot build RandaoRegistrationService without spec")?,
                randao_chain: self
                    .randao_chain
                    .ok_or("Cannot build RandaoRegistrationService without randao_chain")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<S, T> {
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    spec: Arc<ChainSpec>,
    randao_chain: Arc<RandaoChainStore>,
}

/// Submits hash-chain RANDAO commitment registrations at start-up and on epoch transitions.
pub struct RandaoRegistrationService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for RandaoRegistrationService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for RandaoRegistrationService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> RandaoRegistrationService<S, T> {
    /// Start the service, which submits registrations once per epoch.
    pub fn start_update_service(self) -> Result<(), String> {
        info!("RANDAO commitment registration service started");

        let executor = self.executor.clone();
        let spec = self.spec.clone();
        let slot_duration = spec.genesis_slot_duration();

        let interval_fut = async move {
            loop {
                if let Some(slot) = self.slot_clock.now()
                    && should_register::<S::E>(slot, &spec)
                {
                    if let Err(e) = self.register_validators(slot).await {
                        error!(error = ?e, "Error during RANDAO commitment registration");
                    }
                }

                if let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() {
                    sleep(duration_to_next_slot).await;
                } else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                }
            }
        };

        executor.spawn(interval_fut, "randao_registration_service");
        Ok(())
    }

    /// Submit a registration for every validator that does not have one yet.
    async fn register_validators(&self, slot: Slot) -> Result<(), String> {
        let epoch = slot.epoch(S::E::slots_per_epoch());
        let activation_epoch =
            epoch.saturating_add(Epoch::new(S::E::commitment_registration_delay()));

        let pubkeys: Vec<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::only_safe);

        let mut pending = Vec::new();
        for pubkey in pubkeys {
            let Some(validator_index) = self.validator_store.validator_index(&pubkey) else {
                // The validator is not active yet; its registration would be rejected.
                continue;
            };

            // Deriving the chain is ~65k blake3 hashes, so keep it off the async runtime. The
            // store caches the derived chain, so this only runs once per validator.
            let store = self.randao_chain.clone();
            let chain = match self
                .executor
                .spawn_blocking_handle(move || store.get_or_create(&pubkey), "randao_chain_load")
            {
                Some(handle) => match handle.await {
                    Ok(Ok(chain)) => chain,
                    Ok(Err(e)) => {
                        error!(?pubkey, error = ?e, "Unable to open RANDAO hash chain");
                        continue;
                    }
                    Err(e) => {
                        error!(?pubkey, error = ?e, "RANDAO hash chain load task failed");
                        continue;
                    }
                },
                None => {
                    error!(?pubkey, "Unable to spawn RANDAO hash chain load");
                    continue;
                }
            };

            if chain.registered_epoch().is_some() {
                continue;
            }

            let registration = RandaoCommitmentRegistration {
                validator_index,
                commitment: chain.commitment(),
            };

            match self
                .validator_store
                .sign_randao_commitment_registration(pubkey, registration)
                .await
            {
                Ok(signed) => pending.push((pubkey, chain, signed)),
                Err(e) => {
                    warn!(
                        ?pubkey,
                        error = ?e,
                        "Unable to sign RANDAO commitment registration; will retry next epoch"
                    );
                }
            }
        }

        if pending.is_empty() {
            return Ok(());
        }

        debug!(
            epoch = epoch.as_u64(),
            count = pending.len(),
            "Submitting RANDAO commitment registrations"
        );

        for batch in pending.chunks(REGISTRATION_BATCH_SIZE) {
            let registrations: Vec<_> = batch.iter().map(|(_, _, signed)| signed.clone()).collect();
            let count = registrations.len();

            let result = self
                .beacon_nodes
                .request(ApiTopic::Subscriptions, |beacon_node| {
                    let registrations = registrations.clone();
                    async move {
                        beacon_node
                            .post_beacon_pool_randao_commitment_registrations(&registrations)
                            .await
                    }
                })
                .await;

            match result {
                Ok(()) => {
                    for (pubkey, chain, _) in batch {
                        if let Err(e) = chain.mark_registered(epoch, activation_epoch) {
                            error!(
                                ?pubkey,
                                error = ?e,
                                "Unable to persist RANDAO commitment registration"
                            );
                        }
                    }
                    info!(
                        epoch = epoch.as_u64(),
                        activation_epoch = activation_epoch.as_u64(),
                        count,
                        "Submitted RANDAO commitment registrations"
                    );
                }
                Err(e) => {
                    warn!(
                        epoch = epoch.as_u64(),
                        count,
                        error = %e,
                        "Beacon node rejected RANDAO commitment registrations; will retry next epoch"
                    );
                }
            }
        }

        Ok(())
    }
}

/// Only register once EIP-8321 is scheduled: the beacon node rejects registrations
/// before the fork, and the commitment must be in place when the fork activates, so start one
/// `COMMITMENT_REGISTRATION_DELAY` before it.
fn should_register<E: EthSpec>(slot: Slot, spec: &ChainSpec) -> bool {
    let epoch = slot.epoch(E::slots_per_epoch());
    if spec.fork_name_at_epoch(epoch).eip8321_enabled() {
        return true;
    }

    spec.eip8321_fork_epoch.is_some_and(|fork_epoch| {
        epoch.saturating_add(Epoch::new(E::commitment_registration_delay())) >= fork_epoch
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_register_starts_one_delay_before_the_fork() {
        let mut spec = ChainSpec::default();
        let fork_epoch = Epoch::new(10);
        spec.eip8321_fork_epoch = Some(fork_epoch);

        let epoch_to_slot =
            |epoch: u64| Slot::new(epoch * <types::MainnetEthSpec as EthSpec>::slots_per_epoch());

        assert!(!should_register::<types::MainnetEthSpec>(
            epoch_to_slot(6),
            &spec
        ));
        assert!(should_register::<types::MainnetEthSpec>(
            epoch_to_slot(7),
            &spec
        ));
        assert!(should_register::<types::MainnetEthSpec>(
            epoch_to_slot(10),
            &spec
        ));
    }

    #[test]
    fn should_not_register_without_a_scheduled_fork() {
        let mut spec = ChainSpec::default();
        spec.eip8321_fork_epoch = None;
        assert!(!should_register::<types::MainnetEthSpec>(
            Slot::new(1_000),
            &spec
        ));
    }
}
