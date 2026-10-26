//! Hash-chain RANDAO client support (EIP-8321).
//!
//! A validator that wants to use a hash-chain RANDAO registers the tip of a hash chain as its
//! commitment and then, for every proposal, reveals a preimage instead of a BLS signature. This
//! crate owns the validator-client side of that scheme:
//!
//! - generation of the chain itself: `c_i = blake3(HASH_CHAIN_RANDAO || c_{i-1})`;
//! - per-validator persistence of the chain seed, the current index and the registration state;
//! - `commitment()` / `next_reveal()` for registration and block proposal.
//!
//! The chain is derived lazily from the persisted seed and cached in memory. Deriving all
//! `2**16` links costs ~65k blake3 invocations, which is cheap enough to do on demand and
//! avoids storing the 2 MiB of links on disk.

use account_utils::write_file_via_temporary;
use bls::PublicKeyBytes;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use types::consts::heze::{HASH_CHAIN_RANDAO_DST, UNSET_RANDAO_COMMITMENT};
use types::{Epoch, Hash256};

/// Number of links in a hash chain (`2**16`, per the EIP-8321 spec).
pub const HASH_CHAIN_LENGTH: usize = 1 << 16;

/// Index of the last link, which is the commitment a freshly-generated chain registers.
pub const HASH_CHAIN_TIP_INDEX: u64 = HASH_CHAIN_LENGTH as u64 - 1;

/// Subdirectory of the validator definitions directory that holds the per-validator chain state.
pub const RANDAO_CHAIN_DIR: &str = "randao_chains";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The chain directory could not be created.
    #[error("unable to create randao chain directory {0:?}")]
    UnableToCreateDir(PathBuf),
    /// The persisted chain state could not be read.
    #[error("unable to read randao chain file {path:?}: {error}")]
    UnableToReadFile {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The persisted chain state could not be parsed as JSON.
    #[error("unable to parse randao chain file {path:?}: {error}")]
    UnableToParseFile {
        path: PathBuf,
        error: serde_json::Error,
    },
    /// The persisted seed was not a 32-byte `0x`-prefixed hex string.
    #[error("invalid randao chain seed {0:?}")]
    InvalidSeedHex(String),
    /// The chain state could not be serialized as JSON.
    #[error("unable to serialize randao chain state: {0}")]
    UnableToEncode(serde_json::Error),
    /// The chain state could not be written to disk.
    #[error("unable to write randao chain file {0:?}")]
    UnableToWriteFile(PathBuf),
    /// The persisted seed was zero, which is never produced by [`HashChain::generate`].
    #[error("randao chain seed must be non-zero")]
    ZeroSeed,
    /// A derived link was zero, which the spec forbids.
    #[error("randao chain link must be non-zero")]
    ZeroLink,
    /// The requested link index is outside the chain.
    #[error("randao chain index {0} is outside the chain")]
    IndexOutOfRange(u64),
    /// The reveal is not the preimage of the current commitment.
    #[error("randao chain reveal is not the preimage of the current commitment")]
    UnexpectedReveal,
}

/// The state persisted for a single validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    /// The seed (`c_0`) of the chain, as a `0x`-prefixed hex string.
    pub seed_hex: String,
    /// The index of the link that is currently the commitment. Decrements with every reveal.
    pub index: u64,
    /// The epoch in which the registration was submitted to a beacon node, if it succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_epoch: Option<Epoch>,
    /// The epoch in which the registration is expected to activate
    /// (`registered_epoch + COMMITMENT_REGISTRATION_DELAY`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_epoch: Option<Epoch>,
}

/// Derive the next link of a hash chain: `blake3(HASH_CHAIN_RANDAO || previous)`.
pub fn next_link(previous: &Hash256) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HASH_CHAIN_RANDAO_DST);
    hasher.update(previous.as_slice());
    Hash256::from_slice(hasher.finalize().as_bytes())
}

/// A fully-derived hash chain.
#[derive(Debug, Clone)]
pub struct HashChain {
    links: Vec<Hash256>,
}

impl HashChain {
    /// Derive the chain for `seed`, rejecting seeds or links that are zero.
    pub fn from_seed(seed: Hash256) -> Result<Self, Error> {
        if seed == UNSET_RANDAO_COMMITMENT {
            return Err(Error::ZeroSeed);
        }

        let mut links = Vec::with_capacity(HASH_CHAIN_LENGTH);
        let mut current = seed;
        links.push(current);
        for _ in 1..HASH_CHAIN_LENGTH {
            current = next_link(&current);
            if current == UNSET_RANDAO_COMMITMENT {
                return Err(Error::ZeroLink);
            }
            links.push(current);
        }

        Ok(Self { links })
    }

    /// Generate a fresh chain from a random, non-zero seed.
    ///
    /// A zero link aborts the derivation and the seed is regenerated; both events have
    /// negligible probability, so this is effectively a single pass.
    pub fn generate() -> Self {
        loop {
            if let Ok(chain) = Self::from_seed(random_seed()) {
                return chain;
            }
        }
    }

    /// The link at `index`.
    pub fn link(&self, index: u64) -> Option<Hash256> {
        self.links.get(index as usize).copied()
    }

    /// All links, ascending from the seed.
    pub fn links(&self) -> &[Hash256] {
        &self.links
    }

    /// The seed (`c_0`) of the chain.
    pub fn seed(&self) -> Hash256 {
        self.links[0]
    }
}

/// A random, non-zero 32-byte seed.
fn random_seed() -> Hash256 {
    loop {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let seed = Hash256::from_slice(&bytes);
        if seed != UNSET_RANDAO_COMMITMENT {
            return seed;
        }
    }
}

fn encode_seed_hex(seed: &Hash256) -> String {
    format!("0x{}", hex::encode(seed.as_slice()))
}

fn decode_seed_hex(seed_hex: &str) -> Result<Hash256, Error> {
    let stripped = seed_hex.strip_prefix("0x").unwrap_or(seed_hex);
    let bytes = hex::decode(stripped).map_err(|_| Error::InvalidSeedHex(seed_hex.to_string()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidSeedHex(seed_hex.to_string()))?;
    Ok(Hash256::from(seed))
}

/// The hash chain of a single validator, together with its persisted state.
pub struct ValidatorChain {
    pubkey: PublicKeyBytes,
    chain: HashChain,
    path: PathBuf,
    temp_path: PathBuf,
    state: Mutex<PersistedState>,
}

impl ValidatorChain {
    /// Load the chain state at `dir/name`, creating and persisting a fresh chain if absent.
    fn load_or_create_at(dir: &Path, pubkey: PublicKeyBytes, name: &str) -> Result<Self, Error> {
        let path = dir.join(name);
        let temp_path = dir.join(format!(".{name}.tmp"));

        let (chain, state, created) = match fs::read(&path) {
            Ok(bytes) => {
                let state: PersistedState =
                    serde_json::from_slice(&bytes).map_err(|error| Error::UnableToParseFile {
                        path: path.clone(),
                        error,
                    })?;
                let seed = decode_seed_hex(&state.seed_hex)?;
                let chain = HashChain::from_seed(seed)?;
                (chain, state, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let chain = HashChain::generate();
                let state = PersistedState {
                    seed_hex: encode_seed_hex(&chain.links()[0]),
                    index: HASH_CHAIN_TIP_INDEX,
                    registered_epoch: None,
                    activation_epoch: None,
                };
                (chain, state, true)
            }
            Err(error) => {
                return Err(Error::UnableToReadFile { path, error });
            }
        };

        let validator_chain = Self {
            pubkey,
            chain,
            path,
            temp_path,
            state: Mutex::new(state),
        };

        if created {
            validator_chain.persist(&validator_chain.state())?;
        }

        Ok(validator_chain)
    }

    /// The validator this chain belongs to.
    pub fn pubkey(&self) -> PublicKeyBytes {
        self.pubkey
    }

    /// The current commitment: the link at the current index.
    pub fn commitment(&self) -> Hash256 {
        let index = self.state.lock().index;
        self.chain.link(index).unwrap_or(UNSET_RANDAO_COMMITMENT)
    }

    /// The current index, i.e. the position of the commitment in the chain.
    pub fn index(&self) -> u64 {
        self.state.lock().index
    }

    /// The chain seed (`c_0`).
    pub fn seed(&self) -> Hash256 {
        self.chain.seed()
    }

    /// `true` when every link has been revealed.
    pub fn is_exhausted(&self) -> bool {
        self.state.lock().index == 0
    }

    /// The epoch in which the registration was submitted, if any.
    pub fn registered_epoch(&self) -> Option<Epoch> {
        self.state.lock().registered_epoch
    }

    /// The epoch in which the registered commitment activates, if any.
    pub fn activation_epoch(&self) -> Option<Epoch> {
        self.state.lock().activation_epoch
    }

    /// `true` if a registered commitment has activated by `epoch`, i.e. the validator must
    /// reveal hash-chain preimages instead of signing. Exhaustion is reported separately by
    /// [`Self::is_exhausted`].
    pub fn is_active(&self, epoch: Epoch) -> bool {
        self.state
            .lock()
            .activation_epoch
            .is_some_and(|activation_epoch| activation_epoch <= epoch)
    }

    /// The reveal the next proposal must use, without consuming it.
    ///
    /// Returns `None` once the chain is exhausted (index `0`).
    pub fn peek_reveal(&self) -> Result<Option<Hash256>, Error> {
        let index = self.state.lock().index;
        if index == 0 {
            return Ok(None);
        }

        self.chain
            .link(index - 1)
            .map(Some)
            .ok_or(Error::IndexOutOfRange(index - 1))
    }

    /// Consume `reveal` after the block carrying it has been published, decrementing the index and
    /// persisting the new state.
    ///
    /// The on-chain commitment only advances when a block is included, so a reveal that never made
    /// it into a block must be reused: advancing the local chain on a failed proposal would make
    /// every later proposal invalid. `reveal` must be the preimage of the current commitment.
    pub fn consume_reveal(&self, reveal: Hash256) -> Result<(), Error> {
        let mut state = self.state.lock();
        if state.index == 0 {
            return Err(Error::IndexOutOfRange(0));
        }

        match self.chain.link(state.index - 1) {
            Some(expected) if expected == reveal => {}
            Some(_) => return Err(Error::UnexpectedReveal),
            None => return Err(Error::IndexOutOfRange(state.index - 1)),
        }

        state.index -= 1;
        self.persist(&state)
    }

    /// Take the next reveal, decrementing the index and persisting the new state.
    ///
    /// This is [`Self::peek_reveal`] followed by [`Self::consume_reveal`]; block proposals should
    /// peek before requesting a block and only consume once the block has been published.
    ///
    /// Returns `None` once the chain is exhausted (index `0`).
    pub fn next_reveal(&self) -> Result<Option<Hash256>, Error> {
        match self.peek_reveal()? {
            Some(reveal) => {
                self.consume_reveal(reveal)?;
                Ok(Some(reveal))
            }
            None => Ok(None),
        }
    }

    /// Record a successful registration. Idempotent: an existing registration is preserved.
    pub fn mark_registered(
        &self,
        registered_epoch: Epoch,
        activation_epoch: Epoch,
    ) -> Result<(), Error> {
        let mut state = self.state.lock();
        if state.registered_epoch.is_some() {
            return Ok(());
        }
        state.registered_epoch = Some(registered_epoch);
        state.activation_epoch = Some(activation_epoch);
        self.persist(&state)
    }

    /// The persisted state, cloned.
    pub fn state(&self) -> PersistedState {
        self.state.lock().clone()
    }

    fn persist(&self, state: &PersistedState) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(state).map_err(Error::UnableToEncode)?;
        write_file_via_temporary(&self.path, &self.temp_path, &bytes)
            .map_err(|_| Error::UnableToWriteFile(self.path.clone()))
    }
}

/// Per-validator hash chains, backed by `<validator_dir>/randao_chains/`.
pub struct RandaoChainStore {
    dir: PathBuf,
    chains: RwLock<HashMap<PublicKeyBytes, Arc<ValidatorChain>>>,
}

impl RandaoChainStore {
    /// Open (or create) the store rooted at `validator_dir`.
    pub fn open_or_create<P: AsRef<Path>>(validator_dir: P) -> Result<Self, Error> {
        Self::open_at(&validator_dir.as_ref().join(RANDAO_CHAIN_DIR))
    }

    /// Open the store rooted at an arbitrary directory, creating it if necessary.
    pub fn open_at<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|_| Error::UnableToCreateDir(dir.clone()))?;
        Ok(Self {
            dir,
            chains: RwLock::new(HashMap::new()),
        })
    }

    /// The directory holding the per-validator chain state.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Load the chain for `pubkey` if this validator has one, without creating it.
    pub fn get(&self, pubkey: &PublicKeyBytes) -> Result<Option<Arc<ValidatorChain>>, Error> {
        if let Some(chain) = self.chains.read().get(pubkey) {
            return Ok(Some(chain.clone()));
        }

        let name = chain_file_name(pubkey);
        if !self.dir.join(&name).exists() {
            return Ok(None);
        }

        let chain = Arc::new(ValidatorChain::load_or_create_at(
            &self.dir, *pubkey, &name,
        )?);
        self.chains.write().insert(*pubkey, chain.clone());
        Ok(Some(chain))
    }

    /// Load the chain for `pubkey`, generating and persisting a fresh one if necessary.
    pub fn get_or_create(&self, pubkey: &PublicKeyBytes) -> Result<Arc<ValidatorChain>, Error> {
        if let Some(chain) = self.chains.read().get(pubkey) {
            return Ok(chain.clone());
        }

        let chain = Arc::new(ValidatorChain::load_or_create_at(
            &self.dir,
            *pubkey,
            &chain_file_name(pubkey),
        )?);
        self.chains.write().insert(*pubkey, chain.clone());
        Ok(chain)
    }

    /// Insert an already-built chain, for callers that hold one outside the store.
    pub fn insert(&self, chain: Arc<ValidatorChain>) {
        self.chains.write().insert(chain.pubkey(), chain);
    }
}

fn chain_file_name(pubkey: &PublicKeyBytes) -> String {
    format!("{pubkey}.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(byte: u8) -> PublicKeyBytes {
        PublicKeyBytes::deserialize(&[byte; 48]).unwrap()
    }

    #[test]
    fn chain_links_verify() {
        let chain = HashChain::from_seed(Hash256::repeat_byte(0xab)).unwrap();
        assert_eq!(chain.links().len(), HASH_CHAIN_LENGTH);
        assert_eq!(chain.link(0), Some(Hash256::repeat_byte(0xab)));
        for index in 1..HASH_CHAIN_LENGTH {
            let previous = chain.link(index as u64 - 1).unwrap();
            assert_eq!(chain.link(index as u64), Some(next_link(&previous)));
        }
        // The derivation is deterministic in the seed.
        let same = HashChain::from_seed(Hash256::repeat_byte(0xab)).unwrap();
        assert_eq!(
            chain.link(HASH_CHAIN_TIP_INDEX),
            same.link(HASH_CHAIN_TIP_INDEX)
        );
    }

    #[test]
    fn zero_seed_is_rejected() {
        assert!(matches!(
            HashChain::from_seed(Hash256::ZERO),
            Err(Error::ZeroSeed)
        ));
    }

    #[test]
    fn generated_chain_is_non_zero() {
        let chain = HashChain::generate();
        assert_ne!(chain.seed(), Hash256::ZERO);
        assert!(chain.links().iter().all(|link| *link != Hash256::ZERO));
    }

    #[test]
    fn reveal_advances_the_commitment() {
        let dir = tempfile::tempdir().unwrap();
        let chain =
            ValidatorChain::load_or_create_at(dir.path(), test_pubkey(1), "chain.json").unwrap();

        assert_eq!(chain.index(), HASH_CHAIN_TIP_INDEX);
        assert!(!chain.is_exhausted());

        // The chain is derived from the persisted seed, so it can be rebuilt from `seed()`.
        let rebuilt = HashChain::from_seed(chain.seed()).unwrap();
        let commitment = chain.commitment();
        assert_eq!(rebuilt.link(HASH_CHAIN_TIP_INDEX), Some(commitment));

        // The reveal is the preimage of the commitment, and becomes the new commitment.
        let reveal = chain.next_reveal().unwrap().unwrap();
        assert_eq!(next_link(&reveal), commitment);
        assert_eq!(chain.commitment(), reveal);
        assert_eq!(chain.index(), HASH_CHAIN_TIP_INDEX - 1);
        assert_eq!(rebuilt.link(HASH_CHAIN_TIP_INDEX - 1), Some(reveal));
    }

    #[test]
    fn peek_does_not_consume_until_reveal_is_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let chain =
            ValidatorChain::load_or_create_at(dir.path(), test_pubkey(8), "peek.json").unwrap();

        let commitment = chain.commitment();
        let peeked = chain.peek_reveal().unwrap().unwrap();
        assert_eq!(next_link(&peeked), commitment);
        // Peeking repeatedly returns the same reveal and does not advance the chain.
        assert_eq!(chain.peek_reveal().unwrap(), Some(peeked));
        assert_eq!(chain.commitment(), commitment);

        chain.consume_reveal(peeked).unwrap();
        assert_eq!(chain.commitment(), peeked);
        // Consuming an out-of-order reveal is rejected and leaves the chain untouched.
        assert!(matches!(
            chain.consume_reveal(peeked),
            Err(Error::UnexpectedReveal)
        ));
        assert_eq!(chain.commitment(), peeked);
        assert_ne!(chain.peek_reveal().unwrap(), Some(peeked));
    }

    #[test]
    fn exhaustion_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let chain =
            ValidatorChain::load_or_create_at(dir.path(), test_pubkey(2), "chain.json").unwrap();

        // Force the index to the last link without writing 65k reveals.
        chain.state.lock().index = 1;
        let reveal = chain.next_reveal().unwrap().unwrap();
        assert_eq!(chain.index(), 0);
        assert!(chain.is_exhausted());
        assert_eq!(chain.next_reveal().unwrap(), None);
        // The reveal of the last link is the seed, which remains the commitment at index 0.
        assert_eq!(chain.commitment(), reveal);
        assert_eq!(chain.seed(), reveal);
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = test_pubkey(3);
        let activation_epoch = Epoch::new(7);

        let chain =
            ValidatorChain::load_or_create_at(dir.path(), pubkey, "round_trip.json").unwrap();
        let seed = chain.seed();
        let reveal = chain.next_reveal().unwrap().unwrap();
        chain
            .mark_registered(Epoch::new(4), activation_epoch)
            .unwrap();

        let reloaded =
            ValidatorChain::load_or_create_at(dir.path(), pubkey, "round_trip.json").unwrap();
        assert_eq!(reloaded.seed(), seed);
        assert_eq!(reloaded.index(), chain.index());
        assert_eq!(reloaded.commitment(), chain.commitment());
        assert_eq!(reloaded.registered_epoch(), Some(Epoch::new(4)));
        assert_eq!(reloaded.activation_epoch(), Some(activation_epoch));
        assert!(reloaded.is_active(activation_epoch));
        assert!(!reloaded.is_active(Epoch::new(6)));
        // The reveal taken before the restart is the persisted commitment.
        assert_eq!(reloaded.commitment(), reveal);
    }

    #[test]
    fn registration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let chain =
            ValidatorChain::load_or_create_at(dir.path(), test_pubkey(7), "idempotent.json")
                .unwrap();
        chain.mark_registered(Epoch::new(2), Epoch::new(5)).unwrap();
        chain
            .mark_registered(Epoch::new(9), Epoch::new(12))
            .unwrap();
        assert_eq!(chain.registered_epoch(), Some(Epoch::new(2)));
        assert_eq!(chain.activation_epoch(), Some(Epoch::new(5)));
    }

    #[test]
    fn store_creates_and_reuses_chains() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = test_pubkey(4);
        let store = RandaoChainStore::open_at(dir.path().join("randao_chains")).unwrap();

        assert!(store.get(&pubkey).unwrap().is_none());

        let chain = store.get_or_create(&pubkey).unwrap();
        let again = store.get_or_create(&pubkey).unwrap();
        assert_eq!(chain.seed(), again.seed());

        let stored = store.get(&pubkey).unwrap().unwrap();
        assert_eq!(stored.seed(), chain.seed());
        assert_eq!(stored.commitment(), chain.commitment());
    }

    #[test]
    fn store_is_backed_by_the_validator_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = RandaoChainStore::open_or_create(dir.path()).unwrap();
        assert_eq!(store.dir(), dir.path().join(RANDAO_CHAIN_DIR));
        assert!(store.dir().is_dir());
    }

    #[test]
    fn fresh_chain_has_no_registration() {
        let dir = tempfile::tempdir().unwrap();
        let chain =
            ValidatorChain::load_or_create_at(dir.path(), test_pubkey(5), "fresh.json").unwrap();
        assert_eq!(chain.registered_epoch(), None);
        assert_eq!(chain.activation_epoch(), None);
        assert!(!chain.is_active(Epoch::new(0)));
    }
}
