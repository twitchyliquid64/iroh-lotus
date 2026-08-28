//! The state a chain of envelopes folds down to.

use std::collections::{BTreeMap, BTreeSet};

use storage::{NamespaceOp, NodeKind, Resolution, Storage};
use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    keys::{Key, KeyId},
    msg::{
        AmendNamespaceKey, AmendOp, FullCheckpoint, Namespace, NamespaceKey, SetNamespaceKey, Value,
    },
    subkey::{Subkey, SubkeyPath},
};

use crate::{ApplyError, Error, TrustedKeysError, ValueError};

/// The reserved namespace holding the minimum number of minutes every
/// node must keep a message before it is eligible for compaction. Writes
/// are validated: the value must be a [`Value::Int`] that is positive
/// and fits a `u32`. Absent, the [`DEFAULT_MIN_KEEP_MINUTES`] applies.
///
/// The determination that enough time has passed MUST be relative to a
/// local time source, and/or using a signed timestamp.
pub const MIN_KEEP_MINUTES_KEY: &str = "_lotus_min_keep_minutes";

/// The compaction floor in force when a chain never set
/// [`MIN_KEEP_MINUTES_KEY`]: five days.
pub const DEFAULT_MIN_KEEP_MINUTES: u32 = 5 * 24 * 60;

/// The reserved namespace holding the least verified signature weight an
/// envelope must carry to apply. Writes are validated: the value must be
/// a [`Value::Int`] that is non-negative and fits a `u32`. Absent — or
/// zero — nothing is required.
///
/// The threshold in force is the one at an envelope's *parent*, so
/// raising it only binds what comes after. Raise it beyond what the
/// trusted key set can produce and the chain accepts nothing further:
/// the ledger will not second-guess an operator here.
pub const MIN_ENVELOPE_WEIGHT_KEY: &str = "_lotus_min_envelope_weight";

/// The reserved namespace holding the fewest distinct keys that must have
/// verifiably signed an envelope for it to apply. Writes are validated:
/// the value must be a [`Value::Int`] that is non-negative and fits a
/// `u32`. Absent — or zero — nothing is required.
///
/// Distinct keys, not signatures: a key signing twice does not clear a
/// threshold of two. Weight and count are separate knobs — one heavy
/// signer can outweigh two light ones, but cannot stand in for them.
pub const MIN_ENVELOPE_SIGNATURES_KEY: &str = "_lotus_min_envelope_signatures";

/// The reserved namespace holding the keys whose signatures the ledger
/// verifies signatures against: a [`Value::Map`] from a key's id, in
/// [`Value::Key`] it names. Writes are validated — every entry must be a
/// key filed under its own id. Absent, nothing is trusted.
///
/// A map rather than an array so a signature's key is one O(path) lookup
/// and a single key can be added or revoked without rewriting the set.
///
/// A signer's weight is read from the set standing at an envelope's
/// *parent*, which is fixed by its `prev` — so an envelope's weight is
/// the same on every node and can never go stale.
pub const TRUSTED_KEYS_KEY: &str = "_lotus_trusted_keys";

/// The reserved namespace describing nodes known to the cluster.
pub const CLUSTER_NODES_KEY: &str = "_lotus_nodes";

/// The ledger, as of some position in the chain.
///
/// A ledger is a cursor: nothing but the head it stands at. State lives
/// in the [`Storage`] each operation is handed, where it is addressed by
/// head — so any number of ledgers can drive one store at once, and
/// copying a ledger is how a chain forks in place. Applying an envelope
/// touches only what the envelope addresses, never the whole state. Even
/// the ledger's config is just state, stored under reserved `_lotus_`
/// namespaces.
///
/// A ledger must only be used with the store it was opened from; a store
/// treats an unknown head as a broken invariant, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ledger {
    head: EnvelopeDigest,
}

impl Ledger {
    /// Opens a ledger from the `Init` envelope that starts a chain,
    /// installing its checkpoint's namespaces in `storage`. Chains
    /// already in the store are left alone.
    pub fn init<S: Storage>(storage: &mut S, envelope: &Envelope) -> Result<Self, Error<S::Error>> {
        match envelope.payload() {
            Msg::Init(init) => {
                // The boundary covers genesis too: a checkpoint can't
                // smuggle in a value an update would be refused for.
                init.state
                    .namespaces
                    .iter()
                    .try_for_each(|(key, namespace)| Self::validate_value(key, &namespace.value))?;

                let head = envelope.digest()?;
                storage
                    .install(head, init.state.namespaces.clone())
                    .map_err(Error::Storage)?;
                Ok(Self { head })
            }
            _ => Err(Error::NotInit),
        }
    }

    /// Reopens a ledger standing at `head`. Any version the store still
    /// holds works, so an old head opens a historical view — readable,
    /// and appendable as a fork.
    pub fn open<S: Storage>(storage: &S, head: EnvelopeDigest) -> Result<Self, Error<S::Error>> {
        storage
            .contains_version(head)
            .map_err(Error::Storage)?
            .then_some(Self { head })
            .ok_or(Error::UnknownHead(head))
    }

    /// Replays a whole chain into `storage`, `Init` envelope first.
    pub fn replay<'a, S: Storage>(
        storage: &mut S,
        envelopes: impl IntoIterator<Item = &'a Envelope>,
    ) -> Result<Self, Error<S::Error>> {
        let mut envelopes = envelopes.into_iter();
        let mut ledger = envelopes
            .next()
            .ok_or(Error::EmptyChain)
            .and_then(|envelope| Self::init(storage, envelope))?;

        envelopes.try_for_each(|envelope| {
            let status = ledger.verify_envelope(storage, envelope)?;
            let mut envelope = envelope.clone();
            envelope.set_verification_status(status);
            ledger.apply(storage, &envelope)
        })?;
        Ok(ledger)
    }

    /// Advances the ledger by one envelope.
    ///
    /// The envelope must chain onto the current [`head`](Ledger::head).
    /// Everything is validated before the one commit, so a rejected
    /// envelope cannot half-apply. The version at the previous head is
    /// kept — other ledgers may be standing on it.
    ///
    /// The envelope must already have been validated and carry a validation
    /// status, such as via an earlier call to verify_envelope.
    pub fn apply<S: Storage>(
        &mut self,
        storage: &mut S,
        envelope: &Envelope,
    ) -> Result<(), ApplyError<S::Error>> {
        let msg = envelope.payload();
        let prev = msg.prev_digest().ok_or(ApplyError::UnexpectedInit)?;

        if prev != &self.head {
            return Err(ApplyError::ChainMismatch {
                expected: self.head,
                found: *prev,
            });
        }
        let head = envelope.digest()?;

        self.check_sig_thresholds(storage, envelope)?;

        let op = match msg {
            // Unreachable: Init is the only variant without a prev digest,
            // so the check above has already rejected it.
            Msg::Init(_) => return Err(ApplyError::UnexpectedInit),
            Msg::SetNamespace(set) => {
                Self::validate_value(&set.key, &set.namespace.value)?;
                NamespaceOp::Put(set.key.clone(), set.namespace.clone())
            }
            Msg::SetNamespaceKey(set) => self.validate_set_key(storage, set)?,
            Msg::AmendNamespaceKey(amend) => self.validate_amend_key(storage, amend)?,
            Msg::DeleteNamespace(del) => {
                self.resolve(storage, &del.key, &[])?
                    .ok_or_else(|| ApplyError::UnknownNamespace(del.key.clone()))?;
                NamespaceOp::Delete(del.key.clone())
            }
        };

        self.validate_nested(storage, &op)?;

        storage
            .commit(self.head, head, op)
            .map_err(ApplyError::Storage)?;
        self.head = head;
        Ok(())
    }

    /// Checks a `SetNamespaceKey` against the store, yielding the op that
    /// commits it. Nothing is written here.
    ///
    /// Every step of the path must already exist — nothing is created
    /// along the way except a fresh leaf under an existing map, so a
    /// typo'd path is refused rather than quietly building a second copy
    /// of the data beside the real one.
    fn validate_set_key<S: Storage>(
        &self,
        storage: &S,
        set: &SetNamespaceKey,
    ) -> Result<NamespaceOp, ApplyError<S::Error>> {
        let miss = |miss: Miss| miss.into_error(&set.key, &set.path);
        let last = set.path.as_ref().len() - 1;

        let resolution = self
            .resolve(storage, &set.key, set.path.as_ref())?
            .ok_or_else(|| ApplyError::UnknownNamespace(set.key.clone()))?;

        match resolution {
            // The path addresses an existing value: a set overwrites it,
            // a clear removes it.
            Resolution::Node(_) => {}
            // The only legal absence: a fresh key set into a map. The
            // segment's shape matched the map, or this would be Mismatch.
            Resolution::Missing {
                depth,
                at: NodeKind::Map,
            } if depth == last && set.value.is_some() => {}
            Resolution::Missing { .. } => return Err(miss(Miss::NotFound)),
            Resolution::Mismatch { .. } => return Err(miss(Miss::TypeMismatch)),
        }

        Ok(NamespaceOp::SetAt {
            key: set.key.clone(),
            path: set.path.clone(),
            value: set.value.clone(),
        })
    }

    /// Checks an `AmendNamespaceKey` against the store, yielding the op
    /// that commits it. Nothing is written here.
    ///
    /// An append lands on an existing array, or creates a one-entry array
    /// as a fresh key under an existing map — nothing else is conjured,
    /// same as [`validate_set_key`](Ledger::validate_set_key). An
    /// increment lands on an existing integer only, its bounds must not
    /// be inverted, and the sum must clamp or stay inside `i64`. No path
    /// at all amends the namespace's value itself.
    fn validate_amend_key<S: Storage>(
        &self,
        storage: &S,
        amend: &AmendNamespaceKey,
    ) -> Result<NamespaceOp, ApplyError<S::Error>> {
        let segments = amend.path.as_ref().map_or(&[][..], |path| path.as_ref());
        // A pathless amend resolves the root, which always exists — so a
        // Missing or Mismatch walked at least one segment.
        let miss = |miss: Miss| {
            let path = amend
                .path
                .as_ref()
                .expect("Missing and Mismatch resolutions walk at least one segment");
            miss.into_error(&amend.key, path)
        };
        let cannot_amend = || ApplyError::AmendTypeMismatch {
            key: amend.key.clone(),
            path: amend.path.clone(),
        };
        let last = segments.len().checked_sub(1);

        let resolution = self
            .resolve(storage, &amend.key, segments)?
            .ok_or_else(|| ApplyError::UnknownNamespace(amend.key.clone()))?;

        match (&amend.op, resolution) {
            (AmendOp::AppendEntry(_), Resolution::Node(NodeKind::Array)) => {}
            // The only legal absence: an append creating its array as a
            // fresh key under an existing map.
            (
                AmendOp::AppendEntry(_),
                Resolution::Missing {
                    depth,
                    at: NodeKind::Map,
                },
            ) if Some(depth) == last => {}
            (AmendOp::AppendEntry(_), Resolution::Node(_)) => return Err(cannot_amend()),
            (AmendOp::IncrementDecrement(inc), Resolution::Node(NodeKind::Leaf)) => {
                if let (Some(min), Some(max)) = (inc.min, inc.max)
                    && min > max
                {
                    return Err(ApplyError::InvalidBounds {
                        key: amend.key.clone(),
                        path: amend.path.clone(),
                    });
                }
                // A leaf isn't enough — the resolution can't tell an
                // integer from a string, so read the value itself.
                let value = storage
                    .value_at(self.head, &amend.key, segments)
                    .map_err(ApplyError::Storage)?;
                match value {
                    Some(Value::Int(n)) => {
                        let sum = inc.apply(n).ok_or_else(|| ApplyError::Overflow {
                            key: amend.key.clone(),
                            path: amend.path.clone(),
                        })?;
                        // Only a root increment can change the value a
                        // namespace rule judges: today's rules all
                        // constrain leaf-rooted namespaces.
                        if segments.is_empty() {
                            Self::validate_value(&amend.key, &Value::Int(sum))?;
                        }
                    }
                    _ => return Err(cannot_amend()),
                }
            }
            (AmendOp::IncrementDecrement(_), Resolution::Node(_)) => return Err(cannot_amend()),
            (_, Resolution::Missing { .. }) => return Err(miss(Miss::NotFound)),
            (_, Resolution::Mismatch { .. }) => return Err(miss(Miss::TypeMismatch)),
        }

        Ok(NamespaceOp::AmendAt {
            key: amend.key.clone(),
            path: amend.path.clone(),
            op: amend.op.clone(),
        })
    }

    fn resolve<S: Storage>(
        &self,
        storage: &S,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, ApplyError<S::Error>> {
        storage
            .resolve(self.head, key, path)
            .map_err(ApplyError::Storage)
    }

    /// The digest of the most recently applied envelope.
    pub fn head(&self) -> EnvelopeDigest {
        self.head
    }

    /// The compaction floor in force at the ledger's position, read from
    /// the reserved [`MIN_KEEP_MINUTES_KEY`] namespace. Absent — or,
    /// defensively, holding an invalid value validation never saw — the
    /// [`DEFAULT_MIN_KEEP_MINUTES`] applies: a malformed floor must not
    /// split nodes over an unreadable value.
    pub fn min_keep_minutes<S: Storage>(&self, storage: &S) -> Result<u32, S::Error> {
        let key = NamespaceKey::try_new(MIN_KEEP_MINUTES_KEY).expect("the reserved key is static");
        Ok(self
            .namespace(storage, &key)?
            .and_then(|namespace| parse_min_keep(&namespace.value))
            .unwrap_or(DEFAULT_MIN_KEEP_MINUTES))
    }

    /// Returns the set of trusted keys at this state, under the reserved
    /// [`TRUSTED_KEYS_KEY`] namespace. Absent, the set is empty.
    ///
    /// A set that is present but unreadable is an error, not an empty
    /// set — unlike [`min_keep_minutes`](Self::min_keep_minutes), whose
    /// fallback is a safe default. Falling back here would leave every
    /// envelope at zero weight, silently disarming verification just
    /// where the config says to arm it. Validation refuses malformed sets
    /// at the boundary, so this fires only on one written by something
    /// that did not enforce those rules.
    pub fn trusted_keys<S: Storage>(
        &self,
        storage: &S,
    ) -> Result<BTreeMap<KeyId, Key>, ApplyError<S::Error>> {
        let key = NamespaceKey::try_new(TRUSTED_KEYS_KEY).expect("the reserved key is static");
        self.namespace(storage, &key)
            .map_err(ApplyError::Storage)?
            .map_or_else(
                || Ok(BTreeMap::new()),
                |namespace| {
                    parse_trusted_keys(&namespace.value).map_err(|reason| {
                        ApplyError::InvalidValue {
                            key: key.clone(),
                            reason: ValueError::TrustedKeys(reason),
                        }
                    })
                },
            )
    }

    /// The least verified signature weight an envelope must carry to
    /// apply at this position — the reserved [`MIN_ENVELOPE_WEIGHT_KEY`]
    /// namespace. Absent, nothing is required.
    pub fn min_envelope_weight<S: Storage>(
        &self,
        storage: &S,
    ) -> Result<u32, ApplyError<S::Error>> {
        self.threshold(
            storage,
            MIN_ENVELOPE_WEIGHT_KEY,
            ValueError::MinEnvelopeWeight,
        )
    }

    /// The fewest distinct keys that must have verifiably signed an
    /// envelope for it to apply at this position — the reserved
    /// [`MIN_ENVELOPE_SIGNATURES_KEY`] namespace. Absent, nothing is
    /// required.
    pub fn min_envelope_signatures<S: Storage>(
        &self,
        storage: &S,
    ) -> Result<u32, ApplyError<S::Error>> {
        self.threshold(
            storage,
            MIN_ENVELOPE_SIGNATURES_KEY,
            ValueError::MinEnvelopeSignatures,
        )
    }

    /// Returns how to reach each node the cluster knows of, under the
    /// reserved [`CLUSTER_NODES_KEY`] namespace. Absent, it knows of none.
    ///
    /// A set that is present but unreadable is an error, not an empty
    /// set. Validation refuses malformed sets at the boundary,
    /// so this fires only on one written by something that did
    /// not enforce those rules.
    pub fn peer_addresses<S: Storage>(
        &self,
        storage: &S,
    ) -> Result<BTreeMap<KeyId, iroh::EndpointAddr>, ApplyError<S::Error>> {
        let key = NamespaceKey::try_new(CLUSTER_NODES_KEY).expect("the reserved key is static");
        self.namespace(storage, &key)
            .map_err(ApplyError::Storage)?
            .map_or_else(
                || Ok(BTreeMap::new()),
                |namespace| {
                    parse_cluster_nodes(&namespace.value).map_err(|reason| {
                        ApplyError::InvalidValue {
                            key: key.clone(),
                            reason: ValueError::ClusterNodes(reason),
                        }
                    })
                },
            )
    }

    /// Reads a `u32` threshold out of a reserved namespace.
    ///
    /// Absent is no threshold; present but unreadable is an error, never
    /// a silent zero. A guard that disarms itself when its own value is
    /// corrupt is not a guard — the same reasoning as
    /// [`trusted_keys`](Self::trusted_keys).
    fn threshold<S: Storage>(
        &self,
        storage: &S,
        namespace: &'static str,
        reason: ValueError,
    ) -> Result<u32, ApplyError<S::Error>> {
        let key = NamespaceKey::try_new(namespace).expect("the reserved key is static");
        self.namespace(storage, &key)
            .map_err(ApplyError::Storage)?
            .map_or(Ok(0), |namespace| {
                parse_threshold(&namespace.value).ok_or(ApplyError::InvalidValue {
                    key: key.clone(),
                    reason,
                })
            })
    }

    /// Refuses an envelope whose signatures did not verify, or that
    /// clears neither threshold in force here.
    ///
    /// The thresholds are read from this ledger — the envelope's parent —
    /// so they are the ones that were in force when it was written, not
    /// whatever a node happens to hold now.
    fn check_sig_thresholds<S: Storage>(
        &self,
        storage: &S,
        envelope: &Envelope,
    ) -> Result<(), ApplyError<S::Error>> {
        let status = envelope.verification_status();
        // Refuse envelopes with invalid signatures
        if let VerificationStatus::Failed { failing_key_ids } = status {
            return Err(ApplyError::InvalidSignatures {
                failing_key_ids: failing_key_ids.clone(),
            });
        }

        let found = status.signature_weight();
        let required = self.min_envelope_weight(storage)?;
        if found < required {
            return Err(ApplyError::InsufficientWeight { required, found });
        }

        let found = envelope.verified_signers();
        let required = self.min_envelope_signatures(storage)?;
        if found < required {
            return Err(ApplyError::InsufficientSignatures { required, found });
        }

        Ok(())
    }

    /// Verifies `envelope`'s signatures against the trusted key set,
    /// yielding the verification result that can be used during fork
    /// resolution.
    ///
    /// The set of valid keys is read from the state at the parent envelope.
    ///
    /// One signature that does not verify, or names a key the set does
    /// not hold, fails the envelope outright — [`VerificationStatus::AllMatched`]
    /// claims all of them matched. An envelope carrying no signatures is
    /// checked and worth nothing, which is not the same as unchecked.
    pub fn verify_envelope<S: Storage>(
        &self,
        storage: &S,
        envelope: &Envelope,
    ) -> Result<VerificationStatus, ApplyError<S::Error>> {
        // Genesis has no parent: its signatures are verified against the
        // key set it installs itself, so the ledger stands at the
        // envelope itself.
        let parent = match envelope.payload().prev_digest() {
            Some(prev) => *prev,
            None => envelope.digest()?,
        };
        if parent != self.head {
            return Err(ApplyError::ChainMismatch {
                expected: self.head,
                found: parent,
            });
        }

        let signatures = envelope.signatures();
        if signatures.is_empty() {
            return Ok(VerificationStatus::AllMatched { total_weight: 0 });
        }

        let keys = self.trusted_keys(storage)?;
        let digest = envelope.signature_digest()?;

        let failing_key_ids: BTreeSet<KeyId> = signatures
            .iter()
            .filter(|(key_id, signature)| {
                !keys
                    .get(*key_id)
                    .is_some_and(|key| key.verify(signature, &digest).is_ok())
            })
            .map(|(key_id, _)| *key_id)
            .collect();
        if !failing_key_ids.is_empty() {
            return Ok(VerificationStatus::Failed { failing_key_ids });
        }

        // One signature per key by construction, so a key cannot pad the
        // total by signing twice.
        let total: u64 = signatures
            .keys()
            .filter_map(|key_id| keys.get(key_id))
            .map(|key| u64::from(key.weight()))
            .sum();

        // Saturating: weights are set by the ledger's own config, but a
        // wrapped total would decide forks differently in a release build
        // than a debug one.
        Ok(VerificationStatus::AllMatched {
            total_weight: u32::try_from(total).unwrap_or(u32::MAX),
        })
    }

    /// The rule judging what `key`'s namespace may hold, if it has one.
    ///
    /// Today the lookup has two baked-in arms; a schema published under a
    /// reserved key can become another without the callers moving.
    fn rule(key: &NamespaceKey) -> Option<Rule> {
        match key.as_ref() {
            MIN_KEEP_MINUTES_KEY => Some(|value| {
                parse_min_keep(value)
                    .map(|_| ())
                    .ok_or(ValueError::MinKeepMinutes)
            }),
            MIN_ENVELOPE_WEIGHT_KEY => Some(|value| {
                parse_threshold(value)
                    .map(|_| ())
                    .ok_or(ValueError::MinEnvelopeWeight)
            }),
            MIN_ENVELOPE_SIGNATURES_KEY => Some(|value| {
                parse_threshold(value)
                    .map(|_| ())
                    .ok_or(ValueError::MinEnvelopeSignatures)
            }),
            TRUSTED_KEYS_KEY => Some(|value| {
                parse_trusted_keys(value)
                    .map(|_| ())
                    .map_err(ValueError::TrustedKeys)
            }),
            CLUSTER_NODES_KEY => Some(|value| {
                parse_cluster_nodes(value)
                    .map(|_| ())
                    .map_err(ValueError::ClusterNodes)
            }),
            _ => None,
        }
    }

    /// Validates the whole value `key` would hold after a write.
    fn validate_value<E>(key: &NamespaceKey, value: &Value) -> Result<(), ApplyError<E>> {
        Self::rule(key)
            .map_or(Ok(()), |rule| rule(value))
            .map_err(|reason| ApplyError::InvalidValue {
                key: key.clone(),
                reason,
            })
    }

    /// Re-judges a nested write against its namespace's rule.
    ///
    /// [`validate_value`](Self::validate_value) judges whole values, and
    /// the `SetAt`/`AmendAt` paths check only the shape of the path they
    /// walk — so a nested write could otherwise leave a reserved
    /// namespace holding something a whole-value write would have been
    /// refused for. Only namespaces with a rule are materialized; every
    /// other write stays O(path).
    fn validate_nested<S: Storage>(
        &self,
        storage: &S,
        op: &NamespaceOp,
    ) -> Result<(), ApplyError<S::Error>> {
        match op {
            NamespaceOp::SetAt { key, path, value } if Self::rule(key).is_some() => {
                let mut result = self.ruled_value(storage, key)?;
                storage::value::set_at(&mut result, path, value.clone());
                Self::validate_value(key, &result)
            }
            NamespaceOp::AmendAt { key, path, op } if Self::rule(key).is_some() => {
                let mut result = self.ruled_value(storage, key)?;
                storage::value::amend_at(&mut result, path.as_ref(), op.clone());
                Self::validate_value(key, &result)
            }
            // A whole-value write is judged where it is built; a delete
            // leaves the namespace absent, which every rule allows.
            _ => Ok(()),
        }
    }

    /// The value a nested write is about to change. O(namespace), which
    /// is why only ruled namespaces reach it.
    fn ruled_value<S: Storage>(
        &self,
        storage: &S,
        key: &NamespaceKey,
    ) -> Result<Value, ApplyError<S::Error>> {
        Ok(self
            .namespace(storage, key)
            .map_err(ApplyError::Storage)?
            .expect("a nested write is pre-validated: the namespace exists")
            .value)
    }

    /// The namespace stored under `key`, if the ledger holds one.
    ///
    /// Materializes the whole namespace.
    pub fn namespace<S: Storage>(
        &self,
        storage: &S,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, S::Error> {
        storage.namespace(self.head, key)
    }

    /// Every namespace the ledger holds, in key order.
    pub fn namespaces<S: Storage>(
        &self,
        storage: &S,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), S::Error>> {
        storage.namespaces(self.head)
    }

    /// The ledger's state as a checkpoint, ready to open a rewritten
    /// chain. The one read that is O(state): every namespace streams
    /// through memory to build it.
    pub fn checkpoint<S: Storage>(&self, storage: &S) -> Result<FullCheckpoint, S::Error> {
        Ok(FullCheckpoint {
            namespaces: storage.namespaces(self.head).collect::<Result<_, _>>()?,
        })
    }
}

/// A valid compaction floor: a positive integer that fits a `u32`.
/// Shared by validation and the read, so what applies is what reads.
fn parse_min_keep(value: &Value) -> Option<u32> {
    match value {
        Value::Int(minutes) => u32::try_from(*minutes).ok().filter(|&minutes| minutes > 0),
        _ => None,
    }
}

/// Reads a threshold: a non-negative integer that fits a `u32`. Zero is
/// legal and means the threshold is not in force.
fn parse_threshold(value: &Value) -> Option<u32> {
    match value {
        Value::Int(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

/// Reads the trusted key set: a map from a key's hex id to the key.
///
/// `None` for anything else — a value that isn't a map, an entry that
/// isn't a key, or a key filed under an id it doesn't derive to. That
/// last check is what makes the map key trustworthy: a key filed under
/// someone else's id would be unreachable by the signatures naming it,
/// and reachable by ones that never signed under it.
fn parse_trusted_keys(value: &Value) -> Result<BTreeMap<KeyId, Key>, TrustedKeysError> {
    let Value::Map(entries) = value else {
        return Err(TrustedKeysError::NotAMap);
    };
    entries
        .iter()
        .map(|(id, entry)| {
            let Value::Key(key) = entry else {
                return Err(TrustedKeysError::NotAKey { id: id.clone() });
            };
            let derived = key.id();
            (id.as_str() == derived.to_hex().as_ref())
                .then(|| (derived, key.clone()))
                .ok_or_else(|| TrustedKeysError::IdMismatch {
                    id: id.clone(),
                    derived,
                })
        })
        .collect()
}

/// Parses the set of cluster nodes: a map from a nodes keyID to metadata
/// about it including how to reach it over the network.
///
/// Ids are spelled the one way `KeyId::to_hex` writes them. Two spellings
/// of one id are two entries in the ledger but one key here, and the
/// second would silently displace the first.
fn parse_cluster_nodes(value: &Value) -> Result<BTreeMap<KeyId, iroh::EndpointAddr>, String> {
    let Value::Map(entries) = value else {
        return Err("not a map".to_string());
    };
    entries
        .iter()
        .map(|(id, entry)| {
            let node_id = KeyId::from_hex(id).map_err(|e| format!("{id}: {e}"))?;
            if id.as_str() != node_id.to_hex().as_ref() {
                return Err(format!("{id}: not the canonical spelling of a key id"));
            }
            Ok((node_id, {
                let Value::Map(inner) = entry else {
                    return Err(format!("{id}: not a map"));
                };
                let Some(iroh) = inner.get("iroh") else {
                    return Err(format!("{id}: missing or invalid `iroh` value"));
                };
                iroh::EndpointAddr::try_from(iroh).map_err(|e| format!("{id}: {e}"))?
            }))
        })
        .collect()
}

/// A reserved namespace's rule: what its value must satisfy, and why it
/// doesn't when it doesn't.
type Rule = fn(&Value) -> Result<(), ValueError>;

/// Why a path stopped short. Carries no context of its own; the caller
/// pins the namespace and path onto it.
enum Miss {
    NotFound,
    TypeMismatch,
}

impl Miss {
    fn into_error<E>(self, key: &NamespaceKey, path: &SubkeyPath) -> ApplyError<E> {
        let (key, path) = (key.clone(), path.clone());
        match self {
            Miss::NotFound => ApplyError::UnknownPath { key, path },
            Miss::TypeMismatch => ApplyError::PathTypeMismatch { key, path },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use ed25519_zebra::SigningKey;
    use storage::MemStorage;
    use wire::{
        keys::{Ed25519PublicKey, Ed25519Signature, PublicKey, Signature},
        msg::{AddrError, DeleteNamespace, IncrementDecrement, InitMsg, SetNamespace},
    };

    use super::*;

    /// Every namespace at the ledger's head, for whole-state asserts.
    fn state(store: &MemStorage, ledger: &Ledger) -> Vec<(NamespaceKey, Namespace)> {
        ledger.namespaces(store).collect::<Result<_, _>>().unwrap()
    }

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    fn ns(v: &str) -> Namespace {
        Namespace {
            value: Value::String(v.to_string()),
        }
    }

    fn init() -> Envelope {
        Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint::default(),
        }))
    }

    fn setup(envelope: &Envelope) -> (MemStorage, Ledger) {
        let mut store = MemStorage::default();
        let ledger = Ledger::init(&mut store, envelope).unwrap();
        (store, ledger)
    }

    fn set(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace: ns(v),
        }))
    }

    fn delete(prev: EnvelopeDigest, k: &str) -> Envelope {
        Envelope::new(Msg::DeleteNamespace(DeleteNamespace { prev, key: key(k) }))
    }

    fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn path(segments: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
        SubkeyPath::try_new(segments.into_iter().collect()).unwrap()
    }

    fn sub(k: &str) -> Subkey {
        Subkey::Key(k.to_string())
    }

    /// A namespace whose value is
    /// `{"a": {"b": "1"}, "count": 5, "list": ["x", "y"]}`.
    fn nested() -> Namespace {
        Namespace {
            value: map([
                ("a", map([("b", Value::String("1".into()))])),
                ("count", Value::Int(5)),
                (
                    "list",
                    Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
                ),
            ]),
        }
    }

    /// A store and ledger holding [`nested`] under namespace `n`.
    fn nested_ledger() -> (MemStorage, Ledger) {
        setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("n"), nested())].into_iter().collect(),
            },
        })))
    }

    fn set_key(prev: EnvelopeDigest, p: SubkeyPath, value: Option<Value>) -> Envelope {
        Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key("n"),
            path: p,
            value,
        }))
    }

    /// Reads back what a path addresses, for asserting on.
    fn at(store: &MemStorage, ledger: &Ledger, p: &[Subkey]) -> Option<Value> {
        let namespace = ledger.namespace(store, &key("n")).unwrap()?;
        p.iter()
            .try_fold(&namespace.value, |value, segment| match (value, segment) {
                (Value::Map(map), Subkey::Key(k)) => map.get(k),
                (Value::Array(array), Subkey::Index(index)) => array.get(*index as usize),
                _ => None,
            })
            .cloned()
    }

    #[test]
    fn init_opens_at_the_checkpoint() {
        let envelope = init();
        let (store, ledger) = setup(&envelope);

        assert_eq!(ledger.head(), envelope.digest().unwrap());
        assert_eq!(ledger.namespaces(&store).count(), 0);
    }

    /// An `Init` carrying state opens the ledger already populated, which is
    /// what makes a compacted or rewritten chain resumable.
    #[test]
    fn init_carries_its_state_across() {
        let (store, ledger) = setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("a"), ns("1"))].into_iter().collect(),
            },
        })));

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
    }

    #[test]
    fn init_rejects_a_non_init_envelope() {
        let mut store = MemStorage::default();
        let envelope = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        assert!(matches!(
            Ledger::init(&mut store, &envelope),
            Err(Error::NotInit)
        ));
    }

    /// Opening a second chain in the same store must not disturb the
    /// first — that's the point of the store not owning a head.
    #[test]
    fn init_leaves_other_chains_alone() {
        let (mut store, first) = setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("old"), ns("1"))].into_iter().collect(),
            },
        })));

        let second = Ledger::init(&mut store, &init()).unwrap();

        assert_eq!(first.namespace(&store, &key("old")).unwrap(), Some(ns("1")));
        assert_eq!(second.namespace(&store, &key("old")).unwrap(), None);
    }

    #[test]
    fn open_resumes_at_a_head() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let reopened = Ledger::open(&store, ledger.head()).unwrap();
        assert_eq!(reopened, ledger);
        assert_eq!(
            reopened.namespace(&store, &key("a")).unwrap(),
            Some(ns("1"))
        );
    }

    #[test]
    fn open_rejects_an_unknown_head() {
        let store = MemStorage::default();
        let head = EnvelopeDigest::from_bytes([0xab; 32]);

        assert!(matches!(
            Ledger::open(&store, head),
            Err(Error::UnknownHead(h)) if h == head
        ));
    }

    /// Advancing a ledger doesn't consume the version it stood on: the
    /// old head still opens, as a historical view of the chain.
    #[test]
    fn an_old_head_stays_readable() {
        let opening = init();
        let (mut store, mut ledger) = setup(&opening);
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let past = Ledger::open(&store, opening.digest().unwrap()).unwrap();
        assert_eq!(past.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
    }

    /// Copying a ledger forks the chain: both cursors advance from the
    /// same head, in one store, without treading on each other.
    #[test]
    fn forked_ledgers_share_one_store() {
        let (mut store, mut left) = setup(&init());
        let mut right = left;

        left.apply(&mut store, &set(left.head(), "a", "1")).unwrap();
        right
            .apply(&mut store, &set(right.head(), "b", "2"))
            .unwrap();

        assert_eq!(left.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
        assert_eq!(left.namespace(&store, &key("b")).unwrap(), None);
        assert_eq!(right.namespace(&store, &key("b")).unwrap(), Some(ns("2")));
        assert_eq!(right.namespace(&store, &key("a")).unwrap(), None);
    }

    #[test]
    fn apply_sets_a_namespace_and_advances_the_head() {
        let init = init();
        let (mut store, mut ledger) = setup(&init);

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
        assert_eq!(ledger.head(), set.digest().unwrap());
        assert_ne!(ledger.head(), init.digest().unwrap());
    }

    #[test]
    fn set_overwrites_a_namespace_wholesale() {
        let (mut store, mut ledger) = setup(&init());

        let first = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &first).unwrap();
        let second = set(ledger.head(), "a", "2");
        ledger.apply(&mut store, &second).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("2")));
        assert_eq!(ledger.namespaces(&store).count(), 1);
    }

    #[test]
    fn apply_deletes_a_namespace() {
        let (mut store, mut ledger) = setup(&init());

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();
        let delete = delete(ledger.head(), "a");
        ledger.apply(&mut store, &delete).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(ledger.head(), delete.digest().unwrap());
    }

    /// The point of the chain: an envelope that doesn't point at the head is
    /// refused, so a gap or a fork can't be folded in unnoticed.
    #[test]
    fn apply_rejects_an_envelope_that_skips_the_head() {
        let (mut store, mut ledger) = setup(&init());
        let head = ledger.head();

        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        let err = ledger.apply(&mut store, &orphan).unwrap_err();

        assert!(matches!(
            err,
            ApplyError::ChainMismatch { expected, found }
                if expected == head && found == EnvelopeDigest::from_bytes([0xab; 32])
        ));
        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(
            ledger.namespaces(&store).count(),
            0,
            "state must not change"
        );
    }

    /// Replaying the same envelope twice fails the second time: its `prev`
    /// points at what is now the previous head, not the current one.
    #[test]
    fn apply_is_not_idempotent() {
        let (mut store, mut ledger) = setup(&init());

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();
        assert!(matches!(
            ledger.apply(&mut store, &set),
            Err(ApplyError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn apply_rejects_a_second_init() {
        let opening = init();
        let (mut store, mut ledger) = setup(&opening);

        assert!(matches!(
            ledger.apply(&mut store, &init()),
            Err(ApplyError::UnexpectedInit)
        ));
        assert_eq!(ledger.head(), opening.digest().unwrap());
    }

    /// Deleting what isn't there is a malformed message rather than a no-op:
    /// two nodes must never disagree about whether an envelope applied.
    #[test]
    fn delete_rejects_an_unknown_namespace() {
        let (mut store, mut ledger) = setup(&init());
        let head = ledger.head();

        let delete = delete(head, "nope");
        let err = ledger.apply(&mut store, &delete).unwrap_err();

        assert!(matches!(err, ApplyError::UnknownNamespace(k) if k == key("nope")));
        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn replay_folds_a_whole_chain() {
        let init = init();
        let a = set(init.digest().unwrap(), "a", "1");
        let b = set(a.digest().unwrap(), "b", "2");
        let delete_a = delete(b.digest().unwrap(), "a");
        let chain = [init, a, b, delete_a];

        let mut store = MemStorage::default();
        let replayed = Ledger::replay(&mut store, &chain).unwrap();

        assert_eq!(replayed.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(
            replayed.namespace(&store, &key("b")).unwrap(),
            Some(ns("2"))
        );
        assert_eq!(replayed.head(), chain.last().unwrap().digest().unwrap());

        // Same result as advancing one envelope at a time.
        let mut stepwise_store = MemStorage::default();
        let stepwise = chain
            .iter()
            .skip(1)
            .try_fold(
                Ledger::init(&mut stepwise_store, &chain[0]).unwrap(),
                |mut ledger, envelope| ledger.apply(&mut stepwise_store, envelope).map(|()| ledger),
            )
            .unwrap();
        assert_eq!(stepwise, replayed);
        assert_eq!(state(&stepwise_store, &stepwise), state(&store, &replayed));
    }

    #[test]
    fn set_key_writes_a_nested_value() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = set_key(
            ledger.head(),
            path([sub("a"), sub("b")]),
            Some(Value::String("2".into())),
        );
        ledger.apply(&mut store, &envelope).unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("a"), sub("b")]),
            Some(Value::String("2".into()))
        );
        assert_eq!(ledger.head(), envelope.digest().unwrap());
    }

    /// Only the addressed value moves; its siblings are left alone. That's
    /// the whole point of the message over republishing the namespace.
    #[test]
    fn set_key_leaves_the_rest_of_the_namespace_alone() {
        let (mut store, mut ledger) = nested_ledger();
        let before = at(&store, &ledger, &[sub("list")]);

        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("a"), sub("b")]),
                    Some(Value::Int(9)),
                ),
            )
            .unwrap();

        assert_eq!(at(&store, &ledger, &[sub("list")]), before);
    }

    /// A key that isn't there yet is created, as long as its parent map is.
    #[test]
    fn set_key_adds_a_new_leaf_to_an_existing_map() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("a"), sub("new")]),
                    Some(Value::Bool(true)),
                ),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("a"), sub("new")]),
            Some(Value::Bool(true))
        );
    }

    #[test]
    fn set_key_clears_a_value_when_given_none() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(ledger.head(), path([sub("a"), sub("b")]), None),
            )
            .unwrap();

        assert_eq!(at(&store, &ledger, &[sub("a"), sub("b")]), None);
        assert_eq!(at(&store, &ledger, &[sub("a")]), Some(map([])));
    }

    #[test]
    fn set_key_replaces_an_array_element_by_index() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("list"), Subkey::Index(1)]),
                    Some(Value::String("z".into())),
                ),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("list")]),
            Some(Value::Array(vec![
                Value::String("x".into()),
                Value::String("z".into()),
            ]))
        );
    }

    /// Clearing an element shortens the array — later indices shift down.
    #[test]
    fn set_key_removes_an_array_element_when_given_none() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(ledger.head(), path([sub("list"), Subkey::Index(0)]), None),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("list")]),
            Some(Value::Array(vec![Value::String("y".into())]))
        );
    }

    /// Nothing is created along the way: an intermediate that doesn't exist
    /// is refused rather than conjured, so a typo can't build a shadow copy
    /// of the data next to the real one.
    #[test]
    fn set_key_refuses_to_create_intermediates() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();
        let before = ledger.namespace(&store, &key("n")).unwrap();

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("nope"), sub("b")]), Some(Value::Int(1))),
            )
            .unwrap_err();

        assert!(matches!(err, ApplyError::UnknownPath { key: k, path: p }
            if k == key("n") && p == path([sub("nope"), sub("b")])));
        assert_eq!(ledger.namespace(&store, &key("n")).unwrap(), before);
        assert_eq!(ledger.head(), head);
    }

    #[test]
    fn set_key_rejects_a_path_of_the_wrong_shape() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        // A key into an array.
        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("list"), sub("x")]), Some(Value::Int(1))),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // An index into a map.
        let err = ledger
            .apply(
                &mut store,
                &set_key(
                    head,
                    path([sub("a"), Subkey::Index(0)]),
                    Some(Value::Int(1)),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // A step through a leaf.
        let err = ledger
            .apply(
                &mut store,
                &set_key(
                    head,
                    path([sub("a"), sub("b"), sub("deeper")]),
                    Some(Value::Int(1)),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));
    }

    #[test]
    fn set_key_rejects_clearing_what_is_not_there() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("a"), sub("gone")]), None),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("list"), Subkey::Index(9)]), None),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn set_key_rejects_an_unknown_namespace() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev: ledger.head(),
            key: key("absent"),
            path: path([sub("a")]),
            value: Some(Value::Int(1)),
        }));

        assert!(matches!(
            ledger.apply(&mut store, &envelope),
            Err(ApplyError::UnknownNamespace(k)) if k == key("absent")
        ));
    }

    /// A rejected envelope leaves the *store* untouched, not just the
    /// ledger's caches — reopening at the same head must agree.
    #[test]
    fn a_rejected_envelope_leaves_the_store_untouched() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        ledger
            .apply(&mut store, &set_key(head, path([sub("nope")]), None))
            .unwrap_err();

        let reopened = Ledger::open(&store, head).unwrap();
        assert_eq!(reopened.head(), head);
        assert_eq!(
            reopened.namespace(&store, &key("n")).unwrap(),
            Some(nested())
        );
    }

    /// `replay` speaks the crate error, but a mid-chain failure keeps the
    /// specific `ApplyError` underneath rather than flattening it.
    #[test]
    fn replay_wraps_apply_errors() {
        let init = init();
        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");

        let mut store = MemStorage::default();
        let err = Ledger::replay(&mut store, &[init, orphan]).unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::ChainMismatch { .. })
        ));

        // The chain is reachable through `source()`, not just the variant.
        let source = core::error::Error::source(&err).unwrap();
        assert!(source.downcast_ref::<ApplyError<Infallible>>().is_some());
    }

    #[test]
    fn replay_rejects_an_empty_chain() {
        let mut store = MemStorage::default();
        assert!(matches!(
            Ledger::replay(&mut store, &[]),
            Err(Error::EmptyChain)
        ));
    }

    fn amend(prev: EnvelopeDigest, p: SubkeyPath, op: AmendOp) -> Envelope {
        Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev,
            key: key("n"),
            path: Some(p),
            op,
        }))
    }

    /// An amend of namespace `k`'s whole value — no path.
    fn amend_root(prev: EnvelopeDigest, k: &str, op: AmendOp) -> Envelope {
        Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev,
            key: key(k),
            path: None,
            op,
        }))
    }

    fn append(v: &str) -> AmendOp {
        AmendOp::AppendEntry(Value::String(v.to_string()))
    }

    fn inc(delta: i64) -> AmendOp {
        AmendOp::IncrementDecrement(IncrementDecrement::new(delta))
    }

    /// A key is a leaf, so neither writing through one nor amending one is
    /// legal — both are refused at validation, never stored.
    #[test]
    fn a_key_cannot_be_descended_into_or_amended() {
        let (mut store, mut ledger) = nested_ledger();

        let signer = Value::Key(wire::keys::Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32])),
            1,
        ));
        let envelope = set_key(ledger.head(), path([sub("signer")]), Some(signer.clone()));
        ledger.apply(&mut store, &envelope).unwrap();
        assert_eq!(at(&store, &ledger, &[sub("signer")]), Some(signer));

        let head = ledger.head();
        let err = ledger
            .apply(
                &mut store,
                &set_key(
                    head,
                    path([sub("signer"), sub("weight")]),
                    Some(Value::Int(9)),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        let err = ledger
            .apply(&mut store, &amend(head, path([sub("signer")]), inc(1)))
            .unwrap_err();
        assert!(matches!(err, ApplyError::AmendTypeMismatch { .. }));

        assert_eq!(ledger.head(), head);
    }

    #[test]
    fn amend_appends_to_an_existing_array() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = amend(ledger.head(), path([sub("list")]), append("z"));
        ledger.apply(&mut store, &envelope).unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("list")]),
            Some(Value::Array(vec![
                Value::String("x".into()),
                Value::String("y".into()),
                Value::String("z".into()),
            ]))
        );
        assert_eq!(ledger.head(), envelope.digest().unwrap());
    }

    /// An append where nothing is creates the array — a fresh key under an
    /// existing map, same as `SetNamespaceKey`'s one legal absence.
    #[test]
    fn amend_append_creates_a_missing_array() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &amend(ledger.head(), path([sub("a"), sub("fresh")]), append("z")),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("a"), sub("fresh")]),
            Some(Value::Array(vec![Value::String("z".into())]))
        );
    }

    #[test]
    fn amend_append_rejects_a_non_array_target() {
        // A leaf, and a map.
        for p in [path([sub("a"), sub("b")]), path([sub("a")])] {
            let (mut store, mut ledger) = nested_ledger();
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &amend(head, p.clone(), append("z")))
                .unwrap_err();

            assert!(
                matches!(err, ApplyError::AmendTypeMismatch { key: k, path: pp }
                if k == key("n") && pp.as_ref() == Some(&p))
            );
            assert_eq!(ledger.head(), head, "head must not move");
        }
    }

    /// Only a fresh map key is created; a missing intermediate or a
    /// missing array index is refused like any other absence.
    #[test]
    fn amend_append_rejects_other_absences() {
        for p in [
            path([sub("nope"), sub("deeper")]),
            path([sub("list"), Subkey::Index(9)]),
        ] {
            let (mut store, mut ledger) = nested_ledger();
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &amend(head, p.clone(), append("z")))
                .unwrap_err();

            assert!(matches!(err, ApplyError::UnknownPath { key: k, path: pp }
                if k == key("n") && pp == p));
            assert_eq!(ledger.head(), head, "head must not move");
        }
    }

    #[test]
    fn amend_increments_and_decrements_an_integer() {
        let (mut store, mut ledger) = nested_ledger();

        ledger
            .apply(
                &mut store,
                &amend(ledger.head(), path([sub("count")]), inc(3)),
            )
            .unwrap();
        assert_eq!(at(&store, &ledger, &[sub("count")]), Some(Value::Int(8)));

        ledger
            .apply(
                &mut store,
                &amend(ledger.head(), path([sub("count")]), inc(-10)),
            )
            .unwrap();
        assert_eq!(at(&store, &ledger, &[sub("count")]), Some(Value::Int(-2)));
    }

    /// A store and ledger holding a root-array namespace `tags` and a
    /// root-integer namespace `total` — namespaces that are nothing but
    /// their one value.
    fn root_ledger() -> (MemStorage, Ledger) {
        setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [
                    (
                        key("tags"),
                        Namespace {
                            value: Value::Array(vec![Value::String("x".into())]),
                        },
                    ),
                    (
                        key("total"),
                        Namespace {
                            value: Value::Int(5),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            },
        })))
    }

    /// No path: the namespace's whole value is the array appended to.
    #[test]
    fn amend_append_extends_a_root_array() {
        let (mut store, mut ledger) = root_ledger();
        let envelope = amend_root(ledger.head(), "tags", append("y"));
        ledger.apply(&mut store, &envelope).unwrap();

        assert_eq!(
            ledger.namespace(&store, &key("tags")).unwrap(),
            Some(Namespace {
                value: Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
            })
        );
        assert_eq!(ledger.head(), envelope.digest().unwrap());
    }

    /// No path: the namespace's whole value is the integer incremented.
    #[test]
    fn amend_increment_amends_a_root_integer() {
        let (mut store, mut ledger) = root_ledger();
        ledger
            .apply(&mut store, &amend_root(ledger.head(), "total", inc(3)))
            .unwrap();

        assert_eq!(
            ledger.namespace(&store, &key("total")).unwrap(),
            Some(Namespace {
                value: Value::Int(8)
            })
        );
    }

    /// The root always exists, so the only refusal left is its shape:
    /// appends need the root array, increments the root integer.
    #[test]
    fn amend_root_rejects_the_wrong_shape() {
        let cases = [
            ("total", append("y")),
            ("tags", inc(1)),
            ("n", append("y")),
            ("n", inc(1)),
        ];
        for (k, op) in cases {
            let (mut store, mut ledger) = match k {
                "n" => nested_ledger(),
                _ => root_ledger(),
            };
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &amend_root(head, k, op))
                .unwrap_err();

            assert!(
                matches!(err, ApplyError::AmendTypeMismatch { key: kk, path: None }
                if kk == key(k))
            );
            assert_eq!(ledger.head(), head, "head must not move");
        }
    }

    /// A root increment reaches the reserved floor, so the namespace's
    /// rules must judge the sum like they judge any other write.
    #[test]
    fn amend_increment_validates_the_reserved_floor() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set_minutes(ledger.head(), Value::Int(42)))
            .unwrap();

        let bump = amend_root(ledger.head(), MIN_KEEP_MINUTES_KEY, inc(10));
        ledger.apply(&mut store, &bump).unwrap();
        assert_eq!(ledger.min_keep_minutes(&store).unwrap(), 52);

        // A sum the rules refuse — zero or below — never applies.
        let head = ledger.head();
        let err = ledger
            .apply(
                &mut store,
                &amend_root(head, MIN_KEEP_MINUTES_KEY, inc(-52)),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InvalidValue { key: k, .. } if k == key(MIN_KEEP_MINUTES_KEY)
        ));
        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(ledger.min_keep_minutes(&store).unwrap(), 52);

        // Clamped back inside the rules, the same delta applies.
        ledger
            .apply(
                &mut store,
                &amend_root(
                    ledger.head(),
                    MIN_KEEP_MINUTES_KEY,
                    AmendOp::IncrementDecrement(IncrementDecrement::new(-52).with_min(1)),
                ),
            )
            .unwrap();
        assert_eq!(ledger.min_keep_minutes(&store).unwrap(), 1);
    }

    /// A bound only binds when the sum crosses it; count starts at 5.
    #[test]
    fn amend_increment_clamps_to_the_bounds() {
        let cases = [
            (IncrementDecrement::new(3).with_min(0).with_max(10), 8),
            (IncrementDecrement::new(100).with_max(10), 10),
            (IncrementDecrement::new(-100).with_min(0), 0),
            (IncrementDecrement::new(-100).with_max(10), -95),
        ];
        for (inc, expected) in cases {
            let (mut store, mut ledger) = nested_ledger();
            ledger
                .apply(
                    &mut store,
                    &amend(
                        ledger.head(),
                        path([sub("count")]),
                        AmendOp::IncrementDecrement(inc),
                    ),
                )
                .unwrap();

            assert_eq!(
                at(&store, &ledger, &[sub("count")]),
                Some(Value::Int(expected))
            );
        }
    }

    /// A sum that leaves `i64` still applies when a bound on that side
    /// clamps it back — only the unclamped overflow is refused.
    #[test]
    fn amend_increment_clamps_an_overflowing_sum() {
        let cases = [
            (IncrementDecrement::new(i64::MAX).with_max(10), 10),
            (IncrementDecrement::new(i64::MIN).with_min(0), 0),
        ];
        for (inc, expected) in cases {
            let (mut store, mut ledger) = nested_ledger();
            ledger
                .apply(
                    &mut store,
                    &amend(
                        ledger.head(),
                        path([sub("count")]),
                        AmendOp::IncrementDecrement(inc),
                    ),
                )
                .unwrap();

            assert_eq!(
                at(&store, &ledger, &[sub("count")]),
                Some(Value::Int(expected))
            );
        }
    }

    /// A bound on the side the sum doesn't leave can't catch it: the
    /// overflow is still refused.
    #[test]
    fn amend_increment_rejects_overflow_the_bounds_cannot_catch() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(
                &mut store,
                &amend(
                    head,
                    path([sub("count")]),
                    AmendOp::IncrementDecrement(IncrementDecrement::new(i64::MAX).with_min(0)),
                ),
            )
            .unwrap_err();

        assert!(matches!(err, ApplyError::Overflow { .. }));
        assert_eq!(ledger.head(), head, "head must not move");
    }

    /// Inverted bounds are a malformed message, refused before the store
    /// is asked anything.
    #[test]
    fn amend_increment_rejects_inverted_bounds() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(
                &mut store,
                &amend(
                    head,
                    path([sub("count")]),
                    AmendOp::IncrementDecrement(
                        IncrementDecrement::new(1).with_min(10).with_max(0),
                    ),
                ),
            )
            .unwrap_err();

        assert!(matches!(err, ApplyError::InvalidBounds { key: k, path: p }
            if k == key("n") && p == Some(path([sub("count")]))));
        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(at(&store, &ledger, &[sub("count")]), Some(Value::Int(5)));
    }

    /// Incrementing what isn't there is refused, never conjured from zero.
    #[test]
    fn amend_increment_rejects_a_missing_path() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(
                &mut store,
                &amend(head, path([sub("a"), sub("gone")]), inc(1)),
            )
            .unwrap_err();

        assert!(matches!(err, ApplyError::UnknownPath { .. }));
        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn amend_increment_rejects_a_non_integer_target() {
        // A string leaf, a map, and an array.
        for p in [
            path([sub("a"), sub("b")]),
            path([sub("a")]),
            path([sub("list")]),
        ] {
            let (mut store, mut ledger) = nested_ledger();
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &amend(head, p.clone(), inc(1)))
                .unwrap_err();

            assert!(
                matches!(err, ApplyError::AmendTypeMismatch { key: k, path: pp }
                if k == key("n") && pp.as_ref() == Some(&p))
            );
            assert_eq!(ledger.head(), head, "head must not move");
        }
    }

    /// A delta that would leave `i64` is refused before the commit, so
    /// every node agrees the envelope never applied.
    #[test]
    fn amend_increment_rejects_overflow() {
        for delta in [i64::MAX, i64::MIN] {
            let (mut store, mut ledger) = nested_ledger();
            let head = ledger.head();

            // count is 5: +MAX overflows; two +MIN halves underflow.
            if delta == i64::MIN {
                ledger
                    .apply(&mut store, &amend(head, path([sub("count")]), inc(-6)))
                    .unwrap();
            }
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &amend(head, path([sub("count")]), inc(delta)))
                .unwrap_err();

            assert!(matches!(err, ApplyError::Overflow { key: k, path: p }
                if k == key("n") && p == Some(path([sub("count")]))));
            assert_eq!(ledger.head(), head, "head must not move");
        }
    }

    #[test]
    fn amend_rejects_a_path_of_the_wrong_shape() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        // A key into an array, walked through mid-path.
        let err = ledger
            .apply(
                &mut store,
                &amend(
                    head,
                    path([sub("list"), sub("x"), sub("deeper")]),
                    append("z"),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // An index into a map.
        let err = ledger
            .apply(
                &mut store,
                &amend(head, path([sub("a"), Subkey::Index(0)]), inc(1)),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));
    }

    #[test]
    fn amend_rejects_an_unknown_namespace() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev: ledger.head(),
            key: key("absent"),
            path: Some(path([sub("a")])),
            op: inc(1),
        }));

        assert!(matches!(
            ledger.apply(&mut store, &envelope),
            Err(ApplyError::UnknownNamespace(k)) if k == key("absent")
        ));
    }

    fn trusted_key(byte: u8, weight: u32) -> Key {
        Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([byte; 32])),
            weight,
        )
    }

    fn set_keys(prev: EnvelopeDigest, value: Value) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(TRUSTED_KEYS_KEY),
            namespace: Namespace { value },
        }))
    }

    fn hex_id(key: &Key) -> String {
        key.id().to_hex().as_ref().to_string()
    }

    /// The key set as it is stored: each key filed under its own hex id.
    fn keys_map(keys: impl IntoIterator<Item = Key>) -> Value {
        Value::Map(
            keys.into_iter()
                .map(|key| (hex_id(&key), Value::Key(key)))
                .collect(),
        )
    }

    /// The key set is namespace data under a reserved key, versioned per
    /// position — which is what lets an envelope be verified against the
    /// set standing at its parent rather than the node's current head.
    #[test]
    fn trusted_keys_read_the_reserved_namespace() {
        let (mut store, mut ledger) = setup(&init());
        let before = ledger.head();
        assert!(ledger.trusted_keys(&store).unwrap().is_empty());

        let alice = trusted_key(0xaa, 3);
        let bob = trusted_key(0xbb, 1);
        ledger
            .apply(
                &mut store,
                &set_keys(ledger.head(), keys_map([alice.clone(), bob.clone()])),
            )
            .unwrap();

        let keys = ledger.trusted_keys(&store).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.get(&alice.id()), Some(&alice));
        assert_eq!(keys.get(&bob.id()).map(Key::weight), Some(1));

        // The old head still sees the set that was in force there.
        let past = Ledger::open(&store, before).unwrap();
        assert!(past.trusted_keys(&store).unwrap().is_empty());

        // Deleting the namespace trusts nothing again.
        ledger
            .apply(&mut store, &delete(ledger.head(), TRUSTED_KEYS_KEY))
            .unwrap();
        assert!(ledger.trusted_keys(&store).unwrap().is_empty());
    }

    /// Updates to the reserved key set are validated at apply: anything
    /// but a map of keys filed under their own ids is refused before the
    /// commit.
    #[test]
    fn apply_rejects_an_invalid_trusted_key_set() {
        let alice = trusted_key(0xaa, 1);
        let bob_id = hex_id(&trusted_key(0xbb, 1));
        let mismatch = |id: &str| TrustedKeysError::IdMismatch {
            id: id.to_string(),
            derived: alice.id(),
        };
        let upper = hex_id(&alice).to_uppercase();
        let truncated = hex_id(&alice)[..32].to_string();

        // Each case names the reason it must be refused with, so a rule
        // that refuses everything for the wrong reason still fails.
        let invalid = [
            (Value::String("alice".into()), TrustedKeysError::NotAMap),
            (
                Value::Array(vec![Value::Key(alice.clone())]),
                TrustedKeysError::NotAMap,
            ),
            (Value::Key(alice.clone()), TrustedKeysError::NotAMap),
            // An entry that isn't a key.
            (
                map([("id", Value::Int(1))]),
                TrustedKeysError::NotAKey {
                    id: "id".to_string(),
                },
            ),
            // A key filed under someone else's id.
            (
                Value::Map([(bob_id.clone(), Value::Key(alice.clone()))].into()),
                mismatch(&bob_id),
            ),
            // A key filed under an id that isn't hex at all.
            (
                Value::Map([("alice".to_string(), Value::Key(alice.clone()))].into()),
                mismatch("alice"),
            ),
            // The right id, but not in the lowercase-hex canonical form:
            // two spellings of one id would be two entries in the map.
            (
                Value::Map([(upper.clone(), Value::Key(alice.clone()))].into()),
                mismatch(&upper),
            ),
            // The right id, truncated.
            (
                Value::Map([(truncated.clone(), Value::Key(alice.clone()))].into()),
                mismatch(&truncated),
            ),
        ];

        for (value, reason) in invalid {
            let (mut store, mut ledger) = setup(&init());
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &set_keys(head, value))
                .unwrap_err();

            assert!(
                matches!(
                    &err,
                    ApplyError::InvalidValue { key: k, reason: r }
                        if *k == key(TRUSTED_KEYS_KEY)
                            && *r == ValueError::TrustedKeys(reason.clone())
                ),
                "expected {reason:?}, got {err:?}"
            );
            assert_eq!(ledger.head(), head, "head must not move");
            assert!(ledger.trusted_keys(&store).unwrap().is_empty());
        }
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from([seed; 32])
    }

    fn public_key(signing: &SigningKey) -> PublicKey {
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
            signing.verification_key().into(),
        ))
    }

    /// Signs `envelope`'s signature digest with `signing`, naming the key
    /// by the id the trusted set files it under.
    /// Signs `envelope`'s signature digest and files it under the signer's
    /// key id. Attaching a signature never changes that digest, so this
    /// composes however many times.
    fn sign(envelope: Envelope, signing: &SigningKey) -> Envelope {
        let digest = envelope.signature_digest().unwrap();
        let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
            signing.sign(digest.as_bytes()).to_bytes(),
        ));
        envelope.with_signature(public_key(signing).id(), signature)
    }

    /// A ledger whose trusted set holds `keys`, and an envelope chaining
    /// onto it ready to be signed.
    fn verifying_ledger(keys: impl IntoIterator<Item = Key>) -> (MemStorage, Ledger) {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set_keys(ledger.head(), keys_map(keys)))
            .unwrap();
        (store, ledger)
    }

    fn unsigned(prev: EnvelopeDigest) -> Envelope {
        set(prev, "n", "1")
    }

    /// An envelope carrying nothing is checked and worth nothing — which
    /// is not the same as never having been checked.
    #[test]
    fn an_unsigned_envelope_verifies_at_zero_weight() {
        let (store, ledger) = verifying_ledger([]);
        assert_eq!(
            ledger
                .verify_envelope(&store, &unsigned(ledger.head()))
                .unwrap(),
            VerificationStatus::AllMatched { total_weight: 0 }
        );
    }

    /// The weights come from the key set standing at the parent.
    #[test]
    fn signatures_are_weighted_by_their_keys() {
        let alice = signing_key(1);
        let bob = signing_key(2);
        let (store, ledger) = verifying_ledger([
            Key::new(public_key(&alice), 3),
            Key::new(public_key(&bob), 4),
        ]);

        let envelope = unsigned(ledger.head());
        let one = sign(envelope.clone(), &alice);
        assert_eq!(
            ledger.verify_envelope(&store, &one).unwrap(),
            VerificationStatus::AllMatched { total_weight: 3 }
        );

        let both = sign(one, &bob);
        assert_eq!(
            ledger.verify_envelope(&store, &both).unwrap(),
            VerificationStatus::AllMatched { total_weight: 7 }
        );
    }

    /// The same key signing again replaces its signature rather than
    /// adding one, so a padded list cannot multiply what a key is worth.
    #[test]
    fn a_key_signing_twice_counts_once() {
        let alice = signing_key(1);
        let (store, ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);

        let envelope = unsigned(ledger.head());
        let padded = sign(sign(envelope, &alice), &alice);

        assert_eq!(padded.signatures().len(), 1);
        assert_eq!(
            ledger.verify_envelope(&store, &padded).unwrap(),
            VerificationStatus::AllMatched { total_weight: 3 }
        );
    }

    /// `AllMatched` claims every signature matched, so one that does not
    /// fails the envelope rather than merely contributing nothing.
    #[test]
    fn one_bad_signature_fails_the_envelope() {
        let alice = signing_key(1);
        let mallory = signing_key(9);
        let (store, ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);
        let envelope = unsigned(ledger.head());

        // A key the set does not hold.
        let unknown = sign(envelope.clone(), &mallory);
        assert_eq!(
            ledger.verify_envelope(&store, &unknown).unwrap(),
            VerificationStatus::Failed {
                failing_key_ids: [public_key(&mallory).id()].into()
            }
        );

        // A trusted key, but a signature over something else.
        let elsewhere = sign(set(ledger.head(), "other", "1"), &alice);
        let forged = envelope.clone().with_signature(
            public_key(&alice).id(),
            *elsewhere.signatures().values().next().unwrap(),
        );
        assert_eq!(
            ledger.verify_envelope(&store, &forged).unwrap(),
            VerificationStatus::Failed {
                failing_key_ids: [public_key(&alice).id()].into()
            }
        );

        // One good signature does not rescue one bad one, and only the
        // bad one is named.
        let mixed = sign(sign(envelope.clone(), &alice), &mallory);
        assert_eq!(
            ledger.verify_envelope(&store, &mixed).unwrap(),
            VerificationStatus::Failed {
                failing_key_ids: [public_key(&mallory).id()].into()
            }
        );
    }

    /// A signature that verified when it was made and had a byte flipped
    /// on the way is forged, not weak: applying it is refused outright,
    /// the key whose signature no longer checks out is named, and the
    /// ledger stays where it stood.
    #[test]
    fn apply_refuses_an_envelope_whose_signature_was_tampered_with() {
        let alice = signing_key(1);
        let (mut store, mut ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);
        let head = ledger.head();

        let signed = sign(unsigned(head), &alice);
        assert_eq!(
            ledger.verify_envelope(&store, &signed).unwrap(),
            VerificationStatus::AllMatched { total_weight: 3 },
            "the signature being corrupted has to be a good one first",
        );

        // The same key over the same bytes, one bit of the signature
        // itself flipped — what a peer can do to an envelope in flight.
        let Signature::Ed25519(signature) = *signed.signatures().values().next().unwrap();
        let mut bytes = *signature.as_bytes();
        bytes[0] ^= 1;
        let mut tampered = signed.with_signature(
            public_key(&alice).id(),
            Signature::Ed25519(Ed25519Signature::from_bytes(bytes)),
        );

        let status = ledger.verify_envelope(&store, &tampered).unwrap();
        assert_eq!(
            status,
            VerificationStatus::Failed {
                failing_key_ids: [public_key(&alice).id()].into()
            }
        );

        tampered.set_verification_status(status);
        let refused = ledger.apply(&mut store, &tampered).unwrap_err();
        assert!(
            matches!(
                &refused,
                ApplyError::InvalidSignatures { failing_key_ids }
                    if *failing_key_ids == [public_key(&alice).id()].into()
            ),
            "got {refused:?}",
        );
        assert_eq!(ledger.head(), head, "the head stayed where it stood");
    }

    /// Weights come from the ledger's own config, so a total that
    /// overflows is possible — and must clamp rather than wrap, or the
    /// same fork would resolve differently in a release build.
    #[test]
    fn an_overflowing_total_weight_saturates() {
        let alice = signing_key(1);
        let bob = signing_key(2);
        let (store, ledger) = verifying_ledger([
            Key::new(public_key(&alice), u32::MAX),
            Key::new(public_key(&bob), u32::MAX),
        ]);

        let envelope = unsigned(ledger.head());
        let both = sign(sign(envelope.clone(), &alice), &bob);

        assert_eq!(
            ledger.verify_envelope(&store, &both).unwrap(),
            VerificationStatus::AllMatched {
                total_weight: u32::MAX
            }
        );
    }

    /// An unreadable key set is an error, not a silent zero: verification
    /// refuses to guess at what a corrupt set meant to say.
    #[test]
    fn verifying_against_an_unreadable_key_set_errors() {
        let alice = signing_key(1);
        let (mut store, ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);

        let envelope = unsigned(ledger.head());
        let signed = sign(envelope.clone(), &alice);

        // Installed straight into the store, the way an implementation
        // that did not enforce the rules would leave it.
        store
            .install(
                ledger.head(),
                [(
                    key(TRUSTED_KEYS_KEY),
                    Namespace {
                        value: Value::String("alice".into()),
                    },
                )],
            )
            .unwrap();

        let err = ledger.verify_envelope(&store, &signed).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InvalidValue {
                reason: ValueError::TrustedKeys(TrustedKeysError::NotAMap),
                ..
            }
        ));
    }

    /// Revoking a key takes effect for what comes after it, and cannot
    /// reach back: an envelope is always verified at its own parent.
    #[test]
    fn revoking_a_key_only_affects_envelopes_after_it() {
        let alice = signing_key(1);
        let (mut store, mut ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);

        let before = unsigned(ledger.head());
        let signed_before = sign(before.clone(), &alice);
        assert_eq!(
            ledger.verify_envelope(&store, &signed_before).unwrap(),
            VerificationStatus::AllMatched { total_weight: 3 }
        );

        ledger
            .apply(&mut store, &set_keys(ledger.head(), keys_map([])))
            .unwrap();

        // Signed by the same key, but chaining onto the revocation.
        let after = unsigned(ledger.head());
        let signed_after = sign(after.clone(), &alice);
        assert_eq!(
            ledger.verify_envelope(&store, &signed_after).unwrap(),
            VerificationStatus::Failed {
                failing_key_ids: [public_key(&alice).id()].into()
            }
        );
    }

    /// Standing anywhere but the envelope's parent is refused outright —
    /// a ledger that has moved on holds a key set that was never in force
    /// for the envelope, and a weight taken from it would be fiction.
    #[test]
    fn verifying_from_the_wrong_position_is_refused() {
        let alice = signing_key(1);
        let (mut store, mut ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);

        let parent = ledger.head();
        let envelope = unsigned(parent);
        let signed = sign(envelope.clone(), &alice);

        ledger
            .apply(&mut store, &set(parent, "elsewhere", "1"))
            .unwrap();
        let moved_on = ledger.head();

        let err = ledger.verify_envelope(&store, &signed).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::ChainMismatch { expected, found }
                if expected == moved_on && found == parent
        ));
    }

    /// A set that reaches a reader unreadable — written by something that
    /// did not enforce the rules — is an error, not an empty set. Falling
    /// back to empty would leave every envelope at zero weight.
    #[test]
    fn reading_an_unreadable_key_set_is_an_error() {
        let alice = trusted_key(0xaa, 3);
        let (mut store, ledger) = setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("n"), ns("1"))].into_iter().collect(),
            },
        })));

        // Installed straight into the store, bypassing the boundary the
        // way a foreign implementation with laxer rules would.
        store
            .install(
                ledger.head(),
                [(
                    key(TRUSTED_KEYS_KEY),
                    Namespace {
                        value: Value::Map(
                            [(hex_id(&trusted_key(0xbb, 1)), Value::Key(alice.clone()))].into(),
                        ),
                    },
                )],
            )
            .unwrap();

        let err = ledger.trusted_keys(&store).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InvalidValue {
                reason: ValueError::TrustedKeys(TrustedKeysError::IdMismatch { .. }),
                ..
            }
        ));
    }

    /// An empty set is legal — a chain can revoke every key without
    /// deleting the namespace.
    #[test]
    fn an_empty_trusted_key_set_is_valid() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set_keys(ledger.head(), keys_map([])))
            .unwrap();
        assert!(ledger.trusted_keys(&store).unwrap().is_empty());
    }

    /// The id a key is filed under must be exactly what the key derives
    /// to, in lowercase hex — the form [`KeyId::to_hex`] produces.
    #[test]
    fn a_key_is_filed_under_its_own_lowercase_hex_id() {
        let alice = trusted_key(0xaa, 3);
        let id = hex_id(&alice);

        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );

        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(
                &mut store,
                &set_keys(
                    ledger.head(),
                    Value::Map([(id, Value::Key(alice.clone()))].into()),
                ),
            )
            .unwrap();

        assert_eq!(
            ledger.trusted_keys(&store).unwrap().get(&alice.id()),
            Some(&alice)
        );
    }

    /// The point of the map form: rotate one key by path, leaving the
    /// rest of the set untouched.
    #[test]
    fn a_key_can_be_added_and_revoked_by_path() {
        let (mut store, mut ledger) = setup(&init());
        let alice = trusted_key(0xaa, 3);
        let bob = trusted_key(0xbb, 1);
        ledger
            .apply(
                &mut store,
                &set_keys(ledger.head(), keys_map([alice.clone()])),
            )
            .unwrap();

        ledger
            .apply(
                &mut store,
                &set_key_in(
                    ledger.head(),
                    TRUSTED_KEYS_KEY,
                    path([sub(&hex_id(&bob))]),
                    Some(Value::Key(bob.clone())),
                ),
            )
            .unwrap();
        assert_eq!(ledger.trusted_keys(&store).unwrap().len(), 2);

        ledger
            .apply(
                &mut store,
                &set_key_in(
                    ledger.head(),
                    TRUSTED_KEYS_KEY,
                    path([sub(&hex_id(&alice))]),
                    None,
                ),
            )
            .unwrap();
        let keys = ledger.trusted_keys(&store).unwrap();
        assert_eq!(keys.keys().copied().collect::<Vec<_>>(), vec![bob.id()]);
    }

    /// A nested write is judged by the same rule as a whole-value write:
    /// without that, a path could quietly leave the set unreadable, and
    /// an unreadable set leaves every envelope at zero weight.
    #[test]
    fn a_nested_write_cannot_corrupt_the_trusted_key_set() {
        let alice = trusted_key(0xaa, 3);
        let bob_id = hex_id(&trusted_key(0xbb, 1));
        let upper = hex_id(&alice).to_uppercase();
        let mismatch = |id: &str| TrustedKeysError::IdMismatch {
            id: id.to_string(),
            derived: alice.id(),
        };

        let corrupting = [
            // Garbage in place of a key.
            (
                path([sub(&hex_id(&alice))]),
                Some(Value::Int(1)),
                TrustedKeysError::NotAKey { id: hex_id(&alice) },
            ),
            // A key filed under an id it doesn't derive to.
            (
                path([sub(&bob_id)]),
                Some(Value::Key(alice.clone())),
                mismatch(&bob_id),
            ),
            // Its own id, uppercased — the id is right, the spelling isn't.
            (
                path([sub(&upper)]),
                Some(Value::Key(alice.clone())),
                mismatch(&upper),
            ),
        ];

        for (p, value, reason) in corrupting {
            let (mut store, mut ledger) = setup(&init());
            ledger
                .apply(
                    &mut store,
                    &set_keys(ledger.head(), keys_map([alice.clone()])),
                )
                .unwrap();
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &set_key_in(head, TRUSTED_KEYS_KEY, p, value))
                .unwrap_err();

            assert!(
                matches!(
                    &err,
                    ApplyError::InvalidValue { key: k, reason: r }
                        if *k == key(TRUSTED_KEYS_KEY)
                            && *r == ValueError::TrustedKeys(reason.clone())
                ),
                "expected {reason:?}, got {err:?}"
            );
            assert_eq!(ledger.head(), head, "head must not move");
            assert_eq!(ledger.trusted_keys(&store).unwrap().len(), 1);
        }
    }

    /// The same guard on the amend path. Appending onto a key is already
    /// refused as a shape error, but appending under a *fresh* id is a
    /// legal shape — it conjures a one-entry array where a key belongs,
    /// and only the namespace's rule catches that.
    #[test]
    fn a_nested_amend_cannot_corrupt_the_trusted_key_set() {
        let alice = trusted_key(0xaa, 3);
        let amend_keys = |prev, p| {
            Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev,
                key: key(TRUSTED_KEYS_KEY),
                path: Some(p),
                op: append("x"),
            }))
        };

        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(
                &mut store,
                &set_keys(ledger.head(), keys_map([alice.clone()])),
            )
            .unwrap();
        let head = ledger.head();

        // Onto the key itself: a leaf is not an array.
        let err = ledger
            .apply(&mut store, &amend_keys(head, path([sub(&hex_id(&alice))])))
            .unwrap_err();
        assert!(matches!(err, ApplyError::AmendTypeMismatch { .. }));

        // Under an id holding nothing: shapes fine, rule refuses.
        let err = ledger
            .apply(
                &mut store,
                &amend_keys(head, path([sub(&hex_id(&trusted_key(0xbb, 1)))])),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InvalidValue { key: k, .. } if k == key(TRUSTED_KEYS_KEY)
        ));

        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(ledger.trusted_keys(&store).unwrap().len(), 1);
    }

    fn set_key_in(prev: EnvelopeDigest, k: &str, p: SubkeyPath, value: Option<Value>) -> Envelope {
        Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key(k),
            path: p,
            value,
        }))
    }

    fn set_reserved(prev: EnvelopeDigest, k: &str, value: Value) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace: Namespace { value },
        }))
    }

    fn node_key(byte: u8) -> KeyId {
        KeyId::from_bytes([byte; 32])
    }

    /// A node id as the namespace files it: the one spelling
    /// [`KeyId::to_hex`] writes.
    fn node_id(byte: u8) -> String {
        node_key(byte).to_hex().as_ref().to_string()
    }

    /// An endpoint id, spelled the way an address writes one.
    fn node_z32(seed: u8) -> String {
        iroh::SecretKey::from_bytes(&[seed; 32]).public().to_z32()
    }

    fn endpoint(seed: u8) -> iroh::EndpointAddr {
        iroh::EndpointAddr::from_parts(
            iroh::SecretKey::from_bytes(&[seed; 32]).public(),
            [iroh::TransportAddr::Ip("192.0.2.1:4433".parse().unwrap())],
        )
    }

    /// An iroh address, as `wire` writes one into a value.
    fn iroh_addr(seed: u8) -> Value {
        Value::try_from(&endpoint(seed)).unwrap()
    }

    /// What the cluster knows about one node: an address, and whatever
    /// else it publishes.
    fn node(seed: u8) -> Value {
        map([("iroh", iroh_addr(seed))])
    }

    /// The node set as it is stored: each node filed under its hex key id.
    fn nodes(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
        Value::Map(entries.into_iter().collect())
    }

    fn set_nodes(prev: EnvelopeDigest, value: Value) -> Envelope {
        set_reserved(prev, CLUSTER_NODES_KEY, value)
    }

    /// The reason a write to the node set was refused.
    fn refusal(err: &ApplyError<Infallible>) -> &str {
        match err {
            ApplyError::InvalidValue {
                key: k,
                reason: ValueError::ClusterNodes(reason),
            } if *k == key(CLUSTER_NODES_KEY) => reason,
            other => panic!("expected a cluster-nodes refusal, got {other:?}"),
        }
    }

    /// A node needs an address; what else it publishes is its own
    /// business, and rides along unread.
    #[test]
    fn cluster_nodes_accepts_a_node_with_an_address() {
        let (mut store, mut ledger) = setup(&init());
        let value = nodes([
            (node_id(0xaa), node(1)),
            (
                node_id(0xbb),
                map([
                    ("iroh", iroh_addr(2)),
                    ("name", Value::String("bob".into())),
                    ("since", Value::Int(7)),
                ]),
            ),
        ]);

        ledger
            .apply(&mut store, &set_nodes(ledger.head(), value.clone()))
            .unwrap();

        assert_eq!(
            ledger
                .namespace(&store, &key(CLUSTER_NODES_KEY))
                .unwrap()
                .map(|namespace| namespace.value),
            Some(value),
        );
        // What validation accepts is what the reader hands back.
        assert_eq!(
            ledger.peer_addresses(&store).unwrap(),
            BTreeMap::from([(node_key(0xaa), endpoint(1)), (node_key(0xbb), endpoint(2)),]),
        );
    }

    /// An empty set is legal — a cluster that knows of no node yet is not
    /// a corrupt one.
    #[test]
    fn cluster_nodes_accepts_an_empty_set() {
        let (mut store, mut ledger) = setup(&init());

        ledger
            .apply(&mut store, &set_nodes(ledger.head(), map([])))
            .unwrap();
    }

    /// Every way a whole-value write can leave the namespace holding
    /// something no reader could use, refused before it is stored.
    #[test]
    fn apply_rejects_an_invalid_cluster_nodes_set() {
        let id = node_id(0xaa);
        let bad_addr = |addrs: Value| {
            map([
                ("endpoint_id", Value::String(node_z32(1))),
                ("addrs", addrs),
            ])
        };
        let invalid = [
            // The namespace itself is a map of nodes, nothing else.
            (Value::String("nodes".into()), "not a map".to_string()),
            (Value::Int(1), "not a map".to_string()),
            (Value::Array(vec![]), "not a map".to_string()),
            // Filed under something that is not a key id.
            (
                nodes([("nope".to_string(), node(1))]),
                format!("nope: {}", KeyId::from_hex("nope").unwrap_err()),
            ),
            (
                nodes([(node_id(0xaa).replace('a', "z"), node(1))]),
                format!(
                    "{}: {}",
                    node_id(0xaa).replace('a', "z"),
                    KeyId::from_hex(node_id(0xaa).replace('a', "z")).unwrap_err(),
                ),
            ),
            // Its own id, uppercased — the id is right, the spelling
            // isn't, and both spellings would fold into one entry.
            (
                nodes([(node_id(0xaa).to_uppercase(), node(1))]),
                format!(
                    "{}: not the canonical spelling of a key id",
                    node_id(0xaa).to_uppercase(),
                ),
            ),
            (
                nodes([
                    (node_id(0xaa), node(1)),
                    (node_id(0xaa).to_uppercase(), node(2)),
                ]),
                format!(
                    "{}: not the canonical spelling of a key id",
                    node_id(0xaa).to_uppercase(),
                ),
            ),
            // A node is a map of what is known about it.
            (
                nodes([(id.clone(), Value::String("192.0.2.1:4433".into()))]),
                format!("{id}: not a map"),
            ),
            // Known, but not how to reach it.
            (
                nodes([(id.clone(), map([("name", Value::String("alice".into()))]))]),
                format!("{id}: missing or invalid `iroh` value"),
            ),
            // An address that is not one, at three depths: not a map at
            // all, an unreadable id, an unreadable transport.
            (
                nodes([(id.clone(), map([("iroh", Value::Int(1))]))]),
                format!("{id}: {}", AddrError::NotAMap("endpoint address")),
            ),
            (
                nodes([(
                    id.clone(),
                    map([(
                        "iroh",
                        map([
                            ("endpoint_id", Value::String("nope".into())),
                            ("addrs", Value::Array(vec![])),
                        ]),
                    )]),
                )]),
                format!("{id}: {}", AddrError::BadEndpointId("nope".into())),
            ),
            (
                nodes([(
                    id.clone(),
                    map([(
                        "iroh",
                        bad_addr(Value::Array(vec![map([
                            ("type", Value::String("ip".into())),
                            // A host with no port is not a socket address.
                            ("addr", Value::String("192.0.2.1".into())),
                        ])])),
                    )]),
                )]),
                format!(
                    "{id}: {}",
                    AddrError::BadAddr {
                        kind: "ip".into(),
                        text: "192.0.2.1".into(),
                    },
                ),
            ),
        ];

        for (value, reason) in invalid {
            let (mut store, mut ledger) = setup(&init());
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &set_nodes(head, value))
                .unwrap_err();

            assert_eq!(refusal(&err), reason);
            assert_eq!(ledger.head(), head, "head must not move");
            assert_eq!(
                ledger.namespace(&store, &key(CLUSTER_NODES_KEY)).unwrap(),
                None,
                "nothing may be stored",
            );
        }
    }

    /// A nested write is judged by the same rule as a whole-value write:
    /// a path must not be able to leave behind a node the cluster cannot
    /// reach.
    #[test]
    fn a_nested_write_cannot_corrupt_the_cluster_nodes() {
        let id = node_id(0xaa);
        let corrupting = [
            // Garbage in place of the address.
            (
                path([sub(&id), sub("iroh")]),
                Some(Value::Int(1)),
                format!("{id}: {}", AddrError::NotAMap("endpoint address")),
            ),
            // The address cleared away, leaving a node no one can reach.
            (
                path([sub(&id), sub("iroh")]),
                None,
                format!("{id}: missing or invalid `iroh` value"),
            ),
            // Reached into: the id inside the address is still judged.
            (
                path([sub(&id), sub("iroh"), sub("endpoint_id")]),
                Some(Value::Int(1)),
                format!("{id}: {}", AddrError::MissingField("endpoint_id")),
            ),
            // A whole node under an id that is not one.
            (
                path([sub("nope")]),
                Some(node(2)),
                format!("nope: {}", KeyId::from_hex("nope").unwrap_err()),
            ),
            // A second spelling of an id already in the set: stored it
            // would be two entries the reader folds into one.
            (
                path([sub(&node_id(0xaa).to_uppercase())]),
                Some(node(2)),
                format!(
                    "{}: not the canonical spelling of a key id",
                    node_id(0xaa).to_uppercase(),
                ),
            ),
            // A node that is only metadata.
            (
                path([sub(&node_id(0xbb))]),
                Some(map([("name", Value::String("bob".into()))])),
                format!("{}: missing or invalid `iroh` value", node_id(0xbb)),
            ),
        ];

        for (p, value, reason) in corrupting {
            let (mut store, mut ledger) = setup(&init());
            let stored = nodes([(id.clone(), node(1))]);
            ledger
                .apply(&mut store, &set_nodes(ledger.head(), stored.clone()))
                .unwrap();
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &set_key_in(head, CLUSTER_NODES_KEY, p, value))
                .unwrap_err();

            assert_eq!(refusal(&err), reason);
            assert_eq!(ledger.head(), head, "head must not move");
            assert_eq!(
                ledger
                    .namespace(&store, &key(CLUSTER_NODES_KEY))
                    .unwrap()
                    .map(|namespace| namespace.value),
                Some(stored),
                "the set must be left as it was",
            );
        }
    }

    /// The same guard on the amend path, where the shape of the write is
    /// legal and only the namespace's rule catches what it leaves behind.
    #[test]
    fn a_nested_amend_cannot_corrupt_the_cluster_nodes() {
        let id = node_id(0xaa);
        let amend_nodes = |prev, p| {
            Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev,
                key: key(CLUSTER_NODES_KEY),
                path: Some(p),
                op: append("x"),
            }))
        };

        let (mut store, mut ledger) = setup(&init());
        let stored = nodes([(id.clone(), node(1))]);
        ledger
            .apply(&mut store, &set_nodes(ledger.head(), stored.clone()))
            .unwrap();
        let head = ledger.head();

        // Onto the endpoint id: a leaf is not an array.
        let err = ledger
            .apply(
                &mut store,
                &amend_nodes(head, path([sub(&id), sub("iroh"), sub("endpoint_id")])),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::AmendTypeMismatch { .. }));

        // Onto the transport list: a legal append, an unreadable address.
        let err = ledger
            .apply(
                &mut store,
                &amend_nodes(head, path([sub(&id), sub("iroh"), sub("addrs")])),
            )
            .unwrap_err();
        assert_eq!(
            refusal(&err),
            format!("{id}: {}", AddrError::NotAMap("transport address")),
        );

        // Under an id holding nothing: shapes fine, conjures a one-entry
        // array where a node belongs.
        let fresh = node_id(0xbb);
        let err = ledger
            .apply(&mut store, &amend_nodes(head, path([sub(&fresh)])))
            .unwrap_err();
        assert_eq!(refusal(&err), format!("{fresh}: not a map"));

        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(
            ledger
                .namespace(&store, &key(CLUSTER_NODES_KEY))
                .unwrap()
                .map(|namespace| namespace.value),
            Some(stored),
        );
    }

    /// What the check above is for: every id in a stored set reads back
    /// as its own entry, so a node can never be displaced by another
    /// spelling of its id.
    #[test]
    fn every_stored_node_reads_back() {
        let (mut store, mut ledger) = setup(&init());
        let stored = nodes([(node_id(0xaa), node(1)), (node_id(0xbb), node(2))]);

        ledger
            .apply(&mut store, &set_nodes(ledger.head(), stored.clone()))
            .unwrap();

        let Value::Map(entries) = stored else {
            unreachable!("the set is a map");
        };
        assert_eq!(ledger.peer_addresses(&store).unwrap().len(), entries.len());
    }

    /// Absence is not corruption: a cluster may forget every node it knew.
    #[test]
    fn the_cluster_nodes_namespace_can_be_deleted() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(
                &mut store,
                &set_nodes(ledger.head(), nodes([(node_id(0xaa), node(1))])),
            )
            .unwrap();

        ledger
            .apply(&mut store, &delete(ledger.head(), CLUSTER_NODES_KEY))
            .unwrap();

        assert_eq!(
            ledger.namespace(&store, &key(CLUSTER_NODES_KEY)).unwrap(),
            None,
        );
        // Absent is the empty set, not an error.
        assert!(ledger.peer_addresses(&store).unwrap().is_empty());
    }

    /// The boundary covers genesis: a checkpoint cannot install a node
    /// set an update would be refused for.
    #[test]
    fn init_rejects_an_invalid_cluster_nodes_set() {
        let mut store = MemStorage::default();
        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(
                    key(CLUSTER_NODES_KEY),
                    Namespace {
                        value: nodes([(node_id(0xaa), map([("name", Value::String("a".into()))]))]),
                    },
                )]
                .into_iter()
                .collect(),
            },
        }));

        assert!(matches!(
            Ledger::init(&mut store, &envelope),
            Err(Error::Apply(ApplyError::InvalidValue {
                reason: ValueError::ClusterNodes(_),
                ..
            })),
        ));
    }

    /// Both thresholds read the reserved namespace, default to nothing
    /// required, and are versioned per position like any other config.
    #[test]
    fn thresholds_read_their_reserved_namespaces() {
        let alice = signing_key(1);
        let bob = signing_key(2);

        for namespace in [MIN_ENVELOPE_WEIGHT_KEY, MIN_ENVELOPE_SIGNATURES_KEY] {
            let read = |store: &MemStorage, ledger: &Ledger| {
                if namespace == MIN_ENVELOPE_WEIGHT_KEY {
                    ledger.min_envelope_weight(store).unwrap()
                } else {
                    ledger.min_envelope_signatures(store).unwrap()
                }
            };

            let (mut store, mut ledger) = verifying_ledger([
                Key::new(public_key(&alice), 3),
                Key::new(public_key(&bob), 1),
            ]);
            let before = ledger.head();
            assert_eq!(read(&store, &ledger), 0, "{namespace} defaults to nothing");

            ledger
                .apply(
                    &mut store,
                    &set_reserved(ledger.head(), namespace, Value::Int(2)),
                )
                .unwrap();
            assert_eq!(read(&store, &ledger), 2);

            // The old head still sees what was in force there.
            let past = Ledger::open(&store, before).unwrap();
            assert_eq!(read(&store, &past), 0);

            // Deleting the namespace has to clear the threshold it
            // installed — the floor binds the envelope that lifts it.
            let removal = delete(ledger.head(), namespace);
            let signed = verified(&store, &ledger, sign(sign(removal.clone(), &alice), &bob));
            ledger.apply(&mut store, &signed).unwrap();
            assert_eq!(read(&store, &ledger), 0);
        }
    }

    /// Zero is legal — the threshold present but not in force — while
    /// anything that isn't a non-negative `u32` is refused at apply.
    #[test]
    fn apply_rejects_an_invalid_threshold() {
        let cases = [
            (MIN_ENVELOPE_WEIGHT_KEY, ValueError::MinEnvelopeWeight),
            (
                MIN_ENVELOPE_SIGNATURES_KEY,
                ValueError::MinEnvelopeSignatures,
            ),
        ];
        let invalid = [
            Value::String("two".into()),
            Value::Int(-1),
            Value::Int(i64::from(u32::MAX) + 1),
            Value::Bool(true),
            map([]),
        ];

        for (namespace, reason) in cases {
            // Zero is a legal threshold, unlike the compaction floor.
            let (mut store, mut ledger) = setup(&init());
            ledger
                .apply(
                    &mut store,
                    &set_reserved(ledger.head(), namespace, Value::Int(0)),
                )
                .unwrap();

            for value in invalid.clone() {
                let (mut store, mut ledger) = setup(&init());
                let head = ledger.head();

                let err = ledger
                    .apply(&mut store, &set_reserved(head, namespace, value))
                    .unwrap_err();

                assert!(
                    matches!(
                        &err,
                        ApplyError::InvalidValue { key: k, reason: r }
                            if *k == key(namespace) && *r == reason
                    ),
                    "expected {reason:?}, got {err:?}"
                );
                assert_eq!(ledger.head(), head, "head must not move");
            }
        }
    }

    /// An envelope worth less than the floor in force does not apply.
    #[test]
    fn apply_refuses_an_envelope_below_the_weight_floor() {
        let alice = signing_key(1);
        let (mut store, mut ledger) = verifying_ledger([Key::new(public_key(&alice), 3)]);
        ledger
            .apply(
                &mut store,
                &set_reserved(ledger.head(), MIN_ENVELOPE_WEIGHT_KEY, Value::Int(3)),
            )
            .unwrap();
        let head = ledger.head();

        // Unsigned: verified, and worth nothing.
        let bare = unsigned(head);
        let err = ledger.apply(&mut store, &bare).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InsufficientWeight {
                required: 3,
                found: 0
            }
        ));
        assert_eq!(ledger.head(), head, "head must not move");

        // Signed by a key worth exactly the floor: clears it.
        let signed = verified(&store, &ledger, sign(bare, &alice));
        ledger.apply(&mut store, &signed).unwrap();
        assert_ne!(ledger.head(), head);
    }

    /// The count is of distinct keys, so one key signing twice does not
    /// stand in for two signers however heavy it is.
    #[test]
    fn apply_refuses_an_envelope_below_the_signature_floor() {
        let alice = signing_key(1);
        let bob = signing_key(2);
        let (mut store, mut ledger) = verifying_ledger([
            Key::new(public_key(&alice), 9),
            Key::new(public_key(&bob), 1),
        ]);
        ledger
            .apply(
                &mut store,
                &set_reserved(ledger.head(), MIN_ENVELOPE_SIGNATURES_KEY, Value::Int(2)),
            )
            .unwrap();
        let head = ledger.head();

        let envelope = unsigned(head);

        // One heavy signer, counted once however many times it signs —
        // the second signature replaces the first rather than adding one.
        let padded = verified(
            &store,
            &ledger,
            sign(sign(envelope.clone(), &alice), &alice),
        );
        let err = ledger.apply(&mut store, &padded).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::InsufficientSignatures {
                required: 2,
                found: 1
            }
        ));
        assert_eq!(ledger.head(), head, "head must not move");

        // Two distinct signers clear it, however light the second is.
        let both = verified(&store, &ledger, sign(sign(envelope.clone(), &alice), &bob));
        ledger.apply(&mut store, &both).unwrap();
        assert_ne!(ledger.head(), head);
    }

    /// Attaches the status `Chain` would have attached before storing.
    fn verified(store: &MemStorage, ledger: &Ledger, mut envelope: Envelope) -> Envelope {
        let status = ledger.verify_envelope(store, &envelope).unwrap();
        envelope.set_verification_status(status);
        envelope
    }

    fn set_minutes(prev: EnvelopeDigest, value: Value) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(MIN_KEEP_MINUTES_KEY),
            namespace: Namespace { value },
        }))
    }

    /// Config is namespace data under a reserved key: setting it is an
    /// ordinary write, versioned per position like everything else.
    #[test]
    fn min_keep_minutes_reads_the_reserved_namespace() {
        let (mut store, mut ledger) = setup(&init());
        let before = ledger.head();
        assert_eq!(
            ledger.min_keep_minutes(&store).unwrap(),
            DEFAULT_MIN_KEEP_MINUTES
        );

        ledger
            .apply(&mut store, &set_minutes(ledger.head(), Value::Int(42)))
            .unwrap();
        assert_eq!(ledger.min_keep_minutes(&store).unwrap(), 42);

        // The old head still sees what was in force there.
        let past = Ledger::open(&store, before).unwrap();
        assert_eq!(
            past.min_keep_minutes(&store).unwrap(),
            DEFAULT_MIN_KEEP_MINUTES
        );

        // Deleting the namespace reverts to the default.
        ledger
            .apply(&mut store, &delete(ledger.head(), MIN_KEEP_MINUTES_KEY))
            .unwrap();
        assert_eq!(
            ledger.min_keep_minutes(&store).unwrap(),
            DEFAULT_MIN_KEEP_MINUTES
        );
    }

    /// Updates to the reserved floor are validated at apply: anything but
    /// a positive integer that fits a `u32` is refused before the commit.
    #[test]
    fn apply_rejects_an_invalid_min_keep_value() {
        let invalid = [
            Value::String("soon".into()),
            Value::Int(0),
            Value::Int(-1),
            Value::Int(i64::from(u32::MAX) + 1),
            map([]),
        ];
        for value in invalid {
            let (mut store, mut ledger) = setup(&init());
            let head = ledger.head();

            let err = ledger
                .apply(&mut store, &set_minutes(head, value))
                .unwrap_err();

            assert!(matches!(
                err,
                ApplyError::InvalidValue { key: k, .. } if k == key(MIN_KEEP_MINUTES_KEY)
            ));
            assert_eq!(ledger.head(), head, "head must not move");
            assert_eq!(
                ledger.min_keep_minutes(&store).unwrap(),
                DEFAULT_MIN_KEEP_MINUTES
            );
        }
    }

    /// The boundary covers genesis too: an `Init` checkpoint can't
    /// smuggle in a reserved value an update would be refused for.
    #[test]
    fn init_rejects_an_invalid_reserved_value() {
        let mut store = MemStorage::default();
        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key(MIN_KEEP_MINUTES_KEY), ns("garbage"))]
                    .into_iter()
                    .collect(),
            },
        }));

        assert!(matches!(
            Ledger::init(&mut store, &envelope),
            Err(Error::Apply(ApplyError::InvalidValue { .. }))
        ));
    }

    /// A checkpoint built from a ledger's state reopens to exactly that
    /// state — that's what lets a chain be compacted or rewritten, in the
    /// same store, alongside the chain it came from.
    #[test]
    fn checkpoint_reopens_to_the_same_state() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let rewritten = Envelope::new(Msg::Init(InitMsg {
            state: ledger.checkpoint(&store).unwrap(),
        }));
        let reopened = Ledger::init(&mut store, &rewritten).unwrap();

        assert_eq!(
            reopened.checkpoint(&store).unwrap(),
            ledger.checkpoint(&store).unwrap()
        );
        assert_ne!(reopened.head(), ledger.head(), "new chain, new head");
    }
}
