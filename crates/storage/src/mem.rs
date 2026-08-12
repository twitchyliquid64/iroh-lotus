//! The all-in-memory backend.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    sync::Arc,
};

use wire::{
    EnvelopeDigest,
    msg::{FullCheckpoint, LedgerConfig, Namespace, NamespaceKey},
    subkey::Subkey,
};

use crate::{NamespaceOp, Resolution, Storage, value};

/// A [`Storage`] held entirely in memory.
///
/// The backend for tests, and the baseline every other backend must agree
/// with. Nothing it does can fail, and `Error = Infallible` says so in the
/// type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemStorage {
    versions: HashMap<EnvelopeDigest, Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    config: LedgerConfig,
    // Arc-shared with the versions derived from this one; a commit clones
    // the map of pointers and copy-on-writes only what it touches.
    namespaces: BTreeMap<NamespaceKey, Arc<Namespace>>,
}

impl MemStorage {
    fn version(&self, head: EnvelopeDigest) -> &Version {
        self.versions
            .get(&head)
            .expect("head is pre-validated: the version exists")
    }
}

impl Storage for MemStorage {
    type Error = Infallible;

    fn config(&self, head: EnvelopeDigest) -> Result<Option<LedgerConfig>, Infallible> {
        Ok(self
            .versions
            .get(&head)
            .map(|version| version.config.clone()))
    }

    fn resolve(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, Infallible> {
        Ok(self
            .version(head)
            .namespaces
            .get(key)
            .map(|namespace| value::resolve(&namespace.value, path)))
    }

    fn namespace(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, Infallible> {
        Ok(self
            .version(head)
            .namespaces
            .get(key)
            .map(|namespace| Namespace::clone(namespace)))
    }

    fn namespaces(
        &self,
        head: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), Infallible>> {
        self.version(head)
            .namespaces
            .iter()
            .map(|(key, namespace)| Ok((key.clone(), Namespace::clone(namespace))))
    }

    fn commit(
        &mut self,
        parent: EnvelopeDigest,
        head: EnvelopeDigest,
        op: NamespaceOp,
    ) -> Result<(), Infallible> {
        let mut version = self.version(parent).clone();

        match op {
            NamespaceOp::Put(key, namespace) => {
                version.namespaces.insert(key, Arc::new(namespace));
            }
            NamespaceOp::Delete(key) => {
                version
                    .namespaces
                    .remove(&key)
                    .expect("Delete is pre-validated: the namespace exists");
            }
            NamespaceOp::SetAt { key, path, value } => {
                let namespace = version
                    .namespaces
                    .get_mut(&key)
                    .expect("SetAt is pre-validated: the namespace exists");
                value::set_at(&mut Arc::make_mut(namespace).value, &path, value);
            }
        }

        self.versions.insert(head, version);
        Ok(())
    }

    fn install(
        &mut self,
        head: EnvelopeDigest,
        checkpoint: FullCheckpoint,
    ) -> Result<(), Infallible> {
        self.versions.insert(
            head,
            Version {
                config: checkpoint.config,
                namespaces: checkpoint
                    .namespaces
                    .into_iter()
                    .map(|(key, namespace)| (key, Arc::new(namespace)))
                    .collect(),
            },
        );
        Ok(())
    }

    fn retain(&mut self, keep: &[EnvelopeDigest]) -> Result<(), Infallible> {
        self.versions.retain(|head, _| keep.contains(head));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemStorage;

    crate::storage_conformance!(MemStorage::default());
}
