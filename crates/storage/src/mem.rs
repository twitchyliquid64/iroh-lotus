//! The all-in-memory backend.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::Infallible,
    sync::Arc,
};

use wire::{
    Envelope, EnvelopeDigest,
    msg::{Namespace, NamespaceKey, Value},
    subkey::Subkey,
};

use crate::{NamespaceOp, Resolution, Storage, value};

// Arc-shared with the versions derived from it; a commit clones the map
// of pointers and copy-on-writes only what it touches.
type Version = BTreeMap<NamespaceKey, Arc<Namespace>>;

/// A [`Storage`] held entirely in memory.
///
/// The backend for tests, and the baseline every other backend must agree
/// with. Nothing it does can fail, and `Error = Infallible` says so in the
/// type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemStorage {
    versions: HashMap<EnvelopeDigest, Version>,
    envelopes: HashMap<EnvelopeDigest, Envelope>,
    // Children by parent digest; a BTreeSet so `children` yields them in
    // the ascending order the trait promises.
    children: HashMap<EnvelopeDigest, BTreeSet<EnvelopeDigest>>,
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

    fn contains_version(&self, head: EnvelopeDigest) -> Result<bool, Infallible> {
        Ok(self.versions.contains_key(&head))
    }

    fn resolve(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, Infallible> {
        Ok(self
            .version(head)
            .get(key)
            .map(|namespace| value::resolve(&namespace.value, path)))
    }

    fn value_at(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Value>, Infallible> {
        Ok(self
            .version(head)
            .get(key)
            .and_then(|namespace| value::walk(&namespace.value, path).cloned()))
    }

    fn namespace(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, Infallible> {
        Ok(self
            .version(head)
            .get(key)
            .map(|namespace| Namespace::clone(namespace)))
    }

    fn namespaces(
        &self,
        head: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), Infallible>> {
        self.version(head)
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
                version.insert(key, Arc::new(namespace));
            }
            NamespaceOp::Delete(key) => {
                version
                    .remove(&key)
                    .expect("Delete is pre-validated: the namespace exists");
            }
            NamespaceOp::SetAt { key, path, value } => {
                let namespace = version
                    .get_mut(&key)
                    .expect("SetAt is pre-validated: the namespace exists");
                value::set_at(&mut Arc::make_mut(namespace).value, &path, value);
            }
            NamespaceOp::AmendAt { key, path, op } => {
                let namespace = version
                    .get_mut(&key)
                    .expect("AmendAt is pre-validated: the namespace exists");
                value::amend_at(&mut Arc::make_mut(namespace).value, path.as_ref(), op);
            }
        }

        self.versions.insert(head, version);
        Ok(())
    }

    fn install(
        &mut self,
        head: EnvelopeDigest,
        namespaces: impl IntoIterator<Item = (NamespaceKey, Namespace)>,
    ) -> Result<(), Infallible> {
        self.versions.insert(
            head,
            namespaces
                .into_iter()
                .map(|(key, namespace)| (key, Arc::new(namespace)))
                .collect(),
        );
        Ok(())
    }

    fn retain(&mut self, keep: &[EnvelopeDigest]) -> Result<(), Infallible> {
        self.versions.retain(|head, _| keep.contains(head));
        Ok(())
    }

    fn put_envelope(
        &mut self,
        digest: EnvelopeDigest,
        envelope: Envelope,
    ) -> Result<(), Infallible> {
        if let Some(prev) = envelope.payload().prev_digest() {
            self.children.entry(*prev).or_default().insert(digest);
        }
        self.envelopes.insert(digest, envelope);
        Ok(())
    }

    fn envelope(&self, digest: EnvelopeDigest) -> Result<Option<Envelope>, Infallible> {
        Ok(self.envelopes.get(&digest).cloned())
    }

    fn remove_envelope(&mut self, digest: EnvelopeDigest) -> Result<(), Infallible> {
        if let Some(envelope) = self.envelopes.remove(&digest)
            && let Some(prev) = envelope.payload().prev_digest()
            && let Some(siblings) = self.children.get_mut(prev)
        {
            siblings.remove(&digest);
            if siblings.is_empty() {
                self.children.remove(prev);
            }
        }
        Ok(())
    }

    fn children(
        &self,
        parent: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<EnvelopeDigest, Infallible>> {
        self.children
            .get(&parent)
            .into_iter()
            .flatten()
            .copied()
            .map(Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::MemStorage;

    crate::storage_conformance!(MemStorage::default());
}
