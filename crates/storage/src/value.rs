//! Walks over an in-memory [`Value`] tree.
//!
//! Shared by backends that hold a namespace as one tree — [`MemStorage`]
//! and the default [`Storage::resolve`] — so their semantics can't drift.
//! A backend that stores the tree decomposed implements the same walk
//! against its own layout and proves agreement with the
//! [`conformance`](crate::conformance) suite.
//!
//! [`MemStorage`]: crate::MemStorage
//! [`Storage::resolve`]: crate::Storage::resolve

use wire::{
    msg::{AmendOp, Value},
    subkey::{Subkey, SubkeyPath},
};

use crate::{NodeKind, Resolution};

/// The kind of node `value` is.
pub fn kind(value: &Value) -> NodeKind {
    match value {
        Value::Map(_) => NodeKind::Map,
        Value::Array(_) => NodeKind::Array,
        Value::String(_) | Value::Int(_) | Value::Bool(_) | Value::Key(_) => NodeKind::Leaf,
    }
}

/// Walks `path` from `root`, reporting how far it got.
pub fn resolve(root: &Value, path: &[Subkey]) -> Resolution {
    path.iter()
        .enumerate()
        .try_fold(root, |node, (depth, segment)| match (node, segment) {
            (Value::Map(map), Subkey::Key(key)) => map.get(key).ok_or(Resolution::Missing {
                depth,
                at: NodeKind::Map,
            }),
            (Value::Array(array), Subkey::Index(index)) => {
                array.get(*index as usize).ok_or(Resolution::Missing {
                    depth,
                    at: NodeKind::Array,
                })
            }
            _ => Err(Resolution::Mismatch { depth }),
        })
        .map_or_else(|stopped| stopped, |node| Resolution::Node(kind(node)))
}

/// Applies a pre-validated [`SetAt`](crate::NamespaceOp::SetAt) to a tree.
///
/// # Panics
///
/// The op's contract is that the caller [`resolve`]d the path and found it
/// legal; a path that isn't is a broken invariant, not an error.
pub fn set_at(root: &mut Value, path: &SubkeyPath, value: Option<Value>) {
    let (last, parents) = path
        .as_ref()
        .split_last()
        .expect("SubkeyPath is validated non-empty");

    let parent = walk_mut(root, parents).expect("SetAt is pre-validated: every parent exists");

    match (parent, last, value) {
        (Value::Map(map), Subkey::Key(key), Some(value)) => {
            map.insert(key.clone(), value);
        }
        (Value::Map(map), Subkey::Key(key), None) => {
            map.remove(key)
                .expect("SetAt is pre-validated: the value being cleared exists");
        }
        (Value::Array(array), Subkey::Index(index), Some(value)) => {
            *array
                .get_mut(*index as usize)
                .expect("SetAt is pre-validated: the index is in bounds") = value;
        }
        (Value::Array(array), Subkey::Index(index), None) => {
            // Vec::remove panics out of bounds, which is the contract here.
            array.remove(*index as usize);
        }
        _ => unreachable!("SetAt is pre-validated: the parent's shape matches the segment"),
    }
}

/// Applies a pre-validated [`AmendAt`](crate::NamespaceOp::AmendAt) to a
/// tree.
///
/// # Panics
///
/// The op's contract is that the caller [`resolve`]d the path and found it
/// legal; a path that isn't is a broken invariant, not an error.
pub fn amend_at(root: &mut Value, path: Option<&SubkeyPath>, op: AmendOp) {
    let segments = path.map_or(&[][..], |path| path.as_ref());
    match op {
        AmendOp::AppendEntry(entry) => {
            let target = match segments.split_last() {
                // No path: the namespace's whole value is the array.
                None => root,
                Some((last, parents)) => {
                    let parent = walk_mut(root, parents)
                        .expect("AmendAt is pre-validated: every parent exists");
                    match (parent, last) {
                        (Value::Map(map), Subkey::Key(key)) => map
                            .entry(key.clone())
                            .or_insert_with(|| Value::Array(Vec::new())),
                        (Value::Array(array), Subkey::Index(index)) => array
                            .get_mut(*index as usize)
                            .expect("AmendAt is pre-validated: the index is in bounds"),
                        _ => unreachable!(
                            "AmendAt is pre-validated: the parent's shape matches the segment"
                        ),
                    }
                }
            };
            match target {
                Value::Array(array) => array.push(entry),
                _ => unreachable!("AmendAt is pre-validated: the append target is an array"),
            }
        }
        AmendOp::IncrementDecrement(inc) => {
            match walk_mut(root, segments).expect("AmendAt is pre-validated: the target exists") {
                Value::Int(n) => {
                    *n = inc
                        .apply(*n)
                        .expect("AmendAt is pre-validated: the sum fits an i64 or clamps");
                }
                _ => unreachable!("AmendAt is pre-validated: the target is an integer"),
            }
        }
        AmendOp::DeleteMatching(predicate) => {
            match walk_mut(root, segments).expect("AmendAt is pre-validated: the target exists") {
                Value::Map(map) => map.retain(|_, entry| !predicate.matches(entry)),
                Value::Array(array) => array.retain(|entry| !predicate.matches(entry)),
                _ => unreachable!("AmendAt is pre-validated: the target is a map or array"),
            }
        }
    }
}

/// Walks `path` from `root`, yielding the value it addresses.
pub fn walk<'a>(root: &'a Value, path: &[Subkey]) -> Option<&'a Value> {
    path.iter()
        .try_fold(root, |value, segment| match (value, segment) {
            (Value::Map(map), Subkey::Key(key)) => map.get(key),
            (Value::Array(array), Subkey::Index(index)) => array.get(*index as usize),
            _ => None,
        })
}

/// Walks `path` from `root`, yielding the value it addresses.
fn walk_mut<'a>(root: &'a mut Value, path: &[Subkey]) -> Option<&'a mut Value> {
    path.iter()
        .try_fold(root, |value, segment| match (value, segment) {
            (Value::Map(map), Subkey::Key(key)) => map.get_mut(key),
            (Value::Array(array), Subkey::Index(index)) => array.get_mut(*index as usize),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use wire::{
        keys::{Ed25519PublicKey, Key, PublicKey},
        msg::Value,
    };

    use super::*;

    fn key_value() -> Value {
        Value::Key(Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32])),
            1,
        ))
    }

    /// A key is an atom to the walk: it has fields, but no subkey reaches
    /// them, so descending into one is a mismatch like stepping through
    /// any other leaf.
    #[test]
    fn a_path_cannot_descend_into_a_key() {
        assert_eq!(kind(&key_value()), NodeKind::Leaf);

        let root = Value::Map([("signer".to_string(), key_value())].into());

        assert_eq!(
            resolve(&root, &[Subkey::Key("signer".to_string())]),
            Resolution::Node(NodeKind::Leaf),
        );
        assert_eq!(
            resolve(
                &root,
                &[
                    Subkey::Key("signer".to_string()),
                    Subkey::Key("weight".to_string()),
                ],
            ),
            Resolution::Mismatch { depth: 1 },
        );
    }
}
