//! Sampling and matching canonical paths.
//!
//! A locator is the puller's canonical path sampled newest-first at
//! exponentially widening offsets, dense near the head where the split is
//! likely and sparse toward the root. The server answers with the newest
//! entry on its own canonical path; the spacing can overshoot the true
//! divergence point, which only costs re-streamed duplicates —
//! `Chain::insert_batch` folds past them — so one round of negotiation is
//! always enough.
//!
//! Both helpers stream: they consume a walk of the canonical path in one
//! pass and hold O([`MAX_LOCATOR_LEN`]) beyond it, so a caller never has
//! to materialize the whole path. The walk itself still costs one parent
//! lookup per envelope — bounding *that* is a storage index's job, not
//! this module's.

use std::collections::HashSet;

use wire::EnvelopeDigest;

/// The most entries a locator may carry: offsets 0, 1, 2, 4, … plus the
/// root cover a path of 2^62 envelopes within it.
pub const MAX_LOCATOR_LEN: usize = 64;

/// Whether a locator samples the entry this many envelopes behind the
/// head.
fn sampled(offset: usize) -> bool {
    offset == 0 || offset.is_power_of_two()
}

/// Samples `path` — a walk of the canonical chain, newest first — at
/// offsets 0, 1, 2, 4, 8, …, always ending on the walk's last entry (the
/// oldest this node holds). One pass; empty in, empty out.
pub fn sample(path: impl IntoIterator<Item = EnvelopeDigest>) -> Vec<EnvelopeDigest> {
    let mut samples = Vec::new();
    let mut last = None;
    for (offset, digest) in path.into_iter().enumerate() {
        if sampled(offset) {
            samples.push(digest);
        }
        last = Some((offset, digest));
    }
    if let Some((offset, root)) = last
        && !sampled(offset)
    {
        samples.push(root);
    }
    samples
}

/// The newest locator entry on `path` — this node's canonical walk,
/// newest first — which is the split point a server streams from; `None`
/// when the chains share nothing. One pass, ending at the first hit.
///
/// The first hit *is* the newest: entries on both chains lie in their
/// shared history, where a tree's root-ward paths coincide, so both sides
/// order them identically — however the puller ordered its locator.
pub fn split(
    locator: &[EnvelopeDigest],
    path: impl IntoIterator<Item = EnvelopeDigest>,
) -> Option<EnvelopeDigest> {
    let offered: HashSet<EnvelopeDigest> = locator.iter().copied().collect();
    path.into_iter().find(|digest| offered.contains(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct digests to stand in for a canonical path.
    fn path(len: usize) -> Vec<EnvelopeDigest> {
        (0..len)
            .map(|n| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
                EnvelopeDigest::from_bytes(bytes)
            })
            .collect()
    }

    #[test]
    fn an_empty_path_samples_empty() {
        assert_eq!(sample([]), Vec::new());
    }

    /// A one-entry path — a node at its root — is just that entry.
    #[test]
    fn a_root_only_path_samples_itself() {
        let path = path(1);
        assert_eq!(sample(path.clone()), path);
    }

    #[test]
    fn short_paths_sample_densely() {
        let path = path(4);
        // Offsets 0, 1, 2 then the last entry 3.
        assert_eq!(sample(path.clone()), path);
    }

    #[test]
    fn offsets_widen_exponentially_and_end_on_the_root() {
        let path = path(100);
        let sampled = sample(path.clone());
        let want: Vec<_> = [0usize, 1, 2, 4, 8, 16, 32, 64, 99]
            .into_iter()
            .map(|offset| path[offset])
            .collect();
        assert_eq!(sampled, want);
    }

    /// When the root itself lands on a power-of-two offset it appears
    /// once, not twice.
    #[test]
    fn the_root_is_never_duplicated() {
        let path = path(5); // offsets 0, 1, 2 then last = 4, itself a power of two
        let sampled = sample(path.clone());
        assert_eq!(sampled, [path[0], path[1], path[2], path[4]]);
    }

    #[test]
    fn long_paths_stay_within_the_locator_cap() {
        let path = path(1_000_000);
        let sampled = sample(path.clone());
        assert!(sampled.len() <= MAX_LOCATOR_LEN);
        assert_eq!(sampled.first(), path.first(), "the head is always sampled");
        assert_eq!(sampled.last(), path.last(), "the root is always sampled");
    }

    /// The walk stops at the first hit, which the shared-history argument
    /// makes the newest common sample.
    #[test]
    fn split_takes_the_newest_hit() {
        let path = path(10);
        let locator = sample(path.clone()); // [0, 1, 2, 4, 8, 9]
        let known = path[3..].to_vec(); // this side forked 3 back

        let at = split(&locator, known);
        assert_eq!(at, Some(path[4]), "offset 4 is the newest common sample");
    }

    /// A shuffled locator changes nothing: the split is decided by the
    /// path's own order, so a puller cannot steer it.
    #[test]
    fn split_ignores_locator_order() {
        let path = path(10);
        let mut locator = sample(path.clone());
        locator.reverse();
        let known = path[3..].to_vec();

        assert_eq!(split(&locator, known), Some(path[4]));
    }

    #[test]
    fn split_finds_nothing_in_disjoint_histories() {
        let locator = sample(path(10));
        let foreign = path(20)[10..].to_vec();
        assert_eq!(split(&locator, foreign), None);
        assert_eq!(split(&locator, []), None, "an empty walk shares nothing");
    }
}
