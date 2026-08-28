//! How `Core::canonical_chain` bounds the walk it returns.
//!
//! The window is asked about with cutoffs taken from the log's own stamps
//! rather than from the clock. What the walk does at a boundary is a
//! question about ordering, and asking it with a cutoff read off `now()`
//! would be asking how long the test itself took to get there.

use std::time::Duration;

use lotusd::{Core, IfInitialized};
use storage::StoredAt;
use tempfile::TempDir;
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// Long enough that the clock has moved on between two inserts. A cutoff
/// can only fall between two stamps that differ, so the envelopes have to
/// land in different milliseconds — nothing here depends on how long it
/// actually takes.
const GAP: Duration = Duration::from_millis(20);

fn set_ns(prev: EnvelopeDigest, value: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new("cfg").unwrap(),
        namespace: Namespace {
            value: Value::String(value.to_string()),
        },
    }))
}

/// A cluster of three envelopes, each stored a moment after the last.
async fn stamped_chain(dir: &TempDir) -> Core {
    let mut core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();

    for value in ["one", "two"] {
        tokio::time::sleep(GAP).await;
        let envelope = set_ns(core.head(), value);
        core.insert([envelope]).unwrap();
    }

    core
}

/// The reading one millisecond after `at` — a cutoff just past an
/// envelope, where the walk must have stopped.
fn just_after(at: StoredAt) -> StoredAt {
    StoredAt::from_timestamp_millis(at.timestamp_millis() + 1).expect("a millisecond later")
}

/// The digests `since` leaves in the walk.
fn walk(core: &Core, since: Option<StoredAt>) -> Vec<EnvelopeDigest> {
    core.canonical_chain(None, since)
        .unwrap()
        .into_iter()
        .map(|(digest, _)| digest)
        .collect()
}

/// A cutoff keeps everything stored at or after it, and the answer is
/// always the newest end of the chain.
#[tokio::test]
async fn a_window_keeps_the_envelopes_stored_at_or_after_its_cutoff() {
    let dir = TempDir::new().unwrap();
    let core = stamped_chain(&dir).await;

    let chain = core.canonical_chain(None, None).unwrap();
    let stamps: Vec<StoredAt> = chain.iter().map(|(_, entry)| entry.stored_at).collect();
    let all: Vec<EnvelopeDigest> = chain.iter().map(|(digest, _)| *digest).collect();
    assert!(
        stamps[0] < stamps[1] && stamps[1] < stamps[2],
        "the envelopes have to be distinguishable in time: {stamps:?}",
    );

    // A cutoff at an envelope's own stamp keeps that envelope: the walk
    // stops at what is older than the cutoff, not at what fails to be
    // newer than it.
    assert_eq!(walk(&core, Some(stamps[0])), all);
    assert_eq!(walk(&core, Some(stamps[1])), all[1..]);
    assert_eq!(walk(&core, Some(stamps[2])), all[2..]);

    // Just past each stamp, that envelope drops out too.
    assert_eq!(walk(&core, Some(just_after(stamps[0]))), all[1..]);
    assert_eq!(walk(&core, Some(just_after(stamps[2]))), Vec::new());

    // No cutoff is the whole chain, which is what a bound has to differ
    // from to be doing anything.
    assert_eq!(walk(&core, None), all);
}

/// The answer is a run ending at the head, never a chain with holes: an
/// envelope inside the window whose parent is outside it cannot be
/// returned on its own.
#[tokio::test]
async fn a_window_answers_with_a_contiguous_run_ending_at_the_head() {
    let dir = TempDir::new().unwrap();
    let core = stamped_chain(&dir).await;

    let chain = core.canonical_chain(None, None).unwrap();
    let stamps: Vec<StoredAt> = chain.iter().map(|(_, entry)| entry.stored_at).collect();

    for since in stamps.iter().copied().map(Some).chain([None]) {
        let walked = core.canonical_chain(None, since).unwrap();

        assert_eq!(
            walked.last().map(|(digest, _)| *digest),
            Some(core.head()),
            "a bounded walk still ends at the head",
        );
        walked.windows(2).for_each(|pair| {
            assert_eq!(
                pair[1].1.envelope.payload().prev_digest(),
                Some(&pair[0].0),
                "each envelope chains onto the one before it",
            );
        });
    }
}

/// Both bounds may be set at once, and the tighter one wins whichever it
/// is.
#[tokio::test]
async fn a_window_and_a_limit_bound_the_same_walk() {
    let dir = TempDir::new().unwrap();
    let core = stamped_chain(&dir).await;

    let chain = core.canonical_chain(None, None).unwrap();
    let stamps: Vec<StoredAt> = chain.iter().map(|(_, entry)| entry.stored_at).collect();
    let all: Vec<EnvelopeDigest> = chain.iter().map(|(digest, _)| *digest).collect();

    let bounded = |limit, since| {
        core.canonical_chain(limit, since)
            .unwrap()
            .into_iter()
            .map(|(digest, _)| digest)
            .collect::<Vec<_>>()
    };

    // The window would have kept two; the limit keeps one.
    assert_eq!(bounded(Some(1), Some(stamps[1])), all[2..]);
    // The limit would have kept three; the window keeps two.
    assert_eq!(bounded(Some(3), Some(stamps[1])), all[1..]);
    // Neither bites.
    assert_eq!(bounded(Some(3), Some(stamps[0])), all);
}
