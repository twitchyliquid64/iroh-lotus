//! What the envelope log records beside an envelope.

use core::fmt;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use wire::Envelope;

/// When a node's log first stored an envelope, read off that node's own
/// clock.
///
/// Local bookkeeping for whoever is inspecting a log, and nothing else. It
/// is not in the envelope, not in any digest, never gossiped, and nothing
/// relevant to consensus may use this value.
///
/// Naive UTC to the millisecond: no zone travels with it, and it is only
/// ever compared against another reading of the same node's clock. The
/// resolution is part of the type so that every backend stores a reading
/// exactly — one that kept nanoseconds in memory and milliseconds on disk
/// would hand back a different reading depending on where it had been.
///
/// [`SignedTimestamp`]: wire::SignedTimestamp
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoredAt(NaiveDateTime);

impl StoredAt {
    /// The clock as it reads now — what a backend stamps a new envelope
    /// with.
    pub fn now() -> Self {
        Self::truncated(Utc::now().naive_utc())
            .expect("a reading of the system clock is a time a datetime holds")
    }

    /// The reading `ago` before now, or `None` when that lands outside the
    /// range a datetime holds — a window so wide it means "everything"
    /// anyway.
    pub fn ago(ago: Duration) -> Option<Self> {
        TimeDelta::from_std(ago)
            .ok()
            .and_then(|delta| Utc::now().naive_utc().checked_sub_signed(delta))
            .and_then(Self::truncated)
    }

    /// The reading itself.
    pub fn naive_utc(self) -> NaiveDateTime {
        self.0
    }

    /// The reading as milliseconds since the unix epoch, for a backend or
    /// a protocol that carries it as a number. Lossless, which is the
    /// point of the resolution.
    pub fn timestamp_millis(self) -> i64 {
        self.0.and_utc().timestamp_millis()
    }

    /// Reads back what [`timestamp_millis`](Self::timestamp_millis) wrote,
    /// or `None` for a number no datetime can hold.
    pub fn from_timestamp_millis(millis: i64) -> Option<Self> {
        DateTime::from_timestamp_millis(millis).map(|at| Self(at.naive_utc()))
    }

    /// `at` at this type's resolution, or `None` for a datetime outside
    /// the range milliseconds address. The one place a reading is taken
    /// down to milliseconds, so no constructor can forget to.
    fn truncated(at: NaiveDateTime) -> Option<Self> {
        Self::from_timestamp_millis(at.and_utc().timestamp_millis())
    }
}

impl fmt::Display for StoredAt {
    /// Seconds and milliseconds, with no zone on the end: there is none,
    /// and writing one would invite a reader to compare it with a clock
    /// that is not this node's.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%d %H:%M:%S%.3f"))
    }
}

/// An envelope as the log holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The envelope itself, exactly as stored — verification status
    /// included.
    pub envelope: Envelope,
    /// When this node first stored it.
    pub stored_at: StoredAt,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend writes the number and reads it back, so the number has
    /// to be the whole reading — anything the round trip drops is a
    /// reading that changes by being stored.
    #[test]
    fn a_reading_survives_the_number_it_is_stored_as() {
        for at in [
            StoredAt::now(),
            StoredAt::ago(Duration::from_secs(1)).unwrap(),
        ] {
            assert_eq!(
                StoredAt::from_timestamp_millis(at.timestamp_millis()),
                Some(at)
            );
            assert_eq!(
                at.naive_utc().and_utc().timestamp_subsec_nanos() % 1_000_000,
                0
            );
        }
    }

    /// Nothing sensible is a hundred thousand years wide, and a window
    /// that big means "everything" regardless.
    #[test]
    fn an_absurd_window_has_no_cutoff() {
        assert!(StoredAt::ago(Duration::from_secs(60)).is_some());
        assert_eq!(StoredAt::ago(Duration::from_secs(u64::MAX)), None);
    }

    /// Ordering is what a `since` walk stops on, so it has to follow the
    /// clock rather than the encoding.
    #[test]
    fn readings_order_by_the_clock() {
        let early = StoredAt::from_timestamp_millis(1_000).unwrap();
        let late = StoredAt::from_timestamp_millis(2_000).unwrap();

        assert!(early < late);
        assert!(StoredAt::from_timestamp_millis(-1_000).unwrap() < early);
    }
}
