//! Compact one-line summaries of machine traffic for `tracing` output.
//!
//! Deliberately not `Debug`: an `Envelopes` batch would dump whole
//! payloads into the log, where a line wants counts and short digests.

use core::fmt;

use wire::EnvelopeDigest;

use crate::{
    proto::Message,
    session::{Answer, Effect, Input, Query},
};

/// The first eight hex characters of a digest — enough to correlate log
/// lines, short enough to keep them readable.
struct Short(EnvelopeDigest);

impl fmt::Display for Short {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex().as_ref()[..8])
    }
}

/// Summarizes one machine input.
pub(crate) fn input(input: &Input) -> impl fmt::Display {
    InputSummary(input)
}

/// Summarizes a `handle` call's effects, in order.
pub(crate) fn effects<O: fmt::Debug>(effects: &[Effect<O>]) -> impl fmt::Display {
    EffectsSummary(effects)
}

struct InputSummary<'a>(&'a Input);

impl fmt::Display for InputSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Input::Message(message) => write!(f, "{}", MessageSummary(message)),
            Input::Answer(answer) => write!(f, "{}", AnswerSummary(answer)),
            Input::Ingested => f.write_str("Ingested"),
        }
    }
}

struct MessageSummary<'a>(&'a Message);

impl fmt::Display for MessageSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Message::Hello(hello) => {
                write!(f, "Hello(v{}, head {})", hello.version, Short(hello.head))
            }
            Message::FindSplit(find) => write!(f, "FindSplit({} entries)", find.locator.len()),
            Message::Split(split) => write!(f, "Split({})", Short(split.at)),
            Message::NoSplit(_) => f.write_str("NoSplit"),
            Message::Envelopes(envelopes) => {
                write!(f, "Envelopes({})", envelopes.batch.len())
            }
            Message::CaughtUp(_) => f.write_str("CaughtUp"),
            Message::Announce(announce) => write!(f, "Announce({})", Short(announce.head)),
        }
    }
}

struct AnswerSummary<'a>(&'a Answer);

impl fmt::Display for AnswerSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Answer::Contains(held) => write!(f, "Contains({held})"),
            Answer::Locator(entries) => write!(f, "Locator({} entries)", entries.len()),
            Answer::SplitPoint(Some(at)) => write!(f, "SplitPoint({})", Short(*at)),
            Answer::SplitPoint(None) => f.write_str("SplitPoint(none)"),
            Answer::Segment(envelopes) => write!(f, "Segment({})", envelopes.len()),
        }
    }
}

struct QuerySummary<'a>(&'a Query);

impl fmt::Display for QuerySummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Query::ContainsEnvelope(digest) => {
                write!(f, "ContainsEnvelope({})", Short(*digest))
            }
            Query::Locator => f.write_str("Locator"),
            Query::SplitPoint(entries) => write!(f, "SplitPoint({} entries)", entries.len()),
            Query::Segment { after } => write!(f, "Segment(after {})", Short(*after)),
        }
    }
}

struct EffectsSummary<'a, O>(&'a [Effect<O>]);

impl<O: fmt::Debug> fmt::Display for EffectsSummary<'_, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none");
        }
        self.0.iter().enumerate().try_for_each(|(i, effect)| {
            if i > 0 {
                f.write_str(", ")?;
            }
            match effect {
                Effect::Send(message) => write!(f, "Send({})", MessageSummary(message)),
                Effect::Ask(query) => write!(f, "Ask({})", QuerySummary(query)),
                Effect::Ingest(run) => write!(f, "Ingest({})", run.len()),
                Effect::Done(outcome) => write!(f, "Done({outcome:?})"),
                Effect::Violation(breach) => write!(f, "Violation({breach})"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{FindSplit, Hello, Split},
        session::{Breach, PullOutcome},
    };

    fn d(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    #[test]
    fn inputs_summarize_without_payloads() {
        let hello = Input::Message(Message::Hello(Hello {
            version: 1,
            head: d(0xab),
        }));
        assert_eq!(input(&hello).to_string(), "Hello(v1, head abababab)");

        let find = Input::Message(Message::FindSplit(FindSplit {
            locator: vec![d(1), d(2)],
        }));
        assert_eq!(input(&find).to_string(), "FindSplit(2 entries)");

        assert_eq!(input(&Input::Ingested).to_string(), "Ingested");
        assert_eq!(
            input(&Input::Answer(Answer::SplitPoint(None))).to_string(),
            "SplitPoint(none)"
        );
    }

    #[test]
    fn effects_join_in_order() {
        let both: Vec<Effect<PullOutcome>> = vec![
            Effect::Send(Message::Split(Split { at: d(0xcd) })),
            Effect::Ask(Query::Segment { after: d(0xcd) }),
        ];
        assert_eq!(
            effects(&both).to_string(),
            "Send(Split(cdcdcdcd)), Ask(Segment(after cdcdcdcd))"
        );

        assert_eq!(effects::<PullOutcome>(&[]).to_string(), "none");
        assert_eq!(
            effects(&[Effect::<PullOutcome>::Violation(Breach::EmptyBatch)]).to_string(),
            "Violation(an empty envelope batch)"
        );
    }
}
