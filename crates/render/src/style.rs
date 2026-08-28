//! Whether a rendering carries colour, and which colour each part of it is.

use core::fmt;
use std::io::IsTerminal;

/// When a rendering should carry colour.
///
/// The `clap` feature makes this a `--color` argument's value type.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ColorChoice {
    /// Colour a terminal, and nothing else.
    #[default]
    Auto,
    /// Colour whatever the output is — a pipe, a file, a test.
    Always,
    /// Never colour.
    Never,
}

impl ColorChoice {
    /// What this choice comes to for `out`.
    ///
    /// `Auto` also honours [`NO_COLOR`](https://no-color.org), so a caller
    /// that has set it is not coloured merely for having a terminal.
    pub fn palette(self, out: &impl IsTerminal) -> Palette {
        match self {
            ColorChoice::Always => Palette::Ansi,
            ColorChoice::Never => Palette::Plain,
            ColorChoice::Auto => {
                match out.is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                {
                    true => Palette::Ansi,
                    false => Palette::Plain,
                }
            }
        }
    }
}

/// The colours a rendering is written in, or none at all.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum Palette {
    /// Text with no escape sequences in it.
    #[default]
    Plain,
    /// The ANSI colours of a terminal.
    Ansi,
}

impl Palette {
    /// Wraps `value` in `style`, or in nothing at all when plain.
    pub(crate) fn paint<T: fmt::Display>(self, style: Style, value: T) -> Painted<T> {
        Painted {
            value,
            sgr: match self {
                Palette::Plain => None,
                Palette::Ansi => Some(style.sgr()),
            },
        }
    }
}

/// What a piece of a rendering means. The colour follows from the meaning,
/// so a caller never names one.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Style {
    /// The line above a chain, saying what is being shown.
    Header,
    /// An envelope digest.
    Digest,
    /// A field's label.
    Label,
    /// What an envelope is — `root`, `head`.
    Mark,
    /// Signatures that all verified.
    Good,
    /// Signatures nobody has checked yet.
    Unknown,
    /// Signatures that failed to verify.
    Bad,
    /// A field with nothing in it.
    Absent,
}

impl Style {
    /// The SGR parameters this style sets.
    fn sgr(self) -> &'static str {
        match self {
            Style::Header => "1",
            Style::Digest => "36",
            Style::Label => "2",
            Style::Mark => "1;33",
            Style::Good => "32",
            Style::Unknown => "33",
            Style::Bad => "1;31",
            Style::Absent => "2",
        }
    }
}

/// A value with a style around it, applied as it is written.
pub(crate) struct Painted<T> {
    value: T,
    /// The SGR parameters to set, or `None` to write the value bare.
    sgr: Option<&'static str>,
}

impl<T: fmt::Display> fmt::Display for Painted<T> {
    /// Resets rather than restores: nothing here nests, so there is no
    /// outer style for a reset to lose.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sgr {
            Some(sgr) => write!(f, "\x1b[{sgr}m{}\x1b[0m", self.value),
            None => self.value.fmt(f),
        }
    }
}
