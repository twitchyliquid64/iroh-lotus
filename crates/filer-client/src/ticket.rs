//! The ticket: one word that says which volume to mount and where the
//! filer serving it is.
//!
//! It carries no secret. Holding one permits nothing: the filer admits a
//! client by its endpoint id, which the ledger must list. A ticket only
//! saves a client from needing the ledger to find the filer.
//!
//! As text it is [`PREFIX`] followed by the canonical CBOR of the body in
//! unpadded base32, lower case — the shape of a lotus invite.

use core::{fmt, str::FromStr};

use cbor2::Cbor;
use data_encoding::BASE32_NOPAD;
use filer_proto::VolumeName;
use iroh::EndpointAddr;
use wire::msg::{AddrError, Value};

/// What every ticket starts with: what it is, and the version of its body.
pub const PREFIX: &str = "lotusfs1";

/// Which volume to mount, and where the filer serving it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub volume: VolumeName,
    /// The filer's endpoint id, and where it was reachable when the ticket
    /// was made. The id is what matters; the addresses are a head start.
    pub filer: EndpointAddr,
}

/// The ticket as it is encoded. The address is spelled as the ledger
/// spells one, so the two cannot drift apart.
#[derive(Cbor)]
struct Body {
    #[cbor(key = 1)]
    volume: VolumeName,
    #[cbor(key = 2)]
    filer: Value,
}

/// Why text is not a ticket, or a ticket could not be written.
#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    #[error("not a ticket: it does not start with `{PREFIX}`")]
    Prefix,
    #[error("not a ticket: the text after `{PREFIX}` is not base32")]
    Base32,
    #[error("not a ticket: its body does not decode")]
    Body(#[source] wire::Error),
    #[error("the ticket's filer address does not read")]
    Addr(#[source] AddrError),
    #[error("encoding the ticket")]
    Encode(#[source] wire::Error),
}

impl Ticket {
    /// The ticket as text.
    pub fn encode(&self) -> Result<String, TicketError> {
        let body = wire::encode(&Body {
            volume: self.volume.clone(),
            filer: Value::try_from(&self.filer).map_err(TicketError::Addr)?,
        })
        .map_err(TicketError::Encode)?;
        Ok(format!(
            "{PREFIX}{}",
            BASE32_NOPAD.encode(&body).to_ascii_lowercase()
        ))
    }

    /// Reads a ticket from text.
    pub fn decode(text: &str) -> Result<Self, TicketError> {
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(TicketError::Prefix)?;
        let bytes = BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .map_err(|_| TicketError::Base32)?;
        let body: Body = wire::decode(&bytes).map_err(TicketError::Body)?;
        Ok(Self {
            volume: body.volume,
            filer: EndpointAddr::try_from(&body.filer).map_err(TicketError::Addr)?,
        })
    }
}

impl FromStr for Ticket {
    type Err = TicketError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::decode(text)
    }
}

impl fmt::Display for Ticket {
    /// The volume and the filer, for a person; [`encode`](Self::encode)
    /// gives the ticket itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", self.volume, self.filer.id.fmt_short())
    }
}

#[cfg(test)]
mod tests {
    use iroh::{SecretKey, TransportAddr};

    use super::*;

    fn ticket() -> Ticket {
        Ticket {
            volume: VolumeName::try_new("scratch").unwrap(),
            filer: EndpointAddr::from_parts(
                SecretKey::from_bytes(&[7; 32]).public(),
                [
                    TransportAddr::Ip("192.0.2.1:4433".parse().unwrap()),
                    TransportAddr::Relay("https://relay.example./".parse().unwrap()),
                ],
            ),
        }
    }

    #[test]
    fn a_ticket_roundtrips_as_one_lowercase_word() {
        let text = ticket().encode().unwrap();

        assert!(text.starts_with(PREFIX));
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert_eq!(Ticket::decode(&text).unwrap(), ticket());
        assert_eq!(format!("  {text}\n").parse::<Ticket>().unwrap(), ticket());
    }

    #[test]
    fn text_that_is_not_a_ticket_says_why() {
        let text = ticket().encode().unwrap();

        assert!(matches!(
            Ticket::decode("lotus1abc"),
            Err(TicketError::Prefix)
        ));
        assert!(matches!(
            Ticket::decode(&format!("{PREFIX}!!!")),
            Err(TicketError::Base32)
        ));
        assert!(matches!(
            Ticket::decode(&text[..text.len() - 8]),
            Err(TicketError::Body(_) | TicketError::Base32)
        ));
    }
}
