//! What the ledger says about volumes, and how it is spelled there.
//!
//! The `filers` namespace maps a volume's name to its entry:
//!
//! ```text
//! filers.<volume>:
//!   endpoint:        { endpoint_id, addrs: [{ type, addr }] }   # the filer serving it
//!   allowed_clients: { <name>: { endpoint_id, mode: ro | rw } } # an operator's
//! ```
//!
//! `endpoint` is an iroh address exactly as `_lotus_nodes` spells one.
//! Everything here is pure: values in, what they mean out.

use std::collections::BTreeMap;

use filer_proto::{Mode, VolumeName};
use iroh::{EndpointAddr, EndpointId};
use lotus_sdk::{NamespaceKey, Subkey, SubkeyPath, Value, wire::msg::ADDRS};

/// The namespace volumes are listed in.
pub const NAMESPACE: &str = "filers";

/// The field of an entry naming the filer that serves the volume.
pub const ENDPOINT: &str = "endpoint";

/// The field of an entry naming who may connect.
pub const ALLOWED_CLIENTS: &str = "allowed_clients";

const ENDPOINT_ID: &str = "endpoint_id";
const MODE: &str = "mode";
const READ_ONLY: &str = "ro";
const READ_WRITE: &str = "rw";

/// The key of the namespace volumes are listed in.
pub fn namespace() -> NamespaceKey {
    NamespaceKey::try_new(NAMESPACE).expect("the namespace's name is static")
}

/// The path to `below` inside `volume`'s entry; the entry itself when
/// `below` is empty.
pub fn entry_path<'a>(
    volume: &'a VolumeName,
    below: impl IntoIterator<Item = &'a str>,
) -> SubkeyPath {
    SubkeyPath::try_new(
        std::iter::once(volume.as_str())
            .chain(below)
            .map(|key| Subkey::Key(key.to_owned()))
            .collect(),
    )
    .expect("the volume's name is a segment")
}

/// Which filer the ledger gives a volume to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// No filer is named.
    Unclaimed,
    /// The filer at this address.
    Endpoint(EndpointAddr),
    /// Something is written where the filer is named, and it does not
    /// read as an address. Holds why, for an operator.
    Unreadable(String),
}

impl Claim {
    /// Whether the volume is given to the filer with endpoint id `id`.
    pub fn is(&self, id: EndpointId) -> bool {
        matches!(self, Claim::Endpoint(addr) if addr.id == id)
    }
}

/// What one client may do on a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub mode: Mode,
    /// The name the ledger lists the client under, for logs. The first,
    /// where it is listed under several.
    pub name: String,
}

/// Who may connect to a volume, by the endpoint id iroh authenticates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList(BTreeMap<EndpointId, Grant>);

impl AllowList {
    /// What `client` may do, or `None` when it is not listed.
    pub fn grant(&self, client: EndpointId) -> Option<&Grant> {
        self.0.get(&client)
    }

    /// Reads the `allowed_clients` map.
    ///
    /// An entry that does not read grants nothing, and a client listed
    /// under several names gets the least any of them grants: both err
    /// towards refusing.
    fn parse(volume: &str, value: Option<&Value>) -> Self {
        let Some(Value::Map(clients)) = value else {
            return Self::default();
        };
        Self(clients.iter().fold(
            BTreeMap::new(),
            |mut allowed: BTreeMap<EndpointId, Grant>, (name, client)| {
                match parse_client(client) {
                    Some((id, mode)) => {
                        allowed
                            .entry(id)
                            .and_modify(|grant| grant.mode = grant.mode.min(mode))
                            .or_insert_with(|| Grant {
                                mode,
                                name: name.clone(),
                            });
                    }
                    None => {
                        tracing::warn!(volume, client = %name, "ignoring an allowed client that does not read");
                    }
                }
                allowed
            },
        ))
    }
}

fn parse_client(client: &Value) -> Option<(EndpointId, Mode)> {
    let Value::Map(fields) = client else {
        return None;
    };
    let id = match fields.get(ENDPOINT_ID) {
        Some(Value::String(id)) => EndpointId::from_z32(id).ok()?,
        _ => return None,
    };
    let mode = match fields.get(MODE) {
        Some(Value::String(mode)) if mode == READ_ONLY => Mode::ReadOnly,
        Some(Value::String(mode)) if mode == READ_WRITE => Mode::ReadWrite,
        _ => return None,
    };
    Some((id, mode))
}

/// What the ledger says about one volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub claim: Claim,
    pub allowed: AllowList,
}

impl Entry {
    /// Reads `volume`'s entry out of the `filers` namespace's value;
    /// `None` when the namespace does not list it.
    pub fn find(namespace: Option<&Value>, volume: &VolumeName) -> Option<Self> {
        match namespace {
            Some(Value::Map(volumes)) => volumes
                .get(volume.as_str())
                .map(|entry| Self::parse(volume.as_str(), entry)),
            _ => None,
        }
    }

    fn parse(volume: &str, entry: &Value) -> Self {
        let Value::Map(fields) = entry else {
            return Self {
                claim: Claim::Unreadable("the entry is not a map".to_owned()),
                allowed: AllowList::default(),
            };
        };
        Self {
            claim: match fields.get(ENDPOINT) {
                None => Claim::Unclaimed,
                Some(endpoint) => EndpointAddr::try_from(endpoint)
                    .map_or_else(|err| Claim::Unreadable(err.to_string()), Claim::Endpoint),
            },
            allowed: AllowList::parse(volume, fields.get(ALLOWED_CLIENTS)),
        }
    }
}

/// The schema the `filers` namespace is held to, as `_lotus_schema` spells
/// one.
pub fn schema() -> Value {
    fn described(kind: &str, description: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("type".to_owned(), Value::from(kind)),
            ("description".to_owned(), Value::from(description)),
        ])
    }
    fn with(
        mut schema: BTreeMap<String, Value>,
        keywords: impl IntoIterator<Item = (&'static str, Value)>,
    ) -> Value {
        schema.extend(
            keywords
                .into_iter()
                .map(|(keyword, value)| (keyword.to_owned(), value)),
        );
        Value::Map(schema)
    }
    fn strukt(
        description: &str,
        fields: impl IntoIterator<Item = (&'static str, Value)>,
        required: &[&str],
    ) -> Value {
        with(
            described("struct", description),
            [
                ("fields", fields.into_iter().collect()),
                ("required", required.iter().copied().collect()),
            ],
        )
    }
    let string = |description| Value::Map(described("string", description));

    let transport = strukt(
        "One way to reach the endpoint.",
        [
            ("type", string("The transport: relay, ip or custom.")),
            ("addr", string("The address on that transport.")),
        ],
        &["type", "addr"],
    );
    let endpoint = strukt(
        "The filer serving the volume. Written by filerd when it claims the volume; \
         clear it to let another filer claim.",
        [
            (ENDPOINT_ID, string("The filer's iroh endpoint id.")),
            (
                ADDRS,
                with(
                    described("array", "Where the filer is reachable, kept by filerd."),
                    [("items", transport)],
                ),
            ),
        ],
        &[ENDPOINT_ID, ADDRS],
    );
    let client = strukt(
        "A client permitted to connect.",
        [
            (ENDPOINT_ID, string("The client's iroh endpoint id.")),
            (
                MODE,
                with(
                    described("string", "ro to read, rw to read and write."),
                    [("enum", [READ_ONLY, READ_WRITE].into_iter().collect())],
                ),
            ),
        ],
        &[ENDPOINT_ID, MODE],
    );
    let volume = strukt(
        "A volume a filer serves.",
        [
            (ENDPOINT, endpoint),
            (
                ALLOWED_CLIENTS,
                with(
                    described(
                        "map",
                        "Who may connect, under a name of the operator's choosing.",
                    ),
                    [("values", client)],
                ),
            ),
        ],
        &[],
    );
    with(
        described("map", "Volumes served by filerd, by name."),
        [("values", volume)],
    )
}

#[cfg(test)]
mod tests {
    use lotus_sdk::Schema;

    use super::*;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn volume(name: &str) -> VolumeName {
        VolumeName::try_new(name).unwrap()
    }

    fn client(id: EndpointId, mode: &str) -> Value {
        Value::from_iter([(ENDPOINT_ID, id.to_z32()), (MODE, mode.to_owned())])
    }

    fn clients(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
        entries.into_iter().collect()
    }

    fn namespace_of(entry: Value) -> Value {
        Value::from_iter([("scratch", entry)])
    }

    #[test]
    fn the_schema_parses() {
        Schema::parse(&schema()).unwrap();
    }

    #[test]
    fn the_schema_admits_what_filerd_and_an_operator_write() {
        let addr = EndpointAddr::from_parts(
            id(1),
            [iroh::TransportAddr::Ip("192.0.2.1:4433".parse().unwrap())],
        );
        let entry = Value::Map(BTreeMap::from([
            (ENDPOINT.to_owned(), Value::try_from(&addr).unwrap()),
            (
                ALLOWED_CLIENTS.to_owned(),
                clients([("laptop", client(id(2), "rw"))]),
            ),
        ]));

        Schema::parse(&schema())
            .unwrap()
            .check(&namespace_of(entry))
            .unwrap();
    }

    #[test]
    fn the_schema_refuses_an_unknown_mode() {
        let entry = Value::from_iter([(
            ALLOWED_CLIENTS,
            clients([("laptop", client(id(2), "admin"))]),
        )]);

        assert!(
            Schema::parse(&schema())
                .unwrap()
                .check(&namespace_of(entry))
                .is_err()
        );
    }

    #[test]
    fn an_unlisted_volume_has_no_entry() {
        assert_eq!(Entry::find(None, &volume("scratch")), None);
        assert_eq!(
            Entry::find(
                Some(&namespace_of(Value::Map(BTreeMap::new()))),
                &volume("other")
            ),
            None
        );
    }

    #[test]
    fn an_entry_reads_its_claim_and_clients() {
        let addr = EndpointAddr::new(id(1));
        let entry = Value::Map(BTreeMap::from([
            (ENDPOINT.to_owned(), Value::try_from(&addr).unwrap()),
            (
                ALLOWED_CLIENTS.to_owned(),
                clients([("laptop", client(id(2), "rw")), ("ci", client(id(3), "ro"))]),
            ),
        ]));

        let entry = Entry::find(Some(&namespace_of(entry)), &volume("scratch")).unwrap();
        assert!(entry.claim.is(id(1)));
        assert!(!entry.claim.is(id(2)));
        assert_eq!(entry.allowed.grant(id(2)).unwrap().mode, Mode::ReadWrite);
        assert_eq!(entry.allowed.grant(id(3)).unwrap().mode, Mode::ReadOnly);
        assert_eq!(entry.allowed.grant(id(4)), None);
    }

    #[test]
    fn an_entry_without_an_endpoint_is_unclaimed() {
        let entry = Value::from_iter([(ALLOWED_CLIENTS, clients([]))]);
        let entry = Entry::find(Some(&namespace_of(entry)), &volume("scratch")).unwrap();
        assert_eq!(entry.claim, Claim::Unclaimed);
    }

    #[test]
    fn an_endpoint_that_does_not_read_is_nobodys() {
        let entry = Value::from_iter([(ENDPOINT, "over there")]);
        let entry = Entry::find(Some(&namespace_of(entry)), &volume("scratch")).unwrap();
        assert!(matches!(entry.claim, Claim::Unreadable(_)));
        assert!(!entry.claim.is(id(1)));
    }

    #[test]
    fn a_client_listed_twice_gets_the_lesser_grant() {
        let entry = Value::from_iter([(
            ALLOWED_CLIENTS,
            clients([("a", client(id(2), "rw")), ("b", client(id(2), "ro"))]),
        )]);
        let entry = Entry::find(Some(&namespace_of(entry)), &volume("scratch")).unwrap();
        assert_eq!(entry.allowed.grant(id(2)).unwrap().mode, Mode::ReadOnly);
    }

    #[test]
    fn a_client_that_does_not_read_is_not_allowed() {
        let entry = Value::from_iter([(
            ALLOWED_CLIENTS,
            clients([
                (
                    "bad-id",
                    Value::from_iter([(ENDPOINT_ID, "nope"), (MODE, "rw")]),
                ),
                ("bad-mode", client(id(3), "admin")),
                ("good", client(id(4), "ro")),
            ]),
        )]);
        let entry = Entry::find(Some(&namespace_of(entry)), &volume("scratch")).unwrap();
        assert_eq!(entry.allowed.grant(id(3)), None);
        assert_eq!(entry.allowed.grant(id(4)).unwrap().mode, Mode::ReadOnly);
    }
}
