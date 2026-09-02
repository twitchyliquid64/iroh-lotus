//! Where in the ledger a request points, and how that is spelled in a URL.

use core::fmt;

use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use lotus_sdk::{NamespaceKey, Subkey, SubkeyPath};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use crate::Error;

/// Where the URL begins for every ledger location.
const PREFIX: &str = "/ns/";

/// What is escaped in a URL segment: what can't sit in a path unencoded,
/// plus the brackets and quotes a path spells indices and odd keys with,
/// so a path reads the same in a link and on the command line.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// A namespace, and optionally a path inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    key: NamespaceKey,
    path: Option<SubkeyPath>,
}

impl Location {
    /// The value `path` addresses in `key`; the namespace itself for `None`.
    pub fn new(key: NamespaceKey, path: Option<SubkeyPath>) -> Self {
        Self { key, path }
    }

    /// The root of `key`.
    pub fn namespace(key: NamespaceKey) -> Self {
        Self::new(key, None)
    }

    pub fn key(&self) -> &NamespaceKey {
        &self.key
    }

    pub fn path(&self) -> Option<&SubkeyPath> {
        self.path.as_ref()
    }

    /// Whether this is the namespace itself rather than something inside.
    pub fn is_root(&self) -> bool {
        self.path.is_none()
    }

    fn segments(&self) -> &[Subkey] {
        self.path.as_ref().map_or(&[], |path| path.as_ref())
    }

    /// The URL this location is browsed at.
    pub fn url(&self) -> String {
        let key = utf8_percent_encode(self.key.as_ref(), SEGMENT);
        match &self.path {
            None => format!("{PREFIX}{key}"),
            Some(path) => {
                let path = path.to_string();
                let path = utf8_percent_encode(&path, SEGMENT);
                format!("{PREFIX}{key}/{path}")
            }
        }
    }

    /// One level down, at `subkey`.
    pub fn child(&self, subkey: Subkey) -> Self {
        let segments = self.segments().iter().cloned().chain([subkey]).collect();
        Self::new(self.key.clone(), Some(nonempty(segments)))
    }

    /// One level up; `None` at a namespace's root, where up is the whole
    /// ledger.
    pub fn parent(&self) -> Option<Self> {
        let segments = self.segments();
        match segments.split_last() {
            None => None,
            Some((_, [])) => Some(Self::namespace(self.key.clone())),
            Some((_, rest)) => Some(Self::new(self.key.clone(), Some(nonempty(rest.to_vec())))),
        }
    }

    /// The way here: the namespace, then one location per segment, ending
    /// on this one.
    pub fn crumbs(&self) -> impl Iterator<Item = Location> + '_ {
        let root = Self::namespace(self.key.clone());
        let inner = (1..=self.segments().len()).map(move |len| {
            Self::new(
                self.key.clone(),
                Some(nonempty(self.segments()[..len].to_vec())),
            )
        });
        std::iter::once(root).chain(inner)
    }

    /// The last step here, as a crumb reads: the final segment, or the
    /// namespace at its root.
    pub fn name(&self) -> String {
        self.segments()
            .last()
            .map_or_else(|| self.key.to_string(), ToString::to_string)
    }
}

/// A path from segments known to hold at least one.
fn nonempty(segments: Vec<Subkey>) -> SubkeyPath {
    SubkeyPath::try_new(segments).expect("built from at least one segment")
}

impl fmt::Display for Location {
    /// The namespace, then the path as `lotusctl` writes one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            None => write!(f, "{}", self.key),
            Some(path) => write!(f, "{} › {path}", self.key),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Location {
    type Rejection = Error;

    /// Read from the `{key}` and optional `{*path}` route captures.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(captures) = Path::<Vec<(String, String)>>::from_request_parts(parts, state)
            .await
            .map_err(|e| Error::BadRequest(e.body_text()))?;
        let capture = |name| {
            captures
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, value)| value.as_str())
        };

        let key = capture("key")
            .ok_or_else(|| Error::BadRequest("the route names no namespace".into()))
            .and_then(|key| {
                NamespaceKey::try_new(key)
                    .map_err(|e| Error::BadRequest(format!("`{key}` is not a namespace: {e}")))
            })?;
        let path = capture("path")
            .map(|path| {
                path.parse()
                    .map_err(|e| Error::BadRequest(format!("`{path}` is not a path: {e}")))
            })
            .transpose()?;
        Ok(Self::new(key, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(key: &str, path: &str) -> Location {
        Location::new(
            NamespaceKey::try_new(key).unwrap(),
            Some(path.parse().unwrap()),
        )
    }

    fn root(key: &str) -> Location {
        Location::namespace(NamespaceKey::try_new(key).unwrap())
    }

    #[test]
    fn the_url_spells_the_path_as_the_cli_does() {
        assert_eq!(root("cfg").url(), "/ns/cfg");
        assert_eq!(
            at("cfg", "servers[0].host").url(),
            "/ns/cfg/servers%5B0%5D.host"
        );
        assert_eq!(at("cfg", "['a.b']").url(), "/ns/cfg/%5B%27a.b%27%5D");
        assert_eq!(at("cfg", "a b").url(), "/ns/cfg/a%20b");
        assert_eq!(root("a/b").url(), "/ns/a%2Fb");
    }

    #[test]
    fn a_child_extends_the_path_and_a_parent_shortens_it() {
        let servers = root("cfg").child(Subkey::Key("servers".into()));
        assert_eq!(servers, at("cfg", "servers"));
        assert_eq!(servers.child(Subkey::Index(0)), at("cfg", "servers[0]"));

        assert_eq!(at("cfg", "servers[0]").parent(), Some(at("cfg", "servers")));
        assert_eq!(at("cfg", "servers").parent(), Some(root("cfg")));
        assert_eq!(root("cfg").parent(), None);
    }

    #[test]
    fn crumbs_walk_from_the_namespace_to_here() {
        let crumbs: Vec<_> = at("cfg", "servers[0].host").crumbs().collect();
        assert_eq!(
            crumbs,
            [
                root("cfg"),
                at("cfg", "servers"),
                at("cfg", "servers[0]"),
                at("cfg", "servers[0].host"),
            ]
        );
        assert_eq!(root("cfg").crumbs().collect::<Vec<_>>(), [root("cfg")]);
    }

    #[test]
    fn the_name_is_the_last_step() {
        assert_eq!(root("cfg").name(), "cfg");
        assert_eq!(at("cfg", "servers[0]").name(), "[0]");
        assert_eq!(at("cfg", "servers[0].host").name(), "host");
    }
}
