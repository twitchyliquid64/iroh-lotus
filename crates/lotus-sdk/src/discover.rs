//! Where a daemon on this machine keeps its control socket.

use std::path::{Path, PathBuf};

/// The environment variable `lotusd` and `lotusctl` take the state
/// directory from, ahead of the platform default.
pub const STATE_DIR_ENV: &str = "LOTUS_STATE_DIR";

/// The control socket's name inside the state directory.
pub const SOCKET_NAME: &str = "local.sock";

/// The state directory of a daemon installed for the whole machine: where
/// the shipped systemd unit (`StateDirectory=lotus`) and the container
/// image keep it. A client falls back to it when the user runs no daemon
/// of their own — see [`find_state_dir`].
pub const SYSTEM_STATE_DIR: &str = "/var/lib/lotus";

/// StateDir returns the directory a daemon on this machine keeps its state
/// in, as `lotusd` resolves it: `$LOTUS_STATE_DIR` when set, otherwise
/// `iroh-lotus` under the platform state directory (`$XDG_STATE_HOME`,
/// falling back to `~/.local/state`, on Linux). `None` only when no home
/// directory can be determined.
pub fn state_dir() -> Option<PathBuf> {
    state_dir_from(std::env::var_os(STATE_DIR_ENV).map(PathBuf::from))
}

/// The resolution behind [`state_dir`], with the environment read out.
fn state_dir_from(overridden: Option<PathBuf>) -> Option<PathBuf> {
    overridden.or_else(|| {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .map(|dir| dir.join("iroh-lotus"))
    })
}

/// FindStateDir returns the state directory of the daemon a client on
/// this machine should talk to. `$LOTUS_STATE_DIR` is taken as given when
/// set. Otherwise the first of the user's own directory ([`state_dir`])
/// and the machine's ([`SYSTEM_STATE_DIR`]) that exists, so an operator in
/// the daemon's group reaches a system daemon with no configuration while
/// a daemon of their own still wins; when neither exists, the user's, so
/// the connection error names where `lotusd` would have put one.
///
/// Only the directory is looked for, not the socket: the directory of a
/// system daemon is visible to everyone, and a user outside its group
/// then fails at the socket with the permission error that explains it.
/// A daemon that is not running in the directory fails at connect.
///
/// For clients only. `lotusd` itself resolves with [`state_dir`], so a
/// user's `lotusd init` never lands in the machine's directory.
pub fn find_state_dir() -> Option<PathBuf> {
    find_state_dir_among(
        std::env::var_os(STATE_DIR_ENV).map(PathBuf::from),
        state_dir_from(None),
        Path::new(SYSTEM_STATE_DIR),
    )
}

/// The resolution behind [`find_state_dir`], with the environment read out
/// and the candidates named: `overridden` as given, else the first of `user`
/// and `system` that is a directory, else `user`.
fn find_state_dir_among(
    overridden: Option<PathBuf>,
    user: Option<PathBuf>,
    system: &Path,
) -> Option<PathBuf> {
    overridden.or_else(|| {
        user.iter()
            .map(PathBuf::as_path)
            .chain(std::iter::once(system))
            .find(|dir| dir.is_dir())
            .map(Path::to_path_buf)
            .or(user)
    })
}

/// SocketIn returns the control socket inside `state_dir`.
pub fn socket_in(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_taken_as_given() {
        let dir = PathBuf::from("/srv/lotus");
        assert_eq!(state_dir_from(Some(dir.clone())), Some(dir));
    }

    #[test]
    fn the_default_is_under_the_platform_state_directory() {
        let dir = state_dir_from(None).expect("a home directory in the test environment");
        assert_eq!(dir.file_name().and_then(|n| n.to_str()), Some("iroh-lotus"));
        assert!(dir.is_absolute());
    }

    #[test]
    fn a_client_override_is_taken_as_given_even_when_absent() {
        let root = tempfile::tempdir().unwrap();
        let system = root.path().join("system");
        std::fs::create_dir(&system).unwrap();
        let overridden = root.path().join("nowhere");
        assert_eq!(
            find_state_dir_among(Some(overridden.clone()), None, &system),
            Some(overridden)
        );
    }

    #[test]
    fn a_users_own_daemon_wins_over_the_systems() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("user");
        let system = root.path().join("system");
        std::fs::create_dir(&user).unwrap();
        std::fs::create_dir(&system).unwrap();
        assert_eq!(
            find_state_dir_among(None, Some(user.clone()), &system),
            Some(user)
        );
    }

    #[test]
    fn the_system_daemon_is_found_when_the_user_has_none() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("user");
        let system = root.path().join("system");
        std::fs::create_dir(&system).unwrap();
        assert_eq!(
            find_state_dir_among(None, Some(user), &system),
            Some(system.clone())
        );
        assert_eq!(find_state_dir_among(None, None, &system), Some(system));
        assert_eq!(
            find_state_dir_among(None, None, &root.path().join("missing")),
            None
        );
    }

    #[test]
    fn with_no_daemon_anywhere_the_users_directory_is_named() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("user");
        let system = root.path().join("system");
        assert_eq!(
            find_state_dir_among(None, Some(user.clone()), &system),
            Some(user)
        );
    }

    #[test]
    fn the_socket_sits_in_the_state_directory() {
        assert_eq!(
            socket_in(Path::new("/srv/lotus")),
            PathBuf::from("/srv/lotus/local.sock")
        );
    }
}
