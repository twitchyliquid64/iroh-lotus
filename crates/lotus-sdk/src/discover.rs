//! Where a daemon on this machine keeps its control socket.

use std::path::{Path, PathBuf};

/// The environment variable `lotusd` and `lotusctl` take the state
/// directory from, ahead of the platform default.
pub const STATE_DIR_ENV: &str = "LOTUS_STATE_DIR";

/// The control socket's name inside the state directory.
pub const SOCKET_NAME: &str = "local.sock";

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
    fn the_socket_sits_in_the_state_directory() {
        assert_eq!(
            socket_in(Path::new("/srv/lotus")),
            PathBuf::from("/srv/lotus/local.sock")
        );
    }
}
