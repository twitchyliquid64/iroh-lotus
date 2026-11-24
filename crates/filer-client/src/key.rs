//! The secret key an iroh endpoint is identified by, kept in a file.
//!
//! A filer and each of its clients has one of its own: the endpoint id it
//! gives is what the ledger lists a volume under, and what it permits a
//! client by.

use std::{
    io,
    path::{Path, PathBuf},
};

use iroh::SecretKey;
use rand::{TryRng, rngs::SysRng};
use tokio::{fs, io::AsyncWriteExt};

/// Why the key could not be loaded or created.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{what} {}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} holds {len} bytes, not a 32-byte key", path.display())]
    Length { path: PathBuf, len: usize },
    #[error("drawing a key from the system's entropy")]
    Entropy(#[source] rand::rngs::SysError),
}

/// Loads the key in the file at `path`, drawing and saving one where there
/// is none yet.
pub async fn load_or_create(path: &Path) -> Result<SecretKey, KeyError> {
    let path = path.to_path_buf();
    let io = |what| {
        let path = path.clone();
        move |source| KeyError::Io { what, path, source }
    };
    match fs::read(&path).await {
        Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
            .map(|secret| SecretKey::from_bytes(&secret))
            .map_err(|_| KeyError::Length {
                path,
                len: bytes.len(),
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).await.map_err(io("creating"))?;
            }
            let mut secret = [0u8; 32];
            SysRng
                .try_fill_bytes(&mut secret)
                .map_err(KeyError::Entropy)?;

            let mut options = fs::OpenOptions::new();
            // `create_new`: a key that appeared since the read is another
            // filer's, and must not be written over.
            options.write(true).create_new(true);
            // Created 0600 rather than relaxed-then-tightened: a secret key
            // must never exist group- or world-readable.
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&path).await.map_err(io("creating"))?;
            file.write_all(&secret).await.map_err(io("saving"))?;
            // A dropped `File` does not wait for its queued write.
            file.sync_all().await.map_err(io("saving"))?;
            Ok(SecretKey::from_bytes(&secret))
        }
        Err(e) => Err(io("reading")(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_key_is_created_once_and_kept() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("state/secret");

        let first = load_or_create(&path).await.unwrap();
        let second = load_or_create(&path).await.unwrap();
        assert_eq!(first.public(), second.public());
    }

    #[tokio::test]
    async fn a_file_that_is_not_a_key_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"short").unwrap();

        assert!(matches!(
            load_or_create(&path).await,
            Err(KeyError::Length { len: 5, .. })
        ));
    }
}
