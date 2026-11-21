//! Password hashes, as written under a namespace's `auth.users` map.

use argon2::{Argon2, PasswordHasher};

use crate::Error;

/// The key a user's password hash is held under, inside their entry.
pub const PASSWORD_KEY: &str = "password";

/// The argon2id hash of `password` at the default cost, with a fresh salt,
/// as a PHC string. Off the async runtime: a hash takes tens of
/// milliseconds of CPU by design.
pub async fn hash(password: String) -> Result<String, Error> {
    if password.is_empty() {
        return Err(Error::Invalid("a password cannot be empty".into()));
    }
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hashed| hashed.to_string())
            .map_err(Error::Hash)
    })
    .await
    .expect("a blocking task is only cancelled at runtime shutdown, and hashing does not panic")
}

#[cfg(test)]
mod tests {
    use argon2::{PasswordHash, PasswordVerifier};

    use super::*;

    #[tokio::test]
    async fn the_hash_is_argon2id_and_verifies_the_password() {
        let hashed = hash("hunter2".into()).await.unwrap();
        assert!(hashed.starts_with("$argon2id$"), "{hashed}");

        let parsed = PasswordHash::new(&hashed).unwrap();
        let argon2 = Argon2::default();
        argon2.verify_password(b"hunter2", &parsed).unwrap();
        assert!(argon2.verify_password(b"hunter3", &parsed).is_err());
    }

    #[tokio::test]
    async fn each_hash_is_salted_afresh() {
        assert_ne!(
            hash("same".into()).await.unwrap(),
            hash("same".into()).await.unwrap()
        );
    }

    #[tokio::test]
    async fn an_empty_password_is_refused() {
        assert!(matches!(hash(String::new()).await, Err(Error::Invalid(_))));
    }
}
