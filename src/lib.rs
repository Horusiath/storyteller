pub mod patch;
pub mod peer;
pub mod store;

pub type PeerID = [u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("patch verification failed: {0}")]
    VerificationFailed(#[from] ed25519_dalek::SignatureError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
