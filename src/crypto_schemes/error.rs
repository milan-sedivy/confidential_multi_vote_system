#[derive(Debug)]
pub enum CryptoError {
    MissingComponents,
    MissingPublicKey,
    MissingPrivateKey,
    MessageOutOfBounds,
}