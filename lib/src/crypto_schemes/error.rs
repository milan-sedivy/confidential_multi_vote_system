#[derive(Debug)]
#[allow(dead_code)]
pub enum CryptoError {
    MissingComponents,
    MissingPublicKey,
    MissingPrivateKey,
    MessageOutOfBounds,
}