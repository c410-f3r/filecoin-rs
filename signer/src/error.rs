use crate::utils::HexDecodeError;
use hmac::crypto_mac::InvalidKeyLength;
use std::num::ParseIntError;
use thiserror::Error;

/// Filecoin Signer Error
#[derive(Error, Debug)]
pub enum SignerError {
    ///  CBOR error
    #[error("CBOR error")]
    CBOR(#[from] serde_cbor::Error),
    /// Secp256k1 error
    #[error("secp256k1 error")]
    Secp256k1(#[from] secp256k1::Error),
    /// Hex error
    #[error("Hex error")]
    Hex(#[from] hex::FromHexError),
    /// Cannot parse hexstring
    #[error("Cannot parse hexstring")]
    HexDecodeError(#[from] HexDecodeError),
    /// InvalidBigInt error
    #[error("InvalidBigInt error")]
    InvalidBigInt(#[from] num_bigint_chainsafe::ParseBigIntError),
    /// Generic error message
    #[error("Error: `{0}`")]
    GenericString(String),
    /// Not able to parse integer
    #[error("Cannot parse integer")]
    ParseIntError(#[from] ParseIntError),
}

// We need to use from because InvalidKeyLength does not implement as_dyn_err
impl From<InvalidKeyLength> for SignerError {
    fn from(err: InvalidKeyLength) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}
