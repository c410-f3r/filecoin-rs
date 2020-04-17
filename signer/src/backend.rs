mod ledger;
mod soft;

use crate::{
    api::SignedMessageAPI, UnsignedMessageAPI,
    error::SignerError, PrivateKey, Signature
};

pub trait Backend {
    /// Sign a transaction and return a raw signature (RSV format).
    ///
    /// # Arguments
    ///
    /// * `unsigned_message_api` - an unsigned filecoin message
    /// * `private_key` - a `PrivateKey`
    fn transaction_sign(
        unsigned_message: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<SignedMessageAPI, SignerError>;

    /// Sign a transaction and return a signed message (message + signature).
    ///
    /// # Arguments
    ///
    /// * `unsigned_message_api` - an unsigned filecoin message
    /// * `private_key` - a `PrivateKey`
    fn transaction_sign_raw(
        unsigned_message_api: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<Signature, SignerError>;
}