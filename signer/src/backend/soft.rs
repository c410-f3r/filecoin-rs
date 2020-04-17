use crate::{
    api::SignedMessageAPI, UnsignedMessageAPI,
    error::SignerError, PrivateKey, Signature,
    backend::Backend, Message, CborBuffer, api::SignatureAPI,
    utils::self
};
use core::convert::TryFrom;
use forest_encoding::to_vec;
use secp256k1::sign;

pub struct Soft;

impl Backend for Soft {
    fn transaction_sign_raw(
        unsigned_message_api: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<Signature, SignerError> {
        let message = forest_message::UnsignedMessage::try_from(unsigned_message_api)?;
        let message_cbor = CborBuffer(to_vec(&message)?);
    
        let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;
    
        let cid_hashed = utils::get_digest(&message_cbor.0);
    
        let message_digest = Message::parse_slice(&cid_hashed)?;
    
        let (signature_rs, recovery_id) = sign(&message_digest, &secret_key);
    
        let mut signature = Signature { 0: [0; 65] };
        signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
        signature.0[64] = recovery_id.serialize();
    
        Ok(signature)
    }
    
    /// Sign a transaction and return a signed message (message + signature).
    ///
    /// # Arguments
    ///
    /// * `unsigned_message_api` - an unsigned filecoin message
    /// * `private_key` - a `PrivateKey`
    ///
    fn transaction_sign(
        unsigned_message: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<SignedMessageAPI, SignerError> {
        let message = forest_message::UnsignedMessage::try_from(unsigned_message)?;
        let message_cbor = CborBuffer(to_vec(&message)?);
    
        let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;
    
        let cid_hashed = utils::get_digest(&message_cbor.0);
    
        let message_digest = Message::parse_slice(&cid_hashed)?;
    
        let (signature_rs, recovery_id) = sign(&message_digest, &secret_key);
    
        let mut signature = Signature { 0: [0; 65] };
        signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
        signature.0[64] = recovery_id.serialize();
    
        let signed_message = SignedMessageAPI {
            message: unsigned_message.to_owned(),
            signature: SignatureAPI::from(&signature),
        };
    
        Ok(signed_message)
    }    
}