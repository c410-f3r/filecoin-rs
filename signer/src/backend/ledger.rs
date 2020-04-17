mod params;

use core::str;
use ledger::{ApduAnswer, ApduCommand};
use self::{
    params::{APDUErrors, PayloadType}
};
use params::{
    CLA, INS_GET_ADDR_SECP256K1, INS_GET_VERSION, INS_SIGN_SECP256K1, USER_MESSAGE_CHUNK_SIZE,
};
use crate::backend::Backend;

/// Public Key Length
const PK_LEN: usize = 65;

pub struct Ledger {
    app: ledger::LedgerApp,
}

impl Ledger {
    fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(Self { app })
    }

    fn version(&self) -> Result<Version, Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;
        if response.retcode != APDUErrors::NoError as u16 {
            return Err(Error::InvalidVersion);
        }

        if response.data.len() < 4 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Ok(version)
    }

    /// Retrieves the public key and address
    fn address(&self, path: &BIP44Path, require_confirmation: bool) -> Result<Address, Error> {
        let serialized_path = serialize_bip44(path);
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_ADDR_SECP256K1,
            p1,
            p2: 0x00,
            length: 0,
            data: serialized_path,
        };

        match self.app.exchange(command) {
            Ok(response) => {
                if response.retcode != APDUErrors::NoError as u16 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() < PK_LEN {
                    return Err(Error::InvalidPK);
                }

                let public_key = secp256k1::PublicKey::from_slice(&response.data[..PK_LEN])?;
                let mut addr_byte = [Default::default(); 21];
                addr_byte.copy_from_slice(&response.data[PK_LEN + 1..PK_LEN + 1 + 21]);
                let tmp = str::from_utf8(&response.data[PK_LEN + 2 + 21..])?;
                let addr_string = tmp.to_owned();

                let address = Address {
                    public_key,
                    addr_byte,
                    addr_string,
                };
                Ok(address)
            }
            Err(err) => Err(Error::Ledger(err)),
        }
    }

    /// Sign a transaction
    fn sign(&self, path: &BIP44Path, message: &[u8]) -> Result<Signature, Error> {
        let bip44path = serialize_bip44(&path);
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;
        let mut response: ApduAnswer;

        let _command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_SECP256K1,
            p1: PayloadType::Init as u8,
            p2: 0x00,
            length: bip44path.len() as u8,
            data: bip44path,
        };

        response = self.app.exchange(_command)?;

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let mut p1 = PayloadType::Add as u8;
            if packet_idx == (packet_count - 1) as usize {
                p1 = PayloadType::Last as u8
            }

            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_SECP256K1,
                p1,
                p2: 0,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.is_empty() && response.retcode == APDUErrors::NoError as u16 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() < 3 {
            return Err(Error::InvalidSignature);
        }

        //let sig_buffer_len = response.data.len();

        let mut r = [Default::default(); 32];
        r.copy_from_slice(&response.data[..32]);

        let mut s = [Default::default(); 32];
        s.copy_from_slice(&response.data[32..64]);

        let v = response.data[64];

        let sig = secp256k1::Signature::from_der(&response.data[65..])?;

        let signature = Signature { r, s, v, sig };

        Ok(signature)
    }
}

impl Backend for Ledger {
    fn transaction_sign(
        unsigned_message: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<SignedMessageAPI, SignerError> {
        todo!()
    }

    fn transaction_sign_raw(
        unsigned_message_api: &UnsignedMessageAPI,
        private_key: &PrivateKey,
    ) -> Result<Signature, SignerError> {
        todo!()
    }
}

pub struct Address {
    /// Public Key
    pub public_key: secp256k1::PublicKey,

    /// Address byte format
    pub addr_byte: [u8; 21],

    /// Address string format
    pub addr_string: String,
}

/// FilecoinApp signature (includes R, S, V and der format)
pub struct Signature {
    /// r value
    pub r: [u8; 32],

    /// s value
    pub s: [u8; 32],

    /// v value
    pub v: u8,

    /// der signature
    pub sig: secp256k1::Signature,
}

/// FilecoinApp App Version
pub struct Version {
    /// Application Mode
    pub mode: u8,
    /// Version Major
    pub major: u8,
    /// Version Minor
    pub minor: u8,
    /// Version Patch
    pub patch: u8,
}

/// BIP44 Path
pub struct BIP44Path {
    /// Purpose
    pub purpose: u32,
    /// Coin
    pub coin: u32,
    /// Account
    pub account: u32,
    /// Change
    pub change: u32,
    /// Address Index
    pub index: u32,
}