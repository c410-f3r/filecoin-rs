pub const CLA: u8 = 0x06;
pub const INS_GET_VERSION: u8 = 0x00;
pub const INS_GET_ADDR_SECP256K1: u8 = 0x01;
pub const INS_SIGN_SECP256K1: u8 = 0x02;
pub const USER_MESSAGE_CHUNK_SIZE: usize = 250;

pub enum PayloadType {
    Init = 0x00,
    Add = 0x01,
    Last = 0x02,
}

pub enum APDUErrors {
    NoError = 0x9000,
}