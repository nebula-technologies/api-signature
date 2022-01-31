use crate::error::Error;
use hmac::Mac;
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub fn sha256(value: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().as_slice().to_vec()
}

pub fn sha512(value: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(value);
    hasher.finalize().as_slice().to_vec()
}

pub fn hmac_sha512(enc_key: &Vec<u8>, value: &Vec<u8>) -> Vec<u8> {
    let mut mac =
        HmacSha512::new_from_slice(enc_key.as_slice()).expect("HMAC can take key of any size");
    mac.update(value.as_slice());
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac_sha256(enc_key: &Vec<u8>, value: &Vec<u8>) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(enc_key.as_slice()).expect("HMAC can take key of any size");
    mac.update(value.as_slice());
    mac.finalize().into_bytes().to_vec()
}

pub fn base64decode(value: &Vec<u8>) -> Vec<u8> {
    base64::decode(value)
        .map_err(Error::from)
        .unwrap_or(Vec::new())
}
pub fn base64encode(value: &Vec<u8>) -> Vec<u8> {
    base64::encode(value).as_bytes().to_vec()
}

pub fn base58decode(value: &Vec<u8>) -> Vec<u8> {
    bs58::decode(value)
        .into_vec()
        .map_err(Error::from)
        .unwrap_or(Vec::new())
}
pub fn base58encode(value: &Vec<u8>) -> Vec<u8> {
    bs58::encode(value).into_string().as_bytes().to_vec()
}
