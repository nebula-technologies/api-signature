use crate::error::Error;

pub fn sha256(value: &Vec<u8>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(value);
    hasher.finalize().as_slice().to_vec()
}

pub fn sha512(value: &Vec<u8>) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(value);
    hasher.finalize().as_slice().to_vec()
}

pub fn hmac_sha512(enc_key: &Vec<u8>, value: Vec<u8>) -> Vec<u8> {
    type hmac_sha512 = hmac::Hmac<sha2::Sha512>;
    let mut mac =
        hmac_sha512::new_from_slice(enc_key.as_slice()).expect("HMAC can take key of any size");
    mac.update(&value);
    mac.finalize().into_bytes().to_vec()
}

pub fn base64decode(value: &Vec<u8>) -> Result<Vec<u8>> {
    base64::decode(value).map_err(Error::from)
}
pub fn base64encode(value: &Vec<u8>) -> Result<Vec<u8>> {
    base64::encode(value).map_err(Error::from)
}
