pub fn api_sign<T: GetNonce + FormEncodable>(
    urlpath: &str,
    post_data: T,
    private_key: &str,
) -> Result<String> {
    base64decode(private_key).map(|secret| {
        let mut hmac_value = urlpath.as_bytes().to_vec();

        hmac_value.append(&mut sha256(&(post_data.get_nonce() + &post_data.encoded())));
        base64::encode(hmac_sha512(secret, hmac_value))
    })
}

pub fn sha256(value: &str) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(value);
    hasher.finalize().as_slice().to_vec()
}

pub fn hmac_sha512(enc_key: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
    type hmac_sha512 = hmac::Hmac<sha2::Sha512>;
    let mut mac =
        hmac_sha512::new_from_slice(enc_key.as_slice()).expect("HMAC can take key of any size");
    mac.update(&value);
    mac.finalize().into_bytes().to_vec()
}

pub fn base64decode(value: &str) -> Result<Vec<u8>> {
    base64::decode(value).map_err(Error::from)
}
