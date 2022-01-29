extern crate serde;
extern crate serde_derive;
extern crate serde_json;

mod helpers;

use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;

use std::time::{Duration, SystemTime};
pub struct Nonce {}

impl Default for Nonce {
    fn default() -> Self {
        Nonce {}
    }
}

impl NonceHandler for Nonce {
    fn get_nonce() -> usize {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|t| t.as_nanos())
            .unwrap_or(0) as usize
    }
}

trait NonceHandler {
    fn get_nonce() -> usize;
}

pub fn check_signature<T>(
    signature: &[u8],
    nonce: usize,
    payload: T,
    config: SignatureConfig,
) -> Result<T, Error> {
    Ok(payload)
}

pub enum Error {}

pub struct SignatureConfig {
    pattern: SignCal,
}

pub fn encode_sign(nonce: usize, secret_key: String, uri: String) -> String {}

pub fn sign_calc(
    config: &SignCal,
    secret_value: secret,
    variables: &HashMap<String, Variable>,
) -> Vec<u8> {
    match config {
        SignCal::HmacSha512(c) => helpers::hmac_sha512(secret_key, sign_calc(c.deref(), secret_value, variables)),
        SignCal::Sha256(c) => {helpers::sha256(&sign_calc(c, secret_value, variables))}
        SignCal::Base64encode(c) => {helpers::base64encode(&sign_calc(c, secret_value, variables))}
        SignCal::Base64Decode(c) => {helpers::base64decode(&sign_calc(c, secret_value, variables))}
        SignCal::Sha512(c) => {helpers::sha512(&sign(c,secret_value, variables))}
        SignCal::Append(_) => {}
        SignCal::VarData(_) => {}
        SignCal::VarString(_) => {}
        SignCal::VarInteger(_) => {}
        SignCal::EncryptionKey(_) => {}
    }
}

#[derive(Serialize, Deserialize)]
pub enum SignCal {
    HmacSha512(Box<SignCal>),
    Sha256(Box<SignCal>),
    Base64encode(Box<SignCal>),
    Base64Decode(Box<SignCal>),
    Sha512(Box<SignCal>),
    Append(Box<Vec<SignCal>>),
    VarData(String),
    VarString(String),
    VarInteger(String),
    EncryptionKey(Vec<u8>),
}

pub enum Variable {
    Data(Vec<u8>),
    String(String),
    Integer(usize),
}

#[cfg(test)]
mod tests {
    use crate::SignCal;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn test_sign_cal() {
        use SignCal::*;

        let nonce = 1_616_492_376_594usize;
        let encoded_payload = format!(
            "nonce={}&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25",
            nonce
        );
        let private_key = "kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==".to_string();
        let uri_path = "/0/private/AddOrder".to_string();

        let api_signature = HmacSha512(Box::new(Append(Box::new(vec![
            VarString("uri_path".to_string()),
            Sha256(Box::new(Append(Box::new(vec![
                VarInteger("nonce".to_string()),
                VarString("payload".to_string()),
            ])))),
            Base64Decode(Box::new(VarString("private_key".to_string()))),
        ]))));

        println!("{}", serde_json::to_string(&api_signature).unwrap());
    }
}
