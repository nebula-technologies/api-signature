extern crate base64;
extern crate bs58;
extern crate hmac;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;

mod error;
mod helpers;

use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Signature {
    config: Option<SignCal>,
    nonce: Arc<dyn Fn() -> Vec<u8>>,
    variables: HashMap<String, Variable>,
}

impl Signature {
    pub fn new() -> Self {
        Signature {
            config: None,
            nonce: Arc::new(|| -> Vec<u8> {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::new(0, 0))
                    .as_nanos()
                    .to_string()
                    .into_bytes()
            }),
            variables: Default::default(),
        }
    }

    pub fn nonce(&mut self, o: Arc<dyn Fn() -> Vec<u8>>) -> &mut Self {
        self.nonce = o;
        self
    }

    pub fn config(&mut self, config: SignCal) -> &mut Self {
        self.config = Some(config);
        self
    }

    pub fn var<T: Into<Variable>>(&mut self, key: &str, value: T) -> &mut Self {
        self.variables.insert(key.to_string(), value.into());
        self
    }

    pub fn compare<T: Into<Vec<u8>>>(&self, signature: T, nonce: usize) -> bool {
        let mut _self = self.clone();
        _self.nonce = Arc::new(move || -> Vec<u8> { nonce.to_string().as_bytes().to_vec() });
        signature.into() == self.sign()
    }

    pub fn sign(&self) -> Vec<u8> {
        let nonce_fn = &self.nonce;
        let mut variables = self.variables.clone();
        variables.insert("nonce".to_string(), Variable::Data(nonce_fn()));
        sign_calc(
            self.config.as_ref().unwrap_or(&SignCal::default()),
            &variables,
        )
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature::new()
    }
}

fn sign_calc(config: &SignCal, variables: &HashMap<String, Variable>) -> Vec<u8> {
    match config {
        SignCal::HmacSha512(k, c) => {
            helpers::hmac_sha512(&sign_calc(k, variables), &sign_calc(c.deref(), variables))
        }
        SignCal::HmacSha256(k, c) => {
            helpers::hmac_sha256(&sign_calc(k, variables), &sign_calc(c.deref(), variables))
        }
        SignCal::Sha256(c) => helpers::sha256(&sign_calc(c, variables)),
        SignCal::Base64Encode(c) => helpers::base64encode(&sign_calc(c, variables)),
        SignCal::Base64Decode(c) => helpers::base64decode(&sign_calc(c, variables)),
        SignCal::Base58Encode(c) => helpers::base58encode(&sign_calc(c, variables)),
        SignCal::Base58Decode(c) => helpers::base58decode(&sign_calc(c, variables)),
        SignCal::Sha512(c) => helpers::sha512(&sign_calc(c, variables)),
        SignCal::Append(a) => a
            .iter()
            .flat_map(|t| sign_calc(t, variables))
            .collect::<Vec<u8>>(),
        SignCal::VarData(k) => variables
            .get(k)
            .unwrap_or(&Variable::Data(Vec::new()))
            .into(),
        SignCal::VarString(k) => variables
            .get(k)
            .unwrap_or(&Variable::Data(Vec::new()))
            .into(),
        SignCal::VarInteger(k) => variables
            .get(k)
            .unwrap_or(&Variable::Data(Vec::new()))
            .into(),
        SignCal::Raw(v) => v.clone(),
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SignCal {
    HmacSha256(Box<SignCal>, Box<SignCal>),
    HmacSha512(Box<SignCal>, Box<SignCal>),
    Sha256(Box<SignCal>),
    Sha512(Box<SignCal>),
    Base64Encode(Box<SignCal>),
    Base64Decode(Box<SignCal>),
    Base58Encode(Box<SignCal>),
    Base58Decode(Box<SignCal>),
    Append(Vec<SignCal>),
    VarData(String),
    VarString(String),
    VarInteger(String),
    Raw(Vec<u8>),
}

impl Default for SignCal {
    fn default() -> Self {
        use SignCal::*;
        HmacSha512(
            Box::new(VarString("secret_key".to_string())),
            Box::new(Append(vec![
                VarString("uri_path".to_string()),
                Sha256(Box::new(Append(vec![
                    VarInteger("nonce".to_string()),
                    VarString("payload".to_string()),
                ]))),
                Base64Decode(Box::new(VarString("private_key".to_string()))),
            ])),
        )
    }
}

#[derive(Clone)]
pub enum Variable {
    Data(Vec<u8>),
    String(String),
    Integer(usize),
}

impl From<Variable> for Vec<u8> {
    fn from(v: Variable) -> Self {
        match v {
            Variable::Integer(i) => i.to_string().into_bytes(),
            Variable::Data(d) => d,
            Variable::String(s) => s.into_bytes(),
        }
    }
}
impl From<&Variable> for Vec<u8> {
    fn from(v: &Variable) -> Self {
        match v {
            Variable::Integer(i) => i.to_string().into_bytes(),
            Variable::Data(d) => d.clone(),
            Variable::String(s) => s.clone().into_bytes(),
        }
    }
}

impl From<String> for Variable {
    fn from(s: String) -> Self {
        Variable::String(s)
    }
}
impl From<&str> for Variable {
    fn from(s: &str) -> Self {
        Variable::String(s.to_string())
    }
}
impl From<usize> for Variable {
    fn from(i: usize) -> Self {
        Variable::Integer(i)
    }
}
impl From<u8> for Variable {
    fn from(i: u8) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<u32> for Variable {
    fn from(i: u32) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<u64> for Variable {
    fn from(i: u64) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<u128> for Variable {
    fn from(i: u128) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<i8> for Variable {
    fn from(i: i8) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<i32> for Variable {
    fn from(i: i32) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<i64> for Variable {
    fn from(i: i64) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<i128> for Variable {
    fn from(i: i128) -> Self {
        Variable::Integer(i as usize)
    }
}
impl From<Vec<u8>> for Variable {
    fn from(v: Vec<u8>) -> Self {
        Variable::Data(v)
    }
}
impl From<&[u8]> for Variable {
    fn from(v: &[u8]) -> Self {
        Variable::Data(v.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{SignCal, Signature};
    use hex;
    use hex::FromHex;
    use std::sync::Arc;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn test_base58() {
        use SignCal::*;
        assert_eq!(
            b"3mJr7AoUCHxNqd".to_vec(),
            Signature::default()
                .config(Base58Encode(Raw(b"1234567890".to_vec()).into()))
                .sign()
        );
    }

    #[test]
    fn test_base58_decode() {
        use SignCal::*;
        assert_eq!(
            b"1234567890".to_vec(),
            Signature::default()
                .config(Base58Decode(Raw(b"3mJr7AoUCHxNqd".to_vec()).into()))
                .sign()
        );
    }

    #[test]
    fn test_base64() {
        use SignCal::*;
        assert_eq!(
            b"MTIzNDU2Nzg5MA==".to_vec(),
            Signature::default()
                .config(Base64Encode(Raw(b"1234567890".to_vec()).into()))
                .sign()
        );
    }

    #[test]
    fn test_base64_decode() {
        use SignCal::*;
        assert_eq!(
            b"1234567890".to_vec(),
            Signature::default()
                .config(Base64Decode(Raw(b"MTIzNDU2Nzg5MA==".to_vec()).into()))
                .sign()
        );
    }

    #[test]
    fn test_sha256() {
        use SignCal::*;

        let signature = Signature::default()
            .config(Sha256(
                Raw("1234567890".to_string().as_bytes().to_vec()).into(),
            ))
            .sign();

        assert_eq!(
            hex::decode("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646")
                .unwrap(),
            signature
        );
    }

    #[test]
    fn test_sha512() {
        use SignCal::*;
        assert_eq!(
            hex::decode("12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9").unwrap(),
            Signature::default()
                .config(Sha512(Raw(b"1234567890".to_vec()).into()))
                .sign()
        );
    }

    #[test]
    fn test_sign_cal_with_control_signature() {
        use SignCal::*;

        let nonce = 1616492376594usize;
        let mut signature = Signature::default();
        signature.var("payload", format!("nonce={}&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25",nonce))
            .var("secret_key", "kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==")
            .var("url", "/0/private/AddOrder")
            .nonce(Arc::new(move || -> Vec<u8> {nonce.to_string().as_bytes().to_vec()}))
            .config(Base64Encode(
            HmacSha512(
                Base64Decode(VarString("secret_key".to_string()).into()).into(),
                Append(vec![
                    VarString("url".to_string()),
                    Sha256(
                        Append(vec![
                            VarInteger("nonce".to_string()),
                            VarString("payload".to_string()),
                        ])
                        .into(),
                    ),
                ])
                .into(),
            )
            .into(),
        ));

        let api_sign = b"4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ==".to_vec();

        assert_eq!(api_sign, signature.sign());
    }
}
