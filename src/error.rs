use base64::DecodeError;

pub enum Error {
    Base64Decode(base64::DecodeError),
    Base58Decode(bs58::decode::Error),
}

impl From<base64::DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Error::Base64Decode(e)
    }
}
impl From<bs58::decode::Error> for Error {
    fn from(e: bs58::decode::Error) -> Self {
        Error::Base58Decode(e)
    }
}
