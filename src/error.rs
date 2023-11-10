/// Error type for RestApi responses.
#[derive(Debug)]
pub enum Error {
    BitcoinEncodeError(bitcoin::consensus::encode::Error),
    NotOkError(http::StatusCode),
    #[cfg(feature = "use-reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "use-reqwest")))]
    ReqwestError(reqwest::Error),
    #[cfg(not(feature = "use-reqwest"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "use-reqwest"))))]
    CustomError(Box<dyn std::error::Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::BitcoinEncodeError(ref e) => write!(f, "Bitcoin encode error, {e}"),
            Error::NotOkError(ref e) => write!(f, "Incorrect status code {e}"),
            #[cfg(feature = "use-reqwest")]
            #[cfg_attr(docsrs, doc(cfg(feature = "use-reqwest")))]
            Error::ReqwestError(ref e) => write!(f, "Reqwest error, {e}"),
            #[cfg(not(feature = "use-reqwest"))]
            #[cfg_attr(docsrs, doc(cfg(not(feature = "use-reqwest"))))]
            Error::CustomError(ref e) => write!(f, "Custom error, {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            BitcoinEncodeError(e) => Some(e),
            NotOkError(_) => None,
            #[cfg(feature = "use-reqwest")]
            #[cfg_attr(docsrs, doc(cfg(feature = "use-reqwest")))]
            ReqwestError(e) => Some(e),
            #[cfg(not(feature = "use-reqwest"))]
            #[cfg_attr(docsrs, doc(cfg(not(feature = "use-reqwest"))))]
            CustomError(e) => Some(e.as_ref()),
        }
    }
}

#[cfg(feature = "use-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "use-reqwest")))]
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::ReqwestError(err)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Self::BitcoinEncodeError(err)
    }
}
