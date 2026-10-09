use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
    #[from(String, &String, &str)]
    Custom(String),

    // -- Externals
    #[from]
    Io(std::io::Error),
    #[from]
    Postcard(postcard::Error),
    #[from]
    Temper(temper::Error),
}

// region:    --- Custom

impl Error {
    pub fn custom_from_err(err: impl std::error::Error) -> Self {
        Self::Custom(err.to_string())
    }

    pub fn custom(val: impl Into<String>) -> Self {
        Self::Custom(val.into())
    }

    /// The message itself, without the `Custom(...)` wrapper.
    ///
    /// `Display` here is the debug formatter — deliberate, so a log line
    /// never loses which variant failed — which makes it wrong for messages
    /// *about* an error: wrapping one in another `Error::custom` otherwise
    /// produces `Custom("...: Custom(\"...\")")`.
    pub fn message(&self) -> String {
        match self {
            Self::Custom(message) => message.clone(),
            other => other.to_string(),
        }
    }
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
