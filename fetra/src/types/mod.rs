use crate::types::fs_type::FsType;
use crate::types::mode::FileType;
use num_enum::TryFromPrimitiveError;
use std::num::TryFromIntError;

pub mod fs_type;
pub mod mode;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to read dir {0}")]
    Io(#[from] std::io::Error),

    #[error("Device {0}:{1} not found")]
    DeviceNotFound(u32, u32),

    #[error("{0}: {1}")]
    Path(std::io::Error, String),

    #[error("Conversion failed: {0}")]
    IntConv(#[from] TryFromIntError),

    #[error("Conversion failed: {0}")]
    FsType(#[from] TryFromPrimitiveError<FsType>),

    #[error("Conversion failed: {0}")]
    FileType(#[from] TryFromPrimitiveError<FileType>),
}

pub type Result<T> = std::result::Result<T, Error>;
