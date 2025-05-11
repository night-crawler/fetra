pub mod ext;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // #[error("Failed to read dir {1}: {0}")]
    // ReadDir(std::io::Error, String),
}
