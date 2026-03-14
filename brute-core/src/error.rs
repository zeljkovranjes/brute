use thiserror::Error;

#[derive(Debug, Error)]
pub enum BruteError {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("geo lookup error: {0}")]
    Geo(String),

    #[error("analytics error: {0}")]
    Analytics(String),
}
