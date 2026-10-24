use thiserror::Error;

/// Why a piece of chain data was rejected. Every variant means "do not use this data,
/// try another source".
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Reject {
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },
    #[error("invalid proof of work at height {height}")]
    PowInvalid { height: u64 },
    #[error("block hash above its own target at height {height}")]
    TargetNotMet { height: u64 },
    #[error("header at height {height} breaks the difficulty or time rules: {detail}")]
    ContextInvalid { height: u64, detail: String },
    #[error("header at height {height} does not link to its predecessor")]
    BrokenChain { height: u64 },
    #[error("block {height} does not match the checkpoint")]
    CheckpointMismatch { height: u64 },
    #[error("transaction {index} at height {height}: rebuilt ID does not match")]
    TxIdMismatch { height: u64, index: usize },
    #[error("duplicate transaction ID in block {height}")]
    DuplicateTxId { height: u64 },
    #[error("Merkle root mismatch at height {height}")]
    MerkleMismatch { height: u64 },
    #[error("compact block {height} disagrees with its header ({field})")]
    CompactHeaderMismatch { height: u64, field: &'static str },
    #[error("v4 transaction {index} at height {height}: compact data differs from its full bytes")]
    V4CompactMismatch { height: u64, index: usize },
    #[error("history tree root mismatch at height {height}")]
    HistoryMismatch { height: u64 },
    #[error("{pool} note commitment tree root mismatch at height {height}")]
    TreeRootMismatch { height: u64, pool: &'static str },
    #[error("chain work of the offered tip is lower than the known tip")]
    ChainWorkLower,
    #[error("tip is stale: newest header is {age_secs} s old")]
    StaleTip { age_secs: u64 },
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Reject {
    pub(crate) fn malformed(what: &'static str, detail: impl ToString) -> Self {
        Reject::Malformed {
            what,
            detail: detail.to_string(),
        }
    }
}
