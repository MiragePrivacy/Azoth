use thiserror::Error;

/// Error type for CFG and IR construction.
#[derive(Debug, Error)]
pub enum CfgIrError {
    /// No valid entry block was found (e.g., empty instruction list).
    #[error("no valid entry block found")]
    NoEntryBlock,
    /// No valid exit block was found.
    #[error("no valid exit block found")]
    NoExitBlock,
    /// The instruction sequence is invalid (e.g., malformed control flow).
    #[error("invalid instruction sequence")]
    InvalidSequence,
    /// Decoding error from the `decoder` module.
    #[error("decoding error: {0}")]
    DecodeError(#[from] DecodeError),
}

/// Custom error type for decoding operations.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("hex decode failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("could not read file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("heimdall disassembly failed: {0}")]
    Heimdall(String),

    #[error("assembly parse error at line {line}: {msg} ⇒ `{raw}`")]
    Parse {
        line: usize,
        msg: String,
        raw: String,
    },
}

/// Custom error type for detection operations.
#[derive(Debug, Error)]
pub enum DetectError {
    #[error("overlapping sections detected at offset {0}")]
    Overlap(usize),
    #[error("gap detected at offset {0}")]
    Gap(usize),
    #[error("section extends beyond bytecode bounds at offset {0}")]
    OutOfBounds(usize),
    #[error("auxdata overlap detected")]
    AuxdataOverlap,
}

/// Errors that can occur during the encoding process.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// The immediate data for a PUSH opcode is invalid (e.g., wrong length or malformed hex).
    #[error("invalid immediate: {0}")]
    InvalidImmediate(String),
    /// The opcode is not supported by the encoder (e.g., unknown or unimplemented opcode).
    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(String),
    /// Failed to decode hex immediate data (e.g., invalid hex characters).
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

/// Error type for metrics computation.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("CFG is empty or malformed")]
    EmptyCfg,
    #[error("no body blocks found")]
    NoBodyBlocks,
}

/// Custom error type for stripping operations.
#[derive(Debug, Error)]
pub enum StripError {
    #[error("section out of bounds at offset {0}")]
    OutOfBounds(usize),
    #[error("invalid section configuration")]
    InvalidConfig,
    #[error("no runtime found")]
    NoRuntimeFound,
}

/// Error type for transform operations.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error("bytecode size exceeds maximum allowed delta")]
    SizeLimitExceeded,
    #[error("stack depth exceeds maximum limit of 1024")]
    StackOverflow,
    #[error("invalid jump target: {0}")]
    InvalidJumpTarget(usize),
    #[error("instruction encoding failed: {0}")]
    EncodingError(String),
    #[error("core operation failed")]
    CoreError(#[from] CfgIrError),
    #[error("metrics computation failed")]
    MetricsError(#[from] MetricsError),
    #[error("generic error")]
    Generic(String),
}

/// Errors that can occur during obfuscation.
#[derive(Debug, Error)]
pub enum ObfuscateError {
    /// The hex string has an odd length, making it invalid.
    #[error("hex string has odd length: {0}")]
    OddLength(usize),
    /// Failed to decode hex string to bytes.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// File read/write error.
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    /// Transform application failed.
    #[error("transform error: {0}")]
    Transform(#[from] TransformError),
    /// Invalid transform pass specified.
    #[error("invalid pass: {0}")]
    InvalidPass(String),
    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Errors that can occur in the seed system
#[derive(Debug, Clone, Error)]
pub enum SeedError {
    #[error("Invalid seed length: expected 64 hex chars, got {0}")]
    InvalidLength(usize),
    #[error("Invalid hexadecimal in seed")]
    InvalidHex,
    #[error("Invalid relay secret for HMAC")]
    InvalidRelaySecret,
    #[error("Obfuscation failed: {0}")]
    ObfuscationFailed(String),
}

// #[derive(Debug, Error)]
// pub enum Error {
//     #[error("decode error: {0}")]
//     Decode(#[from] DecodeError),
//     #[error("CFG IR error: {0}")]
//     CfgIr(#[from] CfgIrError),
//     #[error("detection error: {0}")]
//     Detect(#[from] DetectError),
//     #[error("strip error: {0}")]
//     Strip(#[from] StripError),
//     #[error("encode error: {0}")]
//     Encode(#[from] EncodeError),
//     #[error("metrics error: {0}")]
//     Metrics(#[from] MetricsError),
//     #[error("metrics error: {0}")]
//     Transform(#[from] TransformError),
//     #[error("metrics error: {0}")]
//     Obfuscate(#[from] ObfuscateError),
// }

// pub type Result<T> = std::result::Result<T, Error>;
