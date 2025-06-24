/// Module defining the EVM opcode enumeration and related functionality.
///
/// This module provides the `Opcode` enum, which represents all EVM opcodes used in the
/// bytecloak project for parsing, encoding, and control flow graph (CFG) construction. It
/// supports opcodes relevant to common Solidity contracts (e.g., ERC-20, DeFi) and planned
/// obfuscation transforms (e.g., shuffle, stack-noise, opaque-predicates, constant-blinding,
/// control-flow flattening). The module includes methods for parsing opcodes from bytes,
/// checking control flow relevance, and converting opcodes to their byte representation.
use std::fmt;

/// Enumeration of EVM opcodes with their byte values and immediate data sizes.
///
/// The `Opcode` enum includes single-byte opcodes (e.g., `STOP`, `ADD`), variable-length stack
/// operations (e.g., `PUSH(n)`, `DUP(n)`), and a catch-all `Other(u8)` for unsupported opcodes.
/// Each variant corresponds to a specific EVM instruction, with associated immediate data sizes
/// for `PUSH` opcodes (1 to 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // 0x range - stop & arithmetic
    STOP, // 0x00
    ADD,  // 0x01
    MUL,  // 0x02
    SUB,  // 0x03
    DIV,  // 0x04
    // 10x range - comparison & logic
    LT,     // 0x10
    GT,     // 0x11
    EQ,     // 0x14
    ISZERO, // 0x15
    AND,    // 0x16
    OR,     // 0x17
    XOR,    // 0x18
    // 30x range - environment
    ADDRESS, // 0x30
    BALANCE, // 0x31
    // 50x range - stack, memory & storage
    POP,      // 0x50
    MLOAD,    // 0x51
    MSTORE,   // 0x52
    MSTORE8,  // 0x53
    SLOAD,    // 0x54
    SSTORE,   // 0x55
    JUMP,     // 0x56
    JUMPI,    // 0x57
    JUMPDEST, // 0x5b
    // 60x-90x range - variable-length stack ops
    PUSH(u8), // 0x60–0x7f (PUSH1 to PUSH32)
    DUP(u8),  // 0x80–0x8f (DUP1 to DUP16)
    SWAP(u8), // 0x90–0x9f (SWAP1 to SWAP16)
    // f0x range - termination
    RETURN,       // 0xf3
    REVERT,       // 0xfd
    INVALID,      // 0xfe
    SELFDESTRUCT, // 0xff
    // Catch-all for unhandled opcodes
    Other(u8),
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opcode::STOP => write!(f, "STOP"),
            Opcode::ADD => write!(f, "ADD"),
            Opcode::MUL => write!(f, "MUL"),
            Opcode::SUB => write!(f, "SUB"),
            Opcode::DIV => write!(f, "DIV"),
            Opcode::LT => write!(f, "LT"),
            Opcode::GT => write!(f, "GT"),
            Opcode::EQ => write!(f, "EQ"),
            Opcode::ISZERO => write!(f, "ISZERO"),
            Opcode::AND => write!(f, "AND"),
            Opcode::OR => write!(f, "OR"),
            Opcode::XOR => write!(f, "XOR"),
            Opcode::ADDRESS => write!(f, "ADDRESS"),
            Opcode::BALANCE => write!(f, "BALANCE"),
            Opcode::POP => write!(f, "POP"),
            Opcode::MLOAD => write!(f, "MLOAD"),
            Opcode::MSTORE => write!(f, "MSTORE"),
            Opcode::MSTORE8 => write!(f, "MSTORE8"),
            Opcode::SLOAD => write!(f, "SLOAD"),
            Opcode::SSTORE => write!(f, "SSTORE"),
            Opcode::JUMP => write!(f, "JUMP"),
            Opcode::JUMPI => write!(f, "JUMPI"),
            Opcode::JUMPDEST => write!(f, "JUMPDEST"),
            Opcode::PUSH(n) => write!(f, "PUSH{}", n),
            Opcode::DUP(n) => write!(f, "DUP{}", n),
            Opcode::SWAP(n) => write!(f, "SWAP{}", n),
            Opcode::RETURN => write!(f, "RETURN"),
            Opcode::REVERT => write!(f, "REVERT"),
            Opcode::INVALID => write!(f, "INVALID"),
            Opcode::SELFDESTRUCT => write!(f, "SELFDESTRUCT"),
            Opcode::Other(byte) => write!(f, "UNKNOWN{:02x}", byte),
        }
    }
}

impl Opcode {
    /// Parses a raw byte into an `Opcode` and its immediate data size.
    ///
    /// # Arguments
    /// * `byte` - The raw byte representing the opcode.
    ///
    /// # Returns
    /// A tuple containing the `Opcode` variant and the number of immediate bytes to follow
    /// (e.g., 1 for `PUSH1`, 32 for `PUSH32`, 0 for others).
    ///
    /// # Examples
    /// ```rust,ignore
    /// let (opcode, imm_size) = Opcode::parse(0x60);
    /// assert_eq!(opcode, Opcode::PUSH(1));
    /// assert_eq!(imm_size, 1);
    /// ```
    pub fn parse(byte: u8) -> (Self, usize) {
        use Opcode::*;

        match byte {
            0x00 => (STOP, 0),
            0x01 => (ADD, 0),
            0x02 => (MUL, 0),
            0x03 => (SUB, 0),
            0x04 => (DIV, 0),
            0x10 => (LT, 0),
            0x11 => (GT, 0),
            0x14 => (EQ, 0),
            0x15 => (ISZERO, 0),
            0x16 => (AND, 0),
            0x17 => (OR, 0),
            0x18 => (XOR, 0),
            0x30 => (ADDRESS, 0),
            0x31 => (BALANCE, 0),
            0x50 => (POP, 0),
            0x51 => (MLOAD, 0),
            0x52 => (MSTORE, 0),
            0x53 => (MSTORE8, 0),
            0x54 => (SLOAD, 0),
            0x55 => (SSTORE, 0),
            0x56 => (JUMP, 0),
            0x57 => (JUMPI, 0),
            0x5b => (JUMPDEST, 0),
            0xf3 => (RETURN, 0),
            0xfd => (REVERT, 0),
            0xfe => (INVALID, 0),
            0xff => (SELFDESTRUCT, 0),
            0x60..=0x7f => {
                let n = byte - 0x5f;
                (PUSH(n), n as usize)
            }
            0x80..=0x8f => (DUP(byte - 0x7f), 0),
            0x90..=0x9f => (SWAP(byte - 0x8f), 0),
            other => (Other(other), 0),
        }
    }

    /// Checks if the opcode affects control flow in CFG construction.
    ///
    /// Returns `true` for opcodes that define block boundaries or alter execution flow
    /// (e.g., `STOP`, `JUMP`, `RETURN`).
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Opcode::STOP
                | Opcode::JUMP
                | Opcode::JUMPI
                | Opcode::JUMPDEST
                | Opcode::RETURN
                | Opcode::REVERT
                | Opcode::SELFDESTRUCT
                | Opcode::INVALID
        )
    }

    /// Converts the opcode to its byte representation.
    ///
    /// # Returns
    /// The byte value of the opcode (e.g., 0x60 for `PUSH1`, 0x00 for `STOP`).
    pub fn to_byte(&self) -> u8 {
        use Opcode::*;

        match self {
            STOP => 0x00,
            ADD => 0x01,
            MUL => 0x02,
            SUB => 0x03,
            DIV => 0x04,
            LT => 0x10,
            GT => 0x11,
            EQ => 0x14,
            ISZERO => 0x15,
            AND => 0x16,
            OR => 0x17,
            XOR => 0x18,
            ADDRESS => 0x30,
            BALANCE => 0x31,
            POP => 0x50,
            MLOAD => 0x51,
            MSTORE => 0x52,
            MSTORE8 => 0x53,
            SLOAD => 0x54,
            SSTORE => 0x55,
            JUMP => 0x56,
            JUMPI => 0x57,
            JUMPDEST => 0x5b,
            PUSH(n) => 0x5f + n,
            DUP(n) => 0x7f + n,
            SWAP(n) => 0x8f + n,
            RETURN => 0xf3,
            REVERT => 0xfd,
            INVALID => 0xfe,
            SELFDESTRUCT => 0xff,
            Other(byte) => *byte,
        }
    }
}
