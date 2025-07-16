pub mod cfg_ir;
pub mod decoder;
pub mod detection;
pub mod encoder;
pub mod strip;

pub use eot::UnifiedOpcode as Opcode;

/// Returns true if the opcode terminates execution.
///
/// Terminal opcodes are those that end the execution of a program or transaction,
/// such as STOP, RETURN, REVERT, SELFDESTRUCT, and INVALID.
pub fn is_terminal_opcode(opcode: &str) -> bool {
    matches!(
        opcode,
        "STOP" | "RETURN" | "REVERT" | "SELFDESTRUCT" | "INVALID"
    )
}

/// Returns true if the opcode ends a basic block.
///
/// Block-ending opcodes include terminal opcodes as well as control flow opcodes
/// like JUMP and JUMPI that transfer control to different parts of the program.
pub fn is_block_ending_opcode(opcode: &str) -> bool {
    matches!(
        opcode,
        "STOP" | "RETURN" | "REVERT" | "SELFDESTRUCT" | "INVALID" | "JUMP" | "JUMPI"
    )
}
