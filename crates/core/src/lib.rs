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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_terminal_opcode() {
        // Terminal opcodes
        assert!(is_terminal_opcode("STOP"));
        assert!(is_terminal_opcode("RETURN"));
        assert!(is_terminal_opcode("REVERT"));
        assert!(is_terminal_opcode("SELFDESTRUCT"));
        assert!(is_terminal_opcode("INVALID"));

        // Non-terminal opcodes
        assert!(!is_terminal_opcode("JUMP"));
        assert!(!is_terminal_opcode("JUMPI"));
        assert!(!is_terminal_opcode("PUSH1"));
        assert!(!is_terminal_opcode("POP"));
        assert!(!is_terminal_opcode("ADD"));
    }

    #[test]
    fn test_is_block_ending_opcode() {
        // Block-ending opcodes (terminal + control flow)
        assert!(is_block_ending_opcode("STOP"));
        assert!(is_block_ending_opcode("RETURN"));
        assert!(is_block_ending_opcode("REVERT"));
        assert!(is_block_ending_opcode("SELFDESTRUCT"));
        assert!(is_block_ending_opcode("INVALID"));
        assert!(is_block_ending_opcode("JUMP"));
        assert!(is_block_ending_opcode("JUMPI"));

        // Non-block-ending opcodes
        assert!(!is_block_ending_opcode("PUSH1"));
        assert!(!is_block_ending_opcode("POP"));
        assert!(!is_block_ending_opcode("ADD"));
    }
}
