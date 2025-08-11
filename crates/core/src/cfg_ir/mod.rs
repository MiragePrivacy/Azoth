/// Module for constructing a Control Flow Graph (CFG) with Intermediate Representation (IR)
/// in Static Single Assignment (SSA) form for EVM bytecode analysis.
///
/// This module builds a CFG from decoded EVM instructions, representing the program's control
/// flow as a graph of basic blocks connected by edges. It supports SSA form for stack
/// operations, enabling analysis and obfuscation transforms. The CFG is used to analyze and modify
/// bytecode structure, ensuring accurate block splitting and edge construction based on
/// control flow opcodes.

use crate::decoder::Instruction;
use crate::detection::Section;
use crate::is_terminal_opcode;
use azoth_utils::errors::CfgIrError;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub use self::builder::build_cfg_ir;

mod builder;
mod updates;

/// Represents a node in the Control Flow Graph (CFG).
///
/// A `Block` can be an entry point, an exit point, or a body block containing a sequence of EVM
/// instructions. Blocks partition the bytecode into logical units for analysis, with `Entry` and
/// `Exit` serving as the start and end nodes of the CFG, respectively. Body blocks hold
/// instructions and track the maximum stack height for Static Single Assignment (SSA) form
/// analysis.
#[derive(Default, Debug, Clone)]
pub enum Block {
    /// The entry point of the CFG, representing the start of execution.
    #[default]
    Entry,
    /// The exit point of the CFG, representing the end of execution (e.g., STOP, RETURN).
    Exit,
    /// A body block containing a sequence of instructions.
    Body {
        /// The program counter (PC) at which the block starts.
        start_pc: usize,
        /// The list of decoded EVM instructions in the block.
        instructions: Vec<Instruction>,
        /// The maximum stack height reached during execution of the block, used for SSA analysis.
        max_stack: usize,
    },
}

/// Represents the type of edge connecting blocks in the CFG.
///
/// Edges define the control flow between blocks, indicating how execution can transition from one
/// block to another. Different edge types correspond to different control flow mechanisms in EVM
/// bytecode, such as sequential execution, jumps, or conditional branches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdgeType {
    /// Sequential execution to the next block (e.g., after non-terminal instructions).
    Fallthrough,
    /// Unconditional jump to a target block (e.g., JUMP instruction).
    Jump,
    /// Conditional branch taken when the condition is true (e.g., JUMPI true branch).
    BranchTrue,
    /// Conditional branch taken when the condition is false (e.g., JUMPI false branch).
    BranchFalse,
}

/// A unique identifier for a value in SSA form.
///
/// Each `ValueId` represents a distinct value produced by an instruction (e.g., a PUSH operation)
/// and is used to track data flow through the stack in the CFG's SSA representation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueId(usize);

/// Bundle of CFG and associated metadata for analysis.
///
/// Contains the control flow graph, a mapping of program counters to block indices, and a
/// `CleanReport` for reassembling bytecode.
#[derive(Debug, Clone)]
pub struct CfgIrBundle {
    /// Graph representing the CFG with blocks as nodes and edges as control flow.
    pub cfg: DiGraph<Block, EdgeType>,
    /// Mapping of program counters to block indices.
    pub pc_to_block: HashMap<usize, NodeIndex>,
    /// Report detailing the stripping process for bytecode reassembly.
    pub clean_report: crate::strip::CleanReport,
    /// Mapping of original function selectors to obfuscated tokens.
    /// Only populated when token-based dispatcher transform is applied.
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
}

impl CfgIrBundle {
    /// Replaces the body of the CFG with new bytecode, rebuilding the CFG and PC mapping.
    ///
    /// # Arguments
    /// * `new_bytecode` - The new bytecode to process.
    /// * `sections` - Detected sections for the new bytecode.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CfgIrError` if rebuilding fails.
    pub fn replace_body(
        &mut self,
        instructions: Vec<Instruction>,
        sections: &[Section],
        new_bytecode: Vec<u8>,
    ) -> Result<(), CfgIrError> {
        let clean_report = self.clean_report.clone();
        let selector_mapping = self.selector_mapping.clone(); // Preserve mapping
        let new_bundle = build_cfg_ir(&instructions, sections, &new_bytecode, clean_report)?;

        self.cfg = new_bundle.cfg;
        self.pc_to_block = new_bundle.pc_to_block;
        self.clean_report = new_bundle.clean_report;
        self.selector_mapping = selector_mapping; // Restore mapping

        Ok(())
    }
}

/// Returns the starting program counter for a block.
impl Block {
    fn start_pc(&self) -> usize {
        match self {
            Block::Body { start_pc, .. } => *start_pc,
            _ => 0,
        }
    }
}

/// Collects jump targets from PUSHn followed by JUMP/JUMPI instruction pairs.
///
/// Iterates through instructions to identify static jump targets where a PUSH instruction
/// is immediately followed by a JUMP or JUMPI instruction. Parses the immediate value
/// of the PUSH instruction as the jump target address.
///
/// # Arguments
/// * `instructions` - Decoded EVM instructions to analyze.
///
/// # Returns
/// A vector of program counters representing static jump targets.
fn collect_jump_targets(instructions: &[Instruction]) -> Vec<usize> {
    let mut targets = Vec::new();
    let mut prev_instr: Option<&Instruction> = None;

    for instr in instructions {
        if let Some(prev) = prev_instr {
            if prev.opcode.starts_with("PUSH") && matches!(instr.opcode.as_str(), "JUMP" | "JUMPI")
            {
                if let Some(imm) = &prev.imm {
                    if let Ok(target_pc) = usize::from_str_radix(imm, 16) {
                        tracing::debug!("Found jump target: pc={}", target_pc);
                        targets.push(target_pc);
                    }
                }
            }
        }
        prev_instr = Some(instr);
    }

    targets
}

/// Validates jump targets against valid program counters and bytecode constraints.
///
/// Filters the provided jump targets to ensure they point to valid JUMPDEST instructions
/// within the bytecode bounds. Also ensures no duplicate blocks are created for the same
/// program counter.
///
/// # Arguments
/// * `targets` - Raw jump targets to validate.
/// * `valid_pcs` - Set of valid program counters from the instruction stream.
/// * `bytecode` - Raw bytecode bytes for opcode validation.
/// * `existing_blocks` - Current blocks to check for duplicates.
///
/// # Returns
/// A vector of validated jump targets that can be used to create blocks.
fn validate_jump_targets(
    targets: &[usize],
    valid_pcs: &HashSet<usize>,
    bytecode: &[u8],
    existing_blocks: &[Block],
) -> Vec<usize> {
    targets
        .iter()
        .filter(|&&tgt| {
            let is_valid = valid_pcs.contains(&tgt)
                && tgt < bytecode.len()
                && bytecode[tgt] == 0x5b // JUMPDEST opcode
                && existing_blocks.iter().all(|b| {
                    if let Block::Body { start_pc, .. } = b {
                        *start_pc != tgt
                    } else {
                        true
                    }
                });

            if is_valid {
                tracing::debug!("Creating block for jump target at pc={}", tgt);
            } else {
                tracing::debug!("Skipping invalid jump target at pc={}", tgt);
            }

            is_valid
        })
        .copied()
        .collect()
}

/// Creates blocks for validated jump targets.
///
/// Generates `Block::Body` instances for each validated jump target, initializing
/// them with empty instruction vectors and zero stack heights. These blocks represent
/// potential entry points for static jumps.
///
/// # Arguments
/// * `targets` - Validated jump targets from `validate_jump_targets`.
///
/// # Returns
/// A vector of `Block::Body` instances for the jump targets.
fn create_blocks_for_targets(targets: &[usize]) -> Vec<Block> {
    targets
        .iter()
        .map(|&tgt| Block::Body {
            start_pc: tgt,
            instructions: Vec::new(),
            max_stack: 0,
        })
        .collect()
}

/// Assigns SSA values and computes stack heights for each block.
///
/// Walks through each block's instructions to assign SSA `ValueId`s for stack operations (e.g.,
/// PUSH) and compute the maximum stack height. Updates the `max_stack` field in `Block::Body`
/// instances.
///
/// # Arguments
/// * `cfg` - The CFG graph with nodes populated.
/// * `pc_to_block` - Mapping of program counters to block indices.
/// * `instructions` - Decoded EVM instructions.
///
/// # Returns
/// A `Result` indicating success or a `CfgIrError` if SSA assignment fails.
fn assign_ssa_values(
    cfg: &mut DiGraph<Block, EdgeType>,
    _pc_to_block: &HashMap<usize, NodeIndex>,
    _instructions: &[Instruction],
) -> Result<(), CfgIrError> {
    let mut value_id = 0;

    for node in cfg.node_indices() {
        let block = cfg.node_weight(node).unwrap();
        let mut ssa_map = HashMap::new();
        let mut stack = Vec::new();
        let mut cur_depth: usize = 0;
        let mut max_stack = 0;

        if let Block::Body { instructions, .. } = block {
            for instr in instructions {
                tracing::debug!("Processing opcode {} at pc={}", instr.opcode, instr.pc);
                if instr.opcode.starts_with("PUSH") || instr.opcode.starts_with("DUP") {
                    cur_depth += 1;
                } else if instr.opcode == "POP" && stack.pop().is_some() {
                    cur_depth = cur_depth.saturating_sub(1);
                }
                if instr.opcode.starts_with("PUSH") {
                    stack.push(ValueId(value_id));
                    ssa_map.insert(instr.pc, ValueId(value_id));
                    value_id += 1;
                }
                max_stack = max_stack.max(cur_depth);
            }
            tracing::debug!(
                "Block at pc={} has max_stack={}",
                block.start_pc(),
                max_stack
            );
            let updated_block = Block::Body {
                start_pc: block.start_pc(),
                instructions: instructions.clone(),
                max_stack,
            };
            cfg[node] = updated_block;
        }
    }

    Ok(())
}
