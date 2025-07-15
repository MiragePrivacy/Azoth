/// Module for constructing a Control Flow Graph (CFG) with Intermediate Representation (IR)
/// in Static Single Assignment (SSA) form for EVM bytecode analysis.
///
/// This module builds a CFG from decoded EVM instructions, representing the program's control
/// flow as a graph of basic blocks connected by edges. It supports SSA form for stack
/// operations, enabling analysis and obfuscation transforms (e.g., shuffle, stack-noise,
/// opaque-predicates). The CFG is used to analyze and modify bytecode structure, ensuring
/// accurate block splitting and edge construction based on control flow opcodes.
use crate::decoder::Instruction;
use crate::detection::Section;
use bytecloak_utils::errors::CfgIrError;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
}

/// Builds a CFG with IR in SSA form from decoded instructions and sections.
///
/// Constructs a control flow graph by splitting instructions into blocks, building edges based on
/// control flow, and assigning SSA values to track stack operations. The resulting `CfgIrBundle`
/// is used for further analysis and obfuscation transforms.
///
/// # Arguments
/// * `instructions` - Decoded EVM instructions from `decoder.rs`.
/// * `sections` - Detected sections from `detection.rs`.
/// * `bytecode` - Raw bytecode bytes.
/// * `clean_report` - Report from `strip.rs` for reassembly.
///
/// # Returns
/// A `Result` containing the `CfgIrBundle` or a `CfgIrError` if construction fails.
///
/// # Examples
/// ```rust,ignore
/// let bytecode = hex::decode("6001600155").unwrap();
/// let (instructions, info, _) = decoder::decode_bytecode("0x6001600155", false).await.unwrap();
/// let sections = detection::locate_sections(&bytecode, &instructions, &info).unwrap();
/// let (_, report) = strip::strip_bytecode(&bytecode, &sections).unwrap();
/// let cfg_ir = build_cfg_ir(&instructions, &sections, &bytecode, report).unwrap();
/// assert!(cfg_ir.cfg.node_count() >= 2);
/// ```
pub fn build_cfg_ir(
    instructions: &[Instruction],
    _sections: &[Section],
    bytecode: &[u8],
    clean_report: crate::strip::CleanReport,
) -> Result<CfgIrBundle, CfgIrError> {
    tracing::debug!(
        "Starting CFG-IR construction with {} instructions",
        instructions.len()
    );

    // Step 1: Block splitter
    let blocks = split_blocks(instructions, bytecode)?;
    tracing::debug!("Split into {} blocks", blocks.len());

    // Step 2: Edge builder
    let mut cfg = DiGraph::new();
    let _entry_idx = cfg.add_node(Block::Entry);
    let _exit_idx = cfg.add_node(Block::Exit);
    let (edges, pc_to_block) = build_edges(&blocks, instructions, &mut cfg)?;
    cfg.extend_with_edges(edges);
    tracing::debug!("Built CFG with {} nodes", cfg.node_count());

    // Step 3: Stack-SSA walk
    let report = clean_report;
    assign_ssa_values(&mut cfg, &pc_to_block, instructions)?;
    tracing::debug!("Assigned SSA values and computed stack heights");

    debug_assert!(
        cfg.node_count() >= 2,
        "CFG must contain at least Entry and Exit"
    );
    Ok(CfgIrBundle {
        cfg,
        pc_to_block,
        clean_report: report,
    })
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
    pub async fn replace_body(
        &mut self,
        new_bytecode: Vec<u8>,
        sections: &[Section],
    ) -> Result<(), CfgIrError> {
        let (instructions, _, _) =
            crate::decoder::decode_bytecode(&format!("0x{}", hex::encode(&new_bytecode)), false)
                .await
                .map_err(CfgIrError::DecodeError)?;

        let clean_report = self.clean_report.clone();
        let new_bundle = build_cfg_ir(&instructions, sections, &new_bytecode, clean_report)?;

        self.cfg = new_bundle.cfg;
        self.pc_to_block = new_bundle.pc_to_block;
        self.clean_report = new_bundle.clean_report;

        Ok(())
    }
}

/// Splits instructions into blocks at JUMPDEST, terminal opcodes, or valid static PUSH-JUMP
/// targets.
///
/// Iterates through instructions to identify block boundaries based on control flow instructions
/// and jump targets, creating `Block::Body` instances for each segment. Ensures blocks are
/// non-empty and handles static jump targets correctly.
///
/// # Arguments
/// * `instructions` - Decoded EVM instructions.
/// * `bytecode` - Raw bytecode bytes for jump target validation.
///
/// # Returns
/// A `Result` containing a vector of `Block` instances or a `CfgIrError` if no blocks are created.
fn split_blocks(instructions: &[Instruction], bytecode: &[u8]) -> Result<Vec<Block>, CfgIrError> {
    let mut blocks = Vec::new();
    let mut cur_block = Block::Body {
        start_pc: 0,
        instructions: Vec::new(),
        max_stack: 0,
    };
    let mut static_jump_targets = Vec::new();
    let mut valid_pcs = HashSet::new();
    let mut prev_instr: Option<&Instruction> = None;

    tracing::debug!(
        "Starting block splitting with {} instructions",
        instructions.len()
    );

    for instr in instructions {
        valid_pcs.insert(instr.pc);
        tracing::debug!(
            "Processing instruction: pc={}, opcode={}",
            instr.pc,
            instr.opcode
        );

        // Collect jump targets for PUSHn followed by JUMP/JUMPI
        if let Some(prev) = prev_instr
            && prev.opcode.starts_with("PUSH") && matches!(instr.opcode.as_str(), "JUMP" | "JUMPI")
                && let Some(imm) = &prev.imm
                    && let Ok(target_pc) = usize::from_str_radix(imm, 16) {
                        tracing::debug!("Found jump target: pc={}", target_pc);
                        static_jump_targets.push(target_pc);
                    }

        // 1. Split before a JUMPDEST only if current block is non-empty
        if instr.opcode == "JUMPDEST"
            && let Block::Body {
                instructions,
                start_pc,
                ..
            } = &cur_block
                && !instructions.is_empty() {
                    tracing::debug!(
                        "Splitting before JUMPDEST at pc={}: pushing block with start_pc={}, instructions={:?}",
                        instr.pc,
                        start_pc,
                        instructions.iter().map(|i| &i.opcode).collect::<Vec<_>>()
                    );
                    blocks.push(std::mem::replace(
                        &mut cur_block,
                        Block::Body {
                            start_pc: instr.pc,
                            instructions: Vec::new(),
                            max_stack: 0,
                        },
                    ));
                }

        // 2. Record the opcode
        if let Block::Body { instructions, .. } = &mut cur_block {
            instructions.push(instr.clone());
            tracing::debug!("Added opcode {} to cur_block", instr.opcode);
        }

        // 3. Seal after every terminal
        if matches!(
            instr.opcode.as_str(),
            "STOP" | "RETURN" | "REVERT" | "SELFDESTRUCT" | "INVALID" | "JUMP" | "JUMPI"
        ) {
            let finished = std::mem::replace(
                &mut cur_block,
                Block::Body {
                    start_pc: instr.pc + 1,
                    instructions: Vec::new(),
                    max_stack: 0,
                },
            );
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &finished
            {
                tracing::debug!(
                    "Sealing terminal opcode {} at pc={}: pushing block with start_pc={}, instructions={:?}",
                    instr.opcode,
                    instr.pc,
                    start_pc,
                    instructions.iter().map(|i| &i.opcode).collect::<Vec<_>>()
                );
            }
            blocks.push(finished);
            prev_instr = None;
            continue;
        }

        prev_instr = Some(instr);
    }

    // 4. Push trailing non-empty block
    if let Block::Body {
        instructions,
        start_pc,
        ..
    } = &cur_block
    {
        tracing::debug!(
            "Checking trailing block: start_pc={}, instructions={:?}",
            start_pc,
            instructions.iter().map(|i| &i.opcode).collect::<Vec<_>>()
        );
        if !instructions.is_empty() {
            tracing::debug!(
                "Pushing trailing block with {} instructions",
                instructions.len()
            );
            blocks.push(cur_block);
        } else {
            tracing::debug!("Skipping empty trailing block");
        }
    }

    // 5. Create blocks for static jump targets at valid PCs that are JUMPDEST
    for tgt in &static_jump_targets {
        if valid_pcs.contains(tgt)
            && *tgt < bytecode.len()
            && bytecode[*tgt] == 0x5b // JUMPDEST opcode
            && blocks.iter().all(|b| {
                if let Block::Body { start_pc, .. } = b {
                    *start_pc != *tgt
                } else {
                    true
                }
            })
        {
            tracing::debug!("Creating block for jump target at pc={}", tgt);
            blocks.push(Block::Body {
                start_pc: *tgt,
                instructions: Vec::new(),
                max_stack: 0,
            });
        } else {
            tracing::debug!("Skipping invalid jump target at pc={}", tgt);
        }
    }

    tracing::debug!(
        "Finished splitting: {} blocks created: {:?}",
        blocks.len(),
        blocks
            .iter()
            .map(|b| {
                if let Block::Body {
                    start_pc,
                    instructions,
                    ..
                } = b
                {
                    (
                        start_pc,
                        instructions.iter().map(|i| &i.opcode).collect::<Vec<_>>(),
                    )
                } else {
                    unreachable!("Only Body blocks are pushed");
                }
            })
            .collect::<Vec<_>>()
    );

    if blocks.is_empty() {
        tracing::debug!("No blocks created, returning NoEntryBlock");
        return Err(CfgIrError::NoEntryBlock);
    }
    Ok(blocks)
}

/// Type alias for the return type of `build_edges`.
type BuildEdgesResult = Result<
    (
        Vec<(NodeIndex, NodeIndex, EdgeType)>,
        HashMap<usize, NodeIndex>,
    ),
    CfgIrError,
>;

/// Builds edges between blocks based on control flow.
///
/// Constructs edges for the CFG by analyzing instruction sequences and control flow instructions
/// (e.g., JUMP, JUMPI, STOP). Connects blocks with appropriate edge types (Fallthrough, Jump,
/// BranchTrue, BranchFalse) and maps program counters to block indices.
///
/// # Arguments
/// * `blocks` - Vector of blocks from `split_blocks`.
/// * `instructions` - Decoded EVM instructions.
/// * `cfg` - The CFG graph to populate with nodes and edges.
///
/// # Returns
/// A `Result` containing a tuple of edge definitions and a PC-to-block mapping, or a `CfgIrError`.
fn build_edges(
    blocks: &[Block],
    _instructions: &[Instruction],
    cfg: &mut DiGraph<Block, EdgeType>,
) -> BuildEdgesResult {
    let mut edges = Vec::new();
    let mut pc_to_block = HashMap::new();
    let mut node_map = HashMap::new();

    // Add body blocks to the graph
    for block in blocks {
        if let Block::Body {
            start_pc,
            instructions,
            max_stack,
        } = block
        {
            let idx = cfg.add_node(Block::Body {
                start_pc: *start_pc,
                instructions: instructions.clone(),
                max_stack: *max_stack,
            });
            node_map.insert(*start_pc, idx);
            pc_to_block.insert(*start_pc, idx);
        }
    }

    // Add edge from Entry to first block, collapsing if let
    if let Some(Block::Body { start_pc, .. }) = blocks.first()
        && let Some(&target) = node_map.get(start_pc) {
            edges.push((NodeIndex::new(0), target, EdgeType::Fallthrough));
        }

    // Build edges with translation through node_map
    for (i, block) in blocks.iter().enumerate() {
        if let Block::Body {
            start_pc,
            instructions,
            ..
        } = block
        {
            let start_idx = node_map[start_pc];
            let last_instr = instructions.last();
            if last_instr.is_none() {
                // Empty block (e.g., JUMPDEST target), connect to next block or Exit
                if i + 1 < blocks.len() {
                    if let Block::Body {
                        start_pc: next_pc, ..
                    } = &blocks[i + 1]
                    {
                        let next_idx = node_map[next_pc];
                        edges.push((start_idx, next_idx, EdgeType::Fallthrough));
                    }
                } else {
                    let exit_idx = NodeIndex::new(cfg.node_count() - 1);
                    edges.push((start_idx, exit_idx, EdgeType::Fallthrough));
                }
                continue;
            }
            let last_instr = last_instr.unwrap();
            match last_instr.opcode.as_str() {
                "JUMP" => {
                    if let Some(imm) = &last_instr.imm
                        && let Ok(target_pc) = usize::from_str_radix(imm, 16)
                            && let Some(&target) = node_map.get(&target_pc) {
                                edges.push((start_idx, target, EdgeType::Jump));
                            }
                    // Skip fall-through for unconditional jump
                    continue;
                }
                "JUMPI" => {
                    if let Some(imm) = &last_instr.imm
                        && let Ok(target_pc) = usize::from_str_radix(imm, 16)
                            && let Some(&target) = node_map.get(&target_pc) {
                                edges.push((start_idx, target, EdgeType::BranchTrue));
                            }
                    if i + 1 < blocks.len()
                        && let Block::Body {
                            start_pc: next_pc, ..
                        } = &blocks[i + 1]
                        {
                            let next_idx = node_map[next_pc];
                            edges.push((start_idx, next_idx, EdgeType::BranchFalse));
                        }
                }
                "STOP" | "RETURN" | "REVERT" | "SELFDESTRUCT" | "INVALID" => {
                    let exit_idx = NodeIndex::new(cfg.node_count() - 1);
                    edges.push((start_idx, exit_idx, EdgeType::Fallthrough));
                }
                _ => {
                    if i + 1 < blocks.len() {
                        if let Block::Body {
                            start_pc: next_pc, ..
                        } = &blocks[i + 1]
                        {
                            let next_idx = node_map[next_pc];
                            edges.push((start_idx, next_idx, EdgeType::Fallthrough));
                        }
                    } else {
                        let exit_idx = NodeIndex::new(cfg.node_count() - 1);
                        edges.push((start_idx, exit_idx, EdgeType::Fallthrough));
                    }
                }
            }
        }
    }

    Ok((edges, pc_to_block))
}

/// Assigns SSA values and computes stack heights for each block.
///
/// Walks through each block’s instructions to assign SSA `ValueId`s for stack operations (e.g.,
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

/// Returns the starting program counter for a block.
impl Block {
    fn start_pc(&self) -> usize {
        match self {
            Block::Body { start_pc, .. } => *start_pc,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decoder, detection, strip};
    use tokio;
    use tracing_subscriber;

    #[tokio::test]
    async fn test_build_cfg_ir_simple() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

        let cfg_ir =
            build_cfg_ir(&instructions, &sections, &bytes, report).expect("CFG builder failed");
        assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
        assert_eq!(cfg_ir.pc_to_block.len(), 2); // Two body blocks mapped
    }

    #[tokio::test]
    async fn test_build_cfg_ir_straight_line() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x600050"; // PUSH1 0x00, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

        let cfg_ir =
            build_cfg_ir(&instructions, &sections, &bytes, report).expect("CFG builder failed");
        assert_eq!(cfg_ir.cfg.node_count(), 3); // Entry, single block, Exit
        assert_eq!(cfg_ir.cfg.edge_count(), 2); // Entry->block, block->Exit
    }

    #[tokio::test]
    async fn test_build_cfg_ir_diamond() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

        let cfg_ir =
            build_cfg_ir(&instructions, &sections, &bytes, report).expect("CFG builder failed");
        assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
        assert_eq!(cfg_ir.cfg.edge_count(), 2); // Entry->block1, BranchFalse
    }

    #[tokio::test]
    async fn test_build_cfg_ir_loop() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x60005b6000"; // PUSH1 0x00, JUMPDEST, PUSH1 0x00
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

        let cfg_ir =
            build_cfg_ir(&instructions, &sections, &bytes, report).expect("CFG builder failed");
        assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
        assert_eq!(cfg_ir.cfg.edge_count(), 3); // Entry->block0, block0->block2, block2->Exit
    }

    #[tokio::test]
    async fn test_build_cfg_ir_malformed() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x6001"; // PUSH1 0x01, no terminal
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

        let cfg_ir =
            build_cfg_ir(&instructions, &sections, &bytes, report).expect("CFG builder succeeded");
        assert_eq!(cfg_ir.cfg.node_count(), 3); // Entry, lone block, Exit
    }
}
