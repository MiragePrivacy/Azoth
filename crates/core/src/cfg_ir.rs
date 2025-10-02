use crate::Opcode;
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
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

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
    /// Detected bytecode sections (Init, Runtime, Auxdata, etc.)
    pub sections: Vec<crate::detection::Section>,
    /// Mapping of original function selectors to obfuscated tokens.
    /// Only populated when token-based dispatcher transform is applied.
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
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
/// * `clean_report` - Report from `strip.rs` for reassembly.
///
/// # Returns
/// A `Result` containing the `CfgIrBundle` or a `CfgIrError` if construction fails.
///
/// # Examples
/// ```rust,ignore
/// let bytecode = hex::decode("6001600155").unwrap();
/// let (cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false).await.unwrap();
/// assert!(cfg_ir.cfg.node_count() >= 2);
/// ```
pub fn build_cfg_ir(
    instructions: &[Instruction],
    sections: &[Section],
    clean_report: crate::strip::CleanReport,
) -> Result<CfgIrBundle, CfgIrError> {
    tracing::debug!(
        "Starting CFG-IR construction with {} instructions",
        instructions.len()
    );

    // Step 1: Block splitter
    let blocks = split_blocks(instructions)?;
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
        sections: sections.to_vec(),
        selector_mapping: None, // Initially empty, set by transforms
    })
}

impl CfgIrBundle {
    /// Replaces the body of the CFG with new instructions, rebuilding the CFG and PC mapping.
    ///
    /// # Arguments
    /// * `instructions` - The new instructions to process.
    /// * `sections` - Detected sections for the new bytecode.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CfgIrError` if rebuilding fails.
    pub fn replace_body(
        &mut self,
        instructions: Vec<Instruction>,
        sections: &[Section],
    ) -> Result<(), CfgIrError> {
        let clean_report = self.clean_report.clone();
        let selector_mapping = self.selector_mapping.clone(); // Preserve mapping
        let new_bundle = build_cfg_ir(&instructions, sections, clean_report)?;

        self.cfg = new_bundle.cfg;
        self.pc_to_block = new_bundle.pc_to_block;
        self.clean_report = new_bundle.clean_report;
        self.sections = new_bundle.sections;
        self.selector_mapping = selector_mapping; // Restore mapping

        Ok(())
    }
}

fn split_blocks(instructions: &[Instruction]) -> Result<Vec<Block>, CfgIrError> {
    let mut blocks = Vec::new();
    let mut cur_block = Block::Body {
        start_pc: 0,
        instructions: Vec::new(),
        max_stack: 0,
    };

    // Collect all JUMPDEST locations from bytecode
    let jumpdest_pcs: HashSet<usize> = instructions
        .iter()
        .filter(|i| matches!(Opcode::from_str(&i.opcode), Ok(Opcode::JUMPDEST)))
        .map(|i| i.pc)
        .collect();

    tracing::debug!(
        "Starting block splitting with {} instructions, {} JUMPDESTs",
        instructions.len(),
        jumpdest_pcs.len()
    );

    for instr in instructions {
        let opcode = match Opcode::from_str(&instr.opcode) {
            Ok(op) => op,
            Err(_) => {
                // Unknown opcode, add to current block and continue
                if let Block::Body { instructions, .. } = &mut cur_block {
                    instructions.push(instr.clone());
                }
                continue;
            }
        };

        // always start new block at JUMPDEST, even if current is empty
        if matches!(opcode, Opcode::JUMPDEST) {
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &cur_block
                && !instructions.is_empty()
            {
                tracing::debug!(
                    "Sealing block before JUMPDEST at pc={:#x} (prev block start={:#x})",
                    instr.pc,
                    start_pc
                );
                blocks.push(std::mem::take(&mut cur_block));
            }

            // Start fresh block AT the JUMPDEST PC
            cur_block = Block::Body {
                start_pc: instr.pc,
                instructions: vec![instr.clone()],
                max_stack: 0,
            };

            tracing::debug!("Started new block at JUMPDEST pc={:#x}", instr.pc);
            continue;
        }

        // Add instruction to current block
        if let Block::Body { instructions, .. } = &mut cur_block {
            instructions.push(instr.clone());
        }

        // terminate both JUMP and JUMPI end blocks
        let is_branch = matches!(opcode, Opcode::JUMP | Opcode::JUMPI);
        let is_terminal = is_terminal_opcode(&instr.opcode);

        if is_branch || is_terminal {
            let finished = std::mem::replace(
                &mut cur_block,
                Block::Body {
                    start_pc: instr.pc + 1,
                    instructions: Vec::new(),
                    max_stack: 0,
                },
            );

            if let Block::Body { start_pc, .. } = &finished {
                tracing::debug!(
                    "Sealed block ending with {} at pc={:#x} (block start={:#x})",
                    instr.opcode,
                    instr.pc,
                    start_pc
                );
            }
            blocks.push(finished);
            continue;
        }
    }

    // Push trailing non-empty block
    if let Block::Body { instructions, .. } = &cur_block
        && !instructions.is_empty()
    {
        tracing::debug!(
            "Pushing trailing block with {} instructions",
            instructions.len()
        );
        blocks.push(cur_block);
    }

    // CANONICALIZATION: verify every JUMPDEST is a block start
    let block_starts: HashSet<usize> = blocks
        .iter()
        .filter_map(|b| {
            if let Block::Body { start_pc, .. } = b {
                Some(*start_pc)
            } else {
                None
            }
        })
        .collect();

    let orphaned_jumpdests: Vec<_> = jumpdest_pcs
        .iter()
        .filter(|pc| !block_starts.contains(pc))
        .collect();

    if !orphaned_jumpdests.is_empty() {
        tracing::error!(
            "Found {} JUMPDESTs not at block starts: {:?}",
            orphaned_jumpdests.len(),
            orphaned_jumpdests
        );
        return Err(CfgIrError::InvalidBlockStructure(format!(
            "JUMPDESTs not aligned with block starts: {:?}",
            orphaned_jumpdests
        )));
    }

    tracing::debug!(
        "Block splitting complete: {} blocks, all {} JUMPDESTs are block starts",
        blocks.len(),
        jumpdest_pcs.len()
    );

    if blocks.is_empty() {
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

    // Add body blocks to graph
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

    // Edge from Entry to first block
    if let Some(Block::Body { start_pc, .. }) = blocks.first()
        && let Some(&target) = node_map.get(start_pc)
    {
        edges.push((NodeIndex::new(0), target, EdgeType::Fallthrough));
    }

    // Build edges using proper jump target extraction
    for (i, block) in blocks.iter().enumerate() {
        if let Block::Body {
            start_pc,
            instructions,
            ..
        } = block
        {
            let start_idx = node_map[start_pc];

            if instructions.is_empty() {
                // Empty block (shouldn't happen after our fixes, but handle it)
                if i + 1 < blocks.len()
                    && let Block::Body {
                        start_pc: next_pc, ..
                    } = &blocks[i + 1]
                {
                    let next_idx = node_map[next_pc];
                    edges.push((start_idx, next_idx, EdgeType::Fallthrough));
                }
                continue;
            }

            let last_instr = &instructions[instructions.len() - 1];

            let last_opcode = Opcode::from_str(&last_instr.opcode).ok();
            match last_opcode {
                Some(Opcode::JUMP) => {
                    // C) Extract target from [PUSHx imm][JUMP] pattern
                    if let Some(target_pc) = extract_jump_target_from_block(instructions) {
                        if let Some(&target_idx) = node_map.get(&target_pc) {
                            edges.push((start_idx, target_idx, EdgeType::Jump));
                            tracing::debug!(
                                "JUMP edge: block {} (pc={:#x}) -> block {} (pc={:#x})",
                                start_idx.index(),
                                start_pc,
                                target_idx.index(),
                                target_pc
                            );
                        } else {
                            tracing::warn!(
                                "JUMP target {:#x} not found in node_map (from block pc={:#x})",
                                target_pc,
                                start_pc
                            );
                        }
                    }
                    // No fallthrough for unconditional jump
                    continue;
                }
                Some(Opcode::JUMPI) => {
                    // C) Extract target from [PUSHx imm][JUMPI] pattern
                    if let Some(target_pc) = extract_jump_target_from_block(instructions)
                        && let Some(&target_idx) = node_map.get(&target_pc)
                    {
                        edges.push((start_idx, target_idx, EdgeType::BranchTrue));
                        tracing::debug!(
                            "JUMPI true edge: block {} -> block {} (target={:#x})",
                            start_idx.index(),
                            target_idx.index(),
                            target_pc
                        );
                    }

                    // False branch: next sequential block
                    if i + 1 < blocks.len()
                        && let Block::Body {
                            start_pc: next_pc, ..
                        } = &blocks[i + 1]
                    {
                        let next_idx = node_map[next_pc];
                        edges.push((start_idx, next_idx, EdgeType::BranchFalse));
                        tracing::debug!(
                            "JUMPI false edge: block {} -> block {}",
                            start_idx.index(),
                            next_idx.index()
                        );
                    }
                }
                _ if is_terminal_opcode(&last_instr.opcode) => {
                    let exit_idx = NodeIndex::new(cfg.node_count() - 1);
                    edges.push((start_idx, exit_idx, EdgeType::Fallthrough));
                }
                _ => {
                    // Fallthrough to next block
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

/// Extract jump target from [PUSHx imm][JUMP/JUMPI] pattern at end of block
fn extract_jump_target_from_block(instructions: &[Instruction]) -> Option<usize> {
    if instructions.len() < 2 {
        return None;
    }

    let last_idx = instructions.len() - 1;
    let jump_instr = &instructions[last_idx];

    let jump_opcode = Opcode::from_str(&jump_instr.opcode).ok()?;
    if !matches!(jump_opcode, Opcode::JUMP | Opcode::JUMPI) {
        return None;
    }

    // Look for preceding PUSH
    let push_instr = &instructions[last_idx - 1];
    let push_opcode = Opcode::from_str(&push_instr.opcode).ok()?;
    if matches!(push_opcode, Opcode::PUSH(_) | Opcode::PUSH0)
        && let Some(imm) = &push_instr.imm
    {
        return usize::from_str_radix(imm, 16).ok();
    }

    None
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
                if let Ok(opcode) = Opcode::from_str(&instr.opcode) {
                    if matches!(opcode, Opcode::PUSH(_) | Opcode::PUSH0 | Opcode::DUP(_)) {
                        cur_depth += 1;
                    } else if matches!(opcode, Opcode::POP) && stack.pop().is_some() {
                        cur_depth = cur_depth.saturating_sub(1);
                    }
                    if matches!(opcode, Opcode::PUSH(_) | Opcode::PUSH0) {
                        stack.push(ValueId(value_id));
                        ssa_map.insert(instr.pc, ValueId(value_id));
                        value_id += 1;
                    }
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

impl CfgIrBundle {
    /// Reindexes all PC values after bytecode modifications.
    ///
    /// This method recalculates program counters for all instructions in all blocks,
    /// maintaining the correct sequential order and updating the pc_to_block mapping.
    /// Should be called after any transform that changes instruction sequences.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CfgIrError` if reindexing fails.
    pub fn reindex_pcs(&mut self) -> Result<(), CfgIrError> {
        tracing::debug!(
            "Starting PC reindexing for {} blocks",
            self.cfg.node_count()
        );

        let mut new_pc_to_block = HashMap::new();
        let mut current_pc = 0;

        // Get all body blocks sorted by their original start_pc to maintain order
        let mut blocks_with_indices: Vec<_> = self
            .cfg
            .node_indices()
            .filter_map(|idx| {
                if let Block::Body { start_pc, .. } = &self.cfg[idx] {
                    Some((idx, *start_pc))
                } else {
                    None
                }
            })
            .collect();

        blocks_with_indices.sort_by_key(|(_, start_pc)| *start_pc);

        // Reindex each block's instructions
        for (node_idx, _) in blocks_with_indices {
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &mut self.cfg[node_idx]
            {
                let new_start_pc = current_pc;
                new_pc_to_block.insert(new_start_pc, node_idx);

                for instruction in instructions.iter_mut() {
                    instruction.pc = current_pc;
                    current_pc += instruction.byte_size(); // ← Much cleaner!
                }

                // Update block's start_pc
                *start_pc = new_start_pc;
                tracing::debug!(
                    "Reindexed block {}: new start_pc = 0x{:x}",
                    node_idx.index(),
                    new_start_pc
                );
            }
        }

        // Update the pc_to_block mapping
        self.pc_to_block = new_pc_to_block;

        // Patch jump immediates to point to new addresses
        self.patch_jump_immediates()?;

        tracing::debug!(
            "PC reindexing complete. Total bytecode size: {} bytes",
            current_pc
        );
        Ok(())
    }

    /// Rebuilds edges for a specific block after instruction modifications.
    ///
    /// Analyzes the block's instructions (especially the last instruction) to determine
    /// correct outgoing edges and updates the CFG accordingly. Handles JUMP, JUMPI,
    /// terminal instructions, and fallthrough cases.
    ///
    /// # Arguments
    /// * `node_idx` - The block whose edges need rebuilding
    ///
    /// # Returns
    /// A `Result` indicating success or a `CfgIrError` if edge rebuilding fails.
    pub fn rebuild_edges_for_block(&mut self, node_idx: NodeIndex) -> Result<(), CfgIrError> {
        tracing::debug!("Rebuilding edges for block {}", node_idx.index());

        // Remove all outgoing edges from this block
        let outgoing_edges: Vec<_> = self
            .cfg
            .edges_directed(node_idx, petgraph::Outgoing)
            .map(|e| e.id())
            .collect();

        for edge_id in outgoing_edges {
            self.cfg.remove_edge(edge_id);
        }

        // Analyze the block to determine new edges
        if let Some(Block::Body { instructions, .. }) = self.cfg.node_weight(node_idx) {
            let last_instr = instructions.last();

            if let Some(last_instr) = last_instr {
                let last_opcode = Opcode::from_str(&last_instr.opcode).ok();
                match last_opcode {
                    Some(Opcode::JUMP) => {
                        // Unconditional jump - find target and create Jump edge
                        if let Some(target_pc) = self.extract_jump_target(instructions) {
                            if let Some(&target_idx) = self.pc_to_block.get(&target_pc) {
                                self.cfg.add_edge(node_idx, target_idx, EdgeType::Jump);
                                tracing::debug!(
                                    "Added JUMP edge: {} -> {} (PC: 0x{:x})",
                                    node_idx.index(),
                                    target_idx.index(),
                                    target_pc
                                );
                            } else {
                                tracing::warn!(
                                    "JUMP target PC 0x{:x} not found in pc_to_block mapping",
                                    target_pc
                                );
                            }
                        }
                    }
                    Some(Opcode::JUMPI) => {
                        // Conditional jump - create both true and false branches
                        if let Some(target_pc) = self.extract_jump_target(instructions)
                            && let Some(&target_idx) = self.pc_to_block.get(&target_pc)
                        {
                            self.cfg
                                .add_edge(node_idx, target_idx, EdgeType::BranchTrue);
                            tracing::debug!(
                                "Added JUMPI true edge: {} -> {} (PC: 0x{:x})",
                                node_idx.index(),
                                target_idx.index(),
                                target_pc
                            );
                        }

                        // Add false branch to next sequential block (only if it doesn't already exist)
                        if let Some(next_idx) = self.find_next_sequential_block(node_idx) {
                            // Check if edge already exists to avoid duplicates
                            let edge_exists = self
                                .cfg
                                .edges_directed(node_idx, petgraph::Outgoing)
                                .any(|e| {
                                    e.target() == next_idx && *e.weight() == EdgeType::BranchFalse
                                });

                            if !edge_exists {
                                self.cfg.add_edge(node_idx, next_idx, EdgeType::BranchFalse);
                                tracing::debug!(
                                    "Added JUMPI false edge: {} -> {}",
                                    node_idx.index(),
                                    next_idx.index()
                                );
                            }
                        }
                    }
                    // Use centralized helper for terminal opcodes
                    _ if is_terminal_opcode(&last_instr.opcode) => {
                        // Terminal instructions - connect to Exit node
                        let exit_idx = self.find_exit_node();
                        self.cfg.add_edge(node_idx, exit_idx, EdgeType::Fallthrough);
                        tracing::debug!("Added terminal edge: {} -> Exit", node_idx.index());
                    }
                    _ => {
                        // Non-terminal instruction - fallthrough to next block
                        if let Some(next_idx) = self.find_next_sequential_block(node_idx) {
                            self.cfg.add_edge(node_idx, next_idx, EdgeType::Fallthrough);
                            tracing::debug!(
                                "Added fallthrough edge: {} -> {}",
                                node_idx.index(),
                                next_idx.index()
                            );
                        } else {
                            // No next block - connect to Exit
                            let exit_idx = self.find_exit_node();
                            self.cfg.add_edge(node_idx, exit_idx, EdgeType::Fallthrough);
                        }
                    }
                }
            } else {
                // Empty block - fallthrough to next block or Exit
                if let Some(next_idx) = self.find_next_sequential_block(node_idx) {
                    self.cfg.add_edge(node_idx, next_idx, EdgeType::Fallthrough);
                } else {
                    let exit_idx = self.find_exit_node();
                    self.cfg.add_edge(node_idx, exit_idx, EdgeType::Fallthrough);
                }
            }
        }

        Ok(())
    }

    /// Updates jump targets throughout the CFG based on PC changes.
    ///
    /// Scans all blocks for PUSH + JUMP/JUMPI patterns and updates the immediate
    /// values to reflect new PC mappings after bytecode modifications.
    ///
    /// # Arguments
    /// * `pc_offset` - The offset to apply to jump targets (can be negative)
    /// * `region_start` - PC where changes began (targets before this are unchanged)
    /// * `pc_mapping` - Optional direct PC mapping for targets within changed regions
    ///
    /// # Returns
    /// A `Result` indicating success or a `CfgIrError` if target updates fail.
    pub fn update_jump_targets(
        &mut self,
        pc_offset: isize,
        region_start: usize,
        pc_mapping: Option<&HashMap<usize, usize>>,
    ) -> Result<(), CfgIrError> {
        tracing::debug!(
            "Updating jump targets: offset={:+}, region_start=0x{:x}",
            pc_offset,
            region_start
        );

        for node_idx in self.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body { instructions, .. } = &mut self.cfg[node_idx] {
                for i in 0..instructions.len().saturating_sub(1) {
                    // Look for PUSH followed by JUMP/JUMPI
                    let push_opcode = Opcode::from_str(&instructions[i].opcode).ok();
                    let next_opcode = Opcode::from_str(&instructions[i + 1].opcode).ok();
                    if matches!(push_opcode, Some(Opcode::PUSH(_) | Opcode::PUSH0))
                        && matches!(next_opcode, Some(Opcode::JUMP | Opcode::JUMPI))
                        && let Some(imm) = &instructions[i].imm
                        && let Ok(old_target) = usize::from_str_radix(imm, 16)
                    {
                        // Calculate new target using local logic to avoid borrowing self
                        let new_target = if let Some(mapping) = pc_mapping {
                            if let Some(&mapped_target) = mapping.get(&old_target) {
                                mapped_target
                            } else if old_target >= region_start {
                                if pc_offset >= 0 {
                                    old_target + (pc_offset as usize)
                                } else {
                                    old_target.saturating_sub((-pc_offset) as usize)
                                }
                            } else {
                                old_target
                            }
                        } else if old_target >= region_start {
                            if pc_offset >= 0 {
                                old_target + (pc_offset as usize)
                            } else {
                                old_target.saturating_sub((-pc_offset) as usize)
                            }
                        } else {
                            old_target
                        };

                        if new_target != old_target {
                            // Update the PUSH instruction with new target (inline logic)
                            let bytes_needed = if new_target == 0 {
                                1
                            } else {
                                (64 - (new_target as u64).leading_zeros()).div_ceil(8) as usize
                            };
                            let push_size = bytes_needed.clamp(1, 32);

                            instructions[i].opcode = format!("PUSH{push_size}");
                            instructions[i].imm =
                                Some(format!("{:0width$x}", new_target, width = push_size * 2));

                            tracing::debug!(
                                "Updated jump target: 0x{:x} -> 0x{:x}",
                                old_target,
                                new_target
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Extracts jump target from PUSH + JUMP/JUMPI pattern
    fn extract_jump_target(&self, instructions: &[Instruction]) -> Option<usize> {
        if instructions.len() < 2 {
            return None;
        }

        let last_idx = instructions.len() - 1;
        let jump_instr = &instructions[last_idx];

        let jump_opcode = Opcode::from_str(&jump_instr.opcode).ok()?;
        if matches!(jump_opcode, Opcode::JUMP | Opcode::JUMPI) {
            // Look for preceding PUSH instruction
            if last_idx > 0 {
                let push_instr = &instructions[last_idx - 1];
                let push_opcode = Opcode::from_str(&push_instr.opcode).ok()?;
                if matches!(push_opcode, Opcode::PUSH(_) | Opcode::PUSH0)
                    && let Some(imm) = &push_instr.imm
                {
                    return usize::from_str_radix(imm, 16).ok();
                }
            }
        }

        None
    }

    /// Finds the next sequential block after the given block
    fn find_next_sequential_block(&self, current_idx: NodeIndex) -> Option<NodeIndex> {
        if let Some(Block::Body {
            start_pc,
            instructions,
            ..
        }) = self.cfg.node_weight(current_idx)
        {
            // Calculate the end PC of the current block
            let end_pc = *start_pc
                + instructions
                    .iter()
                    .map(|instr| instr.byte_size())
                    .sum::<usize>();

            // Find block that starts at end_pc
            self.pc_to_block.get(&end_pc).copied()
        } else {
            None
        }
    }

    /// Finds the Exit node in the CFG
    fn find_exit_node(&mut self) -> NodeIndex {
        for idx in self.cfg.node_indices() {
            if matches!(self.cfg.node_weight(idx), Some(Block::Exit)) {
                return idx;
            }
        }
        // If no Exit node found, create one (shouldn't happen in well-formed CFG)
        self.cfg.add_node(Block::Exit)
    }

    /// Patches PUSH immediate values that target jump destinations after PC reindexing.
    fn patch_jump_immediates(&mut self) -> Result<(), CfgIrError> {
        tracing::debug!("Patching jump immediates after PC reindexing");

        // First, collect all the target mappings to avoid borrowing conflicts
        let mut target_mappings = HashMap::new();
        for node_idx in self.cfg.node_indices() {
            if let Some(Block::Body { start_pc, .. }) = self.cfg.node_weight(node_idx) {
                // Map old PC positions to new start_pc values
                for (&old_pc, &block_idx) in &self.pc_to_block {
                    if block_idx == node_idx {
                        target_mappings.insert(old_pc, *start_pc);
                    }
                }
            }
        }

        // Now patch the instructions
        for node_idx in self.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body { instructions, .. } = &mut self.cfg[node_idx] {
                for i in 0..instructions.len().saturating_sub(1) {
                    // Look for PUSH followed by JUMP/JUMPI
                    let push_opcode = Opcode::from_str(&instructions[i].opcode).ok();
                    let next_opcode = Opcode::from_str(&instructions[i + 1].opcode).ok();
                    if matches!(push_opcode, Some(Opcode::PUSH(_) | Opcode::PUSH0))
                        && matches!(next_opcode, Some(Opcode::JUMP | Opcode::JUMPI))
                        && let Some(imm) = &instructions[i].imm
                        && let Ok(old_target) = usize::from_str_radix(imm, 16)
                    {
                        // Use pre-collected mapping instead of accessing self.cfg
                        if let Some(&new_target) = target_mappings.get(&old_target)
                            && new_target != old_target
                        {
                            // Update the PUSH instruction with new target
                            let bytes_needed = if new_target == 0 {
                                1
                            } else {
                                (64 - (new_target as u64).leading_zeros()).div_ceil(8) as usize
                            };
                            let push_size = bytes_needed.clamp(1, 32);

                            instructions[i].opcode = format!("PUSH{push_size}");
                            instructions[i].imm =
                                Some(format!("{:0width$x}", new_target, width = push_size * 2));

                            tracing::debug!(
                                "Patched jump immediate: 0x{:x} -> 0x{:x}",
                                old_target,
                                new_target
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
