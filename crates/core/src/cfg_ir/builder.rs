//! Core CFG construction logic

use crate::decoder::Instruction;
use crate::detection::Section;
use crate::{is_block_ending_opcode, is_terminal_opcode};
use azoth_utils::errors::CfgIrError;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

use super::{Block, EdgeType, CfgIrBundle, collect_jump_targets, validate_jump_targets, create_blocks_for_targets, assign_ssa_values};

/// Type alias for the return type of `build_edges`.
type BuildEdgesResult = Result<
    (
        Vec<(NodeIndex, NodeIndex, EdgeType)>,
        HashMap<usize, NodeIndex>,
    ),
    CfgIrError,
>;

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
/// let (cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false).await.unwrap();
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
        selector_mapping: None, // Initially empty, set by transforms
    })
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

    let mut valid_pcs = HashSet::new();

    tracing::debug!(
        "Starting block splitting with {} instructions",
        instructions.len()
    );

    // Collect jump targets first
    let static_jump_targets = collect_jump_targets(instructions);

    for instr in instructions {
        valid_pcs.insert(instr.pc);
        tracing::debug!(
            "Processing instruction: pc={}, opcode={}",
            instr.pc,
            instr.opcode
        );

        // 1. Split before a JUMPDEST only if current block is non-empty
        if instr.opcode == "JUMPDEST" {
            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &cur_block
            {
                if !instructions.is_empty() {
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
            }
        }

        // 2. Record the opcode
        if let Block::Body { instructions, .. } = &mut cur_block {
            instructions.push(instr.clone());
            tracing::debug!("Added opcode {} to cur_block", instr.opcode);
        }

        // 3. Seal after every block-ending instruction
        if is_block_ending_opcode(&instr.opcode) {
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
                    "Sealing block-ending opcode {} at pc={}: pushing block with start_pc={}, instructions={:?}",
                    instr.opcode,
                    instr.pc,
                    start_pc,
                    instructions.iter().map(|i| &i.opcode).collect::<Vec<_>>()
                );
            }
            blocks.push(finished);
            continue;
        }
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

    // 5. Create blocks for validated jump targets
    let validated_targets =
        validate_jump_targets(&static_jump_targets, &valid_pcs, bytecode, &blocks);
    let target_blocks = create_blocks_for_targets(&validated_targets);
    blocks.extend(target_blocks);

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
    if let Some(Block::Body { start_pc, .. }) = blocks.first() {
        if let Some(&target) = node_map.get(start_pc) {
            edges.push((NodeIndex::new(0), target, EdgeType::Fallthrough));
        }
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
                    if let Some(imm) = &last_instr.imm {
                        if let Ok(target_pc) = usize::from_str_radix(imm, 16) {
                            if let Some(&target) = node_map.get(&target_pc) {
                                edges.push((start_idx, target, EdgeType::Jump));
                            }
                        }
                    }
                    // Skip fall-through for unconditional jump
                    continue;
                }
                "JUMPI" => {
                    if let Some(imm) = &last_instr.imm {
                        if let Ok(target_pc) = usize::from_str_radix(imm, 16) {
                            if let Some(&target) = node_map.get(&target_pc) {
                                edges.push((start_idx, target, EdgeType::BranchTrue));
                            }
                        }
                    }
                    if i + 1 < blocks.len() {
                        if let Block::Body {
                            start_pc: next_pc, ..
                        } = &blocks[i + 1]
                        {
                            let next_idx = node_map[next_pc];
                            edges.push((start_idx, next_idx, EdgeType::BranchFalse));
                        }
                    }
                }
                _ if is_terminal_opcode(&last_instr.opcode) => {
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
