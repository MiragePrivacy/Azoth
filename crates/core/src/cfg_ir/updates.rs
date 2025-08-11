//! CFG update operations

use crate::decoder::Instruction;
use azoth_utils::errors::CfgIrError;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

use super::{Block, EdgeType, CfgIrBundle, is_terminal_opcode};

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
                match last_instr.opcode.as_str() {
                    "JUMP" => {
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
                    "JUMPI" => {
                        // Conditional jump - create both true and false branches
                        if let Some(target_pc) = self.extract_jump_target(instructions) {
                            if let Some(&target_idx) = self.pc_to_block.get(&target_pc) {
                                self.cfg
                                    .add_edge(node_idx, target_idx, EdgeType::BranchTrue);
                                tracing::debug!(
                                    "Added JUMPI true edge: {} -> {} (PC: 0x{:x})",
                                    node_idx.index(),
                                    target_idx.index(),
                                    target_pc
                                );
                            }
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
                    if instructions[i].opcode.starts_with("PUSH")
                        && matches!(instructions[i + 1].opcode.as_str(), "JUMP" | "JUMPI")
                    {
                        if let Some(imm) = &instructions[i].imm {
                            if let Ok(old_target) = usize::from_str_radix(imm, 16) {
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
                                        (64 - (new_target as u64).leading_zeros()).div_ceil(8)
                                            as usize
                                    };
                                    let push_size = bytes_needed.clamp(1, 32);

                                    instructions[i].opcode = format!("PUSH{push_size}");
                                    instructions[i].imm = Some(format!(
                                        "{:0width$x}",
                                        new_target,
                                        width = push_size * 2
                                    ));

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

        if matches!(jump_instr.opcode.as_str(), "JUMP" | "JUMPI") {
            // Look for preceding PUSH instruction
            if last_idx > 0 {
                let push_instr = &instructions[last_idx - 1];
                if push_instr.opcode.starts_with("PUSH") {
                    if let Some(imm) = &push_instr.imm {
                        return usize::from_str_radix(imm, 16).ok();
                    }
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
                    if instructions[i].opcode.starts_with("PUSH")
                        && matches!(instructions[i + 1].opcode.as_str(), "JUMP" | "JUMPI")
                    {
                        if let Some(imm) = &instructions[i].imm {
                            if let Ok(old_target) = usize::from_str_radix(imm, 16) {
                                // Use pre-collected mapping instead of accessing self.cfg
                                if let Some(&new_target) = target_mappings.get(&old_target) {
                                    if new_target != old_target {
                                        // Update the PUSH instruction with new target
                                        let bytes_needed = if new_target == 0 {
                                            1
                                        } else {
                                            (64 - (new_target as u64).leading_zeros()).div_ceil(8)
                                                as usize
                                        };
                                        let push_size = bytes_needed.clamp(1, 32);

                                        instructions[i].opcode = format!("PUSH{push_size}");
                                        instructions[i].imm = Some(format!(
                                            "{:0width$x}",
                                            new_target,
                                            width = push_size * 2
                                        ));

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
                }
            }
        }

        Ok(())
    }
}
