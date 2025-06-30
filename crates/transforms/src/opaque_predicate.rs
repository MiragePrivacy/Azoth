use crate::util::{PassConfig, Transform};
use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
use bytecloak_core::decoder::Instruction;
use bytecloak_core::Opcode;
use bytecloak_utils::errors::TransformError;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rand::prelude::SliceRandom;
use rand::{rngs::StdRng, Rng};
use sha3::{Digest, Keccak256};
use tracing::debug;

/// Injects opaque predicates to increase control flow complexity and potency.
pub struct OpaquePredicate {
    config: PassConfig,
}

impl OpaquePredicate {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    fn generate_constant(&self, seed: u64) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(seed.to_le_bytes());
        hasher.finalize().into()
    }

    fn is_non_terminal(&self, instr: &Instruction) -> bool {
        !Opcode::is_control_flow(&match instr.opcode.as_str() {
            "STOP" => Opcode::STOP,
            "RETURN" => Opcode::RETURN,
            "REVERT" => Opcode::REVERT,
            "SELFDESTRUCT" => Opcode::SELFDESTRUCT,
            "INVALID" => Opcode::INVALID,
            "JUMP" => Opcode::JUMP,
            "JUMPI" => Opcode::JUMPI,
            _ => Opcode::UNKNOWN(0),
        })
    }
}

#[async_trait]
impl Transform for OpaquePredicate {
    fn name(&self) -> &'static str {
        "OpaquePredicate"
    }

    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        let mut changed = false;
        let max_opaque = self.config.max_opaque_ratio;
        let mut eligible_blocks: Vec<NodeIndex> = ir
            .cfg
            .node_indices()
            .filter(|&n| {
                if let Block::Body { instructions, .. } = &ir.cfg[n] {
                    instructions
                        .last()
                        .is_some_and(|instr| self.is_non_terminal(instr))
                } else {
                    false
                }
            })
            .collect();

        let max_predicates = ((eligible_blocks.len() as f32) * max_opaque).ceil() as usize;
        if max_predicates == 0 || eligible_blocks.is_empty() {
            return Ok(false);
        }
        let predicate_count = rng.random_range(1..=max_predicates.min(eligible_blocks.len()));
        eligible_blocks.shuffle(rng);
        let selected: Vec<NodeIndex> = eligible_blocks.into_iter().take(predicate_count).collect();

        for block_id in selected {
            let original_fallthrough = ir
                .cfg
                .edges_directed(block_id, petgraph::Outgoing)
                .find(|e| *e.weight() == EdgeType::Fallthrough)
                .map(|e| e.target());

            let true_start_pc = ir.pc_to_block.keys().max().map_or(0, |&pc| pc + 1);
            let false_start_pc = true_start_pc + 1;

            let true_label = ir.cfg.add_node(Block::Body {
                start_pc: true_start_pc,
                instructions: vec![Instruction {
                    pc: true_start_pc,
                    opcode: Opcode::JUMPDEST.to_string(),
                    imm: None,
                }],
                max_stack: 0,
            });

            let false_label = ir.cfg.add_node(Block::Body {
                start_pc: false_start_pc,
                instructions: vec![
                    Instruction {
                        pc: false_start_pc,
                        opcode: Opcode::JUMPDEST.to_string(),
                        imm: None,
                    },
                    Instruction {
                        pc: false_start_pc + 1,
                        opcode: Opcode::PUSH(1).to_string(),
                        imm: Some("00".to_string()),
                    },
                    Instruction {
                        pc: false_start_pc + 2,
                        opcode: Opcode::JUMP.to_string(),
                        imm: Some(
                            original_fallthrough
                                .map(|n| {
                                    if let Block::Body { start_pc, .. } = &ir.cfg[n] {
                                        format!("{:x}", start_pc)
                                    } else {
                                        "0".to_string()
                                    }
                                })
                                .unwrap_or("0".to_string()),
                        ),
                    },
                ],
                max_stack: 1,
            });

            if let Block::Body { instructions, .. } = &mut ir.cfg[block_id] {
                let seed = rng.random::<u64>();
                let constant = self.generate_constant(seed);
                let constant_hex = hex::encode(constant);
                instructions.extend(vec![
                    Instruction {
                        pc: 0,
                        opcode: Opcode::PUSH(32).to_string(),
                        imm: Some(constant_hex.clone()),
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::PUSH(32).to_string(),
                        imm: Some(constant_hex),
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::EQ.to_string(),
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::PUSH(2).to_string(),
                        imm: Some(format!("{:x}", true_start_pc)),
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::JUMPI.to_string(),
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::JUMPDEST.to_string(),
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        opcode: Opcode::JUMP.to_string(),
                        imm: Some(format!("{:x}", false_start_pc)),
                    },
                ]);
            }

            if let Some(target) = original_fallthrough {
                ir.cfg
                    .remove_edge(ir.cfg.find_edge(block_id, target).unwrap());
            }
            ir.cfg.add_edge(block_id, true_label, EdgeType::BranchTrue);
            ir.cfg
                .add_edge(block_id, false_label, EdgeType::BranchFalse);
            if let Some(target) = original_fallthrough {
                ir.cfg.add_edge(false_label, target, EdgeType::Jump);
                ir.cfg.add_edge(true_label, target, EdgeType::Fallthrough);
            }

            changed = true;
        }

        if changed {
            debug!("Inserted {} opaque predicates", predicate_count);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecloak_analysis::collect_metrics;
    use bytecloak_core::{cfg_ir, decoder, detection, strip};
    use rand::SeedableRng;
    use tokio;

    #[tokio::test]
    async fn test_opaque_predicate_adds_blocks() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x6001600260016003"; // PUSH1 0x01, PUSH1 0x02, PUSH1 0x01, PUSH1 0x03
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report).unwrap();

        let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let config = PassConfig {
            max_opaque_ratio: 0.5, // Ensure max_predicates > 0
            ..Default::default()
        };
        let transform = OpaquePredicate::new(config);
        let changed = transform.apply(&mut cfg_ir, &mut rng).await.unwrap();
        assert!(changed, "OpaquePredicate should insert predicates");
        let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        assert!(
            after.block_cnt > before.block_cnt,
            "Block count should increase"
        );
    }
}
