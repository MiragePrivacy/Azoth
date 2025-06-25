use crate::util::{PassConfig, Transform};
use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle};
use bytecloak_core::decoder::Instruction;
use bytecloak_core::opcode::Opcode;
use bytecloak_utils::errors::TransformError;
use rand::{Rng, rngs::StdRng};
use tracing::debug;

/// Adds stack manipulation noise (DUP/SWAP) to increase stack depth and potency.
pub struct StackNoise {
    config: PassConfig,
}

impl StackNoise {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    fn dup_instruction(&self, n: u8, pc: usize) -> Instruction {
        Instruction {
            pc,
            opcode: format!("DUP{}", n),
            imm: None,
        }
    }
}

#[async_trait]
impl Transform for StackNoise {
    fn name(&self) -> &'static str {
        "StackNoise"
    }

    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        let mut changed = false;
        let max_noise = self.config.max_noise_ratio;

        for node in ir.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body {
                instructions,
                max_stack,
                start_pc,
                ..
            } = &mut ir.cfg[node]
            {
                if instructions.is_empty() || *max_stack < 2 {
                    continue;
                }
                if *max_stack + 2 > 1024 {
                    return Err(TransformError::StackOverflow);
                }

                let max_insertions = ((instructions.len() as f32) * max_noise).ceil() as usize;
                if max_insertions == 0 {
                    return Ok(false); // No insertions possible
                }
                let insert_count = rng.random_range(1..=max_insertions);
                for _ in 0..insert_count {
                    let insert_at = rng.random_range(0..=instructions.len());
                    let dup_n = rng.random_range(1..=3); // Randomize DUP1 to DUP3
                    let current_pc = *start_pc + instructions.len();
                    instructions.insert(insert_at, self.dup_instruction(dup_n, current_pc));
                    instructions.insert(insert_at + 1, self.dup_instruction(dup_n, current_pc + 1));
                    instructions.insert(
                        insert_at + 2,
                        Instruction {
                            pc: current_pc + 2,
                            opcode: Opcode::ADD.to_string(),
                            imm: None,
                        },
                    );
                    instructions.insert(
                        insert_at + 3,
                        Instruction {
                            pc: current_pc + 3,
                            opcode: Opcode::POP.to_string(),
                            imm: None,
                        },
                    );
                    *max_stack += 2;
                    changed = true;
                }
            }
        }

        if changed {
            debug!("Inserted stack noise in {} blocks", ir.cfg.node_count());
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
    async fn test_stack_noise_increases_stack_peak() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x60016002"; // PUSH1 0x01, PUSH1 0x02
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report).unwrap();

        let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let config = PassConfig {
            max_noise_ratio: 0.5, // Ensure max_insertions > 0
            ..Default::default()
        };
        let transform = StackNoise::new(config);
        let changed = transform.apply(&mut cfg_ir, &mut rng).await.unwrap();
        assert!(changed, "StackNoise should insert instructions");
        let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        assert!(
            after.max_stack_peak > before.max_stack_peak,
            "Stack peak should increase"
        );
        assert!(
            after.byte_len <= (before.byte_len as f32 * 1.05) as usize,
            "Size limit exceeded"
        );
    }
}
