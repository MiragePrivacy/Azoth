use crate::{PassConfig, Transform};
use azoth_analysis::{collect_metrics, compare};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, SeedableRng};
use tracing::info;

/// Trait for running a sequence of obfuscation transforms on a CFG IR.
pub trait Pass {
    fn run(
        &self,
        ir: &mut CfgIrBundle,
        passes: &[Box<dyn Transform>],
        cfg: &PassConfig,
        seed: u64,
    ) -> Result<(), TransformError>;
}

/// Default implementation of the Pass trait.
pub struct DefaultPass;

impl Pass for DefaultPass {
    fn run(
        &self,
        ir: &mut CfgIrBundle,
        passes: &[Box<dyn Transform>],
        config: &PassConfig,
        seed: u64,
    ) -> Result<(), TransformError> {
        let mut rng = StdRng::seed_from_u64(seed);

        for pass in passes {
            let before = collect_metrics(ir, &ir.clean_report)?;
            let mut snapshot = ir.clone();

            let mutated = pass.apply(&mut snapshot, &mut rng)?;
            if !mutated {
                continue;
            }

            let after = collect_metrics(&snapshot, &snapshot.clean_report)?;
            let delta = compare(&before, &after);

            let keep = delta >= config.accept_threshold || config.aggressive;
            info!(
                "{:>14} Δ{:+.2} {}",
                pass.name(),
                delta,
                if keep { "✓" } else { "×" }
            );

            if keep {
                *ir = snapshot;
            }
        }
        Ok(())
    }
}

/// Convenience function to run the default pass.
pub fn run(
    ir: &mut CfgIrBundle,
    passes: &[Box<dyn Transform>],
    cfg: &PassConfig,
    seed: u64,
) -> Result<(), TransformError> {
    DefaultPass.run(ir, passes, cfg, seed)
}
