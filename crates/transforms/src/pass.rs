use crate::{PassConfig, Transform};
use azoth_analysis::{collect_metrics, compare};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_utils::errors::TransformError;
use azoth_utils::seed::Seed;
use tracing::info;

/// Trait for running a sequence of obfuscation transforms on a CFG IR.
pub trait Pass {
    fn run(
        &self,
        ir: &mut CfgIrBundle,
        passes: &[Box<dyn Transform>],
        cfg: &PassConfig,
        seed: &Seed,
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
        seed: &Seed,
    ) -> Result<(), TransformError> {
        let mut rng = seed.create_deterministic_rng();

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
    seed: &Seed,
) -> Result<(), TransformError> {
    DefaultPass.run(ir, passes, cfg, seed)
}
