use crate::util::{PassConfig, Transform};
use async_trait::async_trait;
use azoth_analysis::{collect_metrics, compare};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, SeedableRng};
use tracing::info;

/// Trait for running a sequence of obfuscation transforms on a CFG IR.
#[async_trait]
pub trait Pass {
    async fn run(
        &self,
        ir: &mut CfgIrBundle,
        passes: &[Box<dyn Transform>],
        cfg: &PassConfig,
        seed: u64,
    ) -> Result<(), TransformError>;
}

/// Default implementation of the Pass trait.
pub struct DefaultPass;

#[async_trait]
impl Pass for DefaultPass {
    async fn run(
        &self,
        ir: &mut CfgIrBundle,
        passes: &[Box<dyn Transform>],
        cfg: &PassConfig,
        seed: u64,
    ) -> Result<(), TransformError> {
        let mut rng = StdRng::seed_from_u64(seed);

        for pass in passes {
            let before = collect_metrics(ir, &ir.clean_report)?;
            let mut snapshot = ir.clone();

            let mutated = pass.apply(&mut snapshot, &mut rng).await?;
            if !mutated {
                continue;
            }

            let after = collect_metrics(&snapshot, &snapshot.clean_report)?;
            let delta = compare(&before, &after);

            let keep = delta >= cfg.accept_threshold || cfg.aggressive;
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
pub async fn run(
    ir: &mut CfgIrBundle,
    passes: &[Box<dyn Transform>],
    cfg: &PassConfig,
    seed: u64,
) -> Result<(), TransformError> {
    DefaultPass.run(ir, passes, cfg, seed).await
}
