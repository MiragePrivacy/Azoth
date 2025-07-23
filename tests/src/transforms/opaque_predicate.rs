use azoth_analysis::collect_metrics;
use azoth_core::{cfg_ir, decoder, detection, strip};
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::{PassConfig, Transform};
use rand::rngs::StdRng;
use rand::SeedableRng;

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
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    assert!(changed, "OpaquePredicate should insert predicates");
    let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    assert!(
        after.block_cnt > before.block_cnt,
        "Block count should increase"
    );
}
