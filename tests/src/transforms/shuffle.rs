use azoth_analysis::collect_metrics;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[tokio::test]
async fn test_shuffle_reorders_blocks() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x60015b6002"; // PUSH1 0x01, JUMPDEST, PUSH1 0x02
    let mut cfg_ir = azoth_core::process_bytecode_to_cfg_only(bytecode, false)
        .await
        .unwrap();

    let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let transform = Shuffle;
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    assert!(changed, "Shuffle should reorder blocks");
    assert_eq!(
        before.byte_len, after.byte_len,
        "Byte length should not change"
    );
}
