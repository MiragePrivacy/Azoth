use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use azoth_transform::obfuscator::{
    obfuscate_bytecode, ObfuscationConfig, ObfuscationResult as PipelineResult,
};
use azoth_transform::{
    jump_address_transformer::JumpAddressTransformer, opaque_predicate::OpaquePredicate,
    shuffle::Shuffle, PassConfig, Transform,
};
use azoth_utils::seed::Seed;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info};

#[derive(Debug, Deserialize, Serialize)]
struct ObfuscateRequest {
    /// Raw bytecode as hex string (with or without 0x prefix)
    bytecode: String,
    /// Optional obfuscation options
    options: Option<ObfuscationOptions>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ObfuscationOptions {
    /// Enable instruction shuffling
    shuffle: Option<bool>,
    /// Enable opaque predicates
    opaque_predicates: Option<bool>,
    /// Enable jump address transformation
    jump_address_transform: Option<bool>,
    /// Custom seed for deterministic obfuscation
    seed: Option<String>,
    /// Obfuscation intensity (0.0 to 1.0)
    intensity: Option<f32>,
}

impl Default for ObfuscationOptions {
    fn default() -> Self {
        Self {
            shuffle: Some(true),
            opaque_predicates: Some(true),
            jump_address_transform: Some(true),
            seed: None,
            intensity: Some(0.5),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ObfuscateResponse {
    /// Obfuscated bytecode as hex string
    obfuscated_bytecode: String,
    /// Original bytecode length in bytes
    original_size: usize,
    /// Obfuscated bytecode length in bytes
    obfuscated_size: usize,
    /// Size increase percentage
    size_increase_percentage: f64,
    /// Gas cost analysis (if available)
    gas_analysis: Option<GasAnalysis>,
    /// Obfuscation metadata
    metadata: ObfuscationMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct GasAnalysis {
    original_gas_estimate: Option<u64>,
    obfuscated_gas_estimate: Option<u64>,
    gas_overhead_percentage: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ObfuscationMetadata {
    transforms_applied: Vec<String>,
    execution_time_ms: u64,
    blocks_created: usize,
    instructions_added: usize,
    unknown_opcodes_count: usize,
    size_limit_exceeded: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let app = Router::new()
        .route("/", get(health_check))
        .route("/obfuscate", post(obfuscate_bytecode_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("azoth API server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> ResponseJson<serde_json::Value> {
    ResponseJson(serde_json::json!({
        "status": "healthy",
        "service": "azoth-api",
        "version": env!("CARGO_PKG_VERSION"),
        "features": {
            "function_dispatcher": true,
            "shuffle": true,
            "opaque_predicates": true,
            "jump_address_transform": true,
        }
    }))
}

async fn obfuscate_bytecode_handler(
    Json(request): Json<ObfuscateRequest>,
) -> Result<ResponseJson<ObfuscateResponse>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let start_time = std::time::Instant::now();

    info!(
        "Received obfuscation request for bytecode: {}",
        &request.bytecode[..std::cmp::min(20, request.bytecode.len())]
    );

    // Normalize bytecode input
    let bytecode_hex = request.bytecode.trim_start_matches("0x");

    // Validate hex input
    if hex::decode(bytecode_hex).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                error: "Invalid hex bytecode".to_string(),
                details: Some("Bytecode must be valid hexadecimal".to_string()),
            }),
        ));
    }

    let options = request.options.unwrap_or_default();
    let input_bytecode = format!("0x{bytecode_hex}");

    match perform_obfuscation(&input_bytecode, &options).await {
        Ok(result) => {
            let execution_time = start_time.elapsed();

            // Calculate gas estimates using the same formula as the main workflow
            let original_gas = calculate_deployment_gas(&hex::decode(bytecode_hex).unwrap());
            let obfuscated_gas = calculate_deployment_gas(
                &hex::decode(result.obfuscated_bytecode.trim_start_matches("0x")).unwrap(),
            );
            let gas_overhead =
                ((obfuscated_gas as f64 - original_gas as f64) / original_gas as f64) * 100.0;

            let response = ObfuscateResponse {
                obfuscated_bytecode: result.obfuscated_bytecode,
                original_size: result.original_size,
                obfuscated_size: result.obfuscated_size,
                size_increase_percentage: result.size_increase_percentage,
                gas_analysis: Some(GasAnalysis {
                    original_gas_estimate: Some(original_gas),
                    obfuscated_gas_estimate: Some(obfuscated_gas),
                    gas_overhead_percentage: Some(gas_overhead),
                }),
                metadata: ObfuscationMetadata {
                    transforms_applied: result.metadata.transforms_applied,
                    execution_time_ms: execution_time.as_millis() as u64,
                    blocks_created: result.blocks_created,
                    instructions_added: result.instructions_added,
                    unknown_opcodes_count: result.unknown_opcodes_count,
                    size_limit_exceeded: result.metadata.size_limit_exceeded,
                },
            };

            info!(
                "Obfuscation completed in {}ms, size: {} -> {} bytes ({:.1}% increase)",
                execution_time.as_millis(),
                result.original_size,
                result.obfuscated_size,
                result.size_increase_percentage,
            );
            Ok(ResponseJson(response))
        }
        Err(e) => {
            error!("Obfuscation failed: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(ErrorResponse {
                    error: "Obfuscation failed".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

async fn perform_obfuscation(
    bytecode: &str,
    options: &ObfuscationOptions,
) -> Result<PipelineResult, Box<dyn std::error::Error + Send + Sync>> {
    // Configure transformation parameters
    let intensity = options.intensity.unwrap_or(0.5).clamp(0.0, 1.0);

    // Handle seed creation/parsing
    let seed = match &options.seed {
        Some(seed_str) => {
            // Try to parse as hex string
            Seed::from_hex(seed_str).map_err(|e| {
                format!("Invalid seed format: {e}. Expected 64-character hex string with or without 0x prefix")
            })?
        }
        None => Seed::generate(),
    };

    // Create transform pipeline based on options
    let mut transforms: Vec<Box<dyn Transform>> = Vec::new();

    // Add enabled transforms
    if options.shuffle.unwrap_or(true) {
        transforms.push(Box::new(Shuffle));
    }

    if options.opaque_predicates.unwrap_or(true) {
        transforms.push(Box::new(OpaquePredicate::new(PassConfig {
            max_opaque_ratio: intensity * 0.5,
            max_size_delta: intensity,
            aggressive: intensity > 0.7,
            ..Default::default()
        })));
    }

    if options.jump_address_transform.unwrap_or(true) {
        transforms.push(Box::new(JumpAddressTransformer::new(PassConfig {
            max_size_delta: intensity,
            aggressive: intensity > 0.7,
            ..Default::default()
        })));
    }

    let config = ObfuscationConfig {
        seed: seed.clone(),
        transforms,
        pass_config: PassConfig {
            accept_threshold: 0.0,
            aggressive: intensity > 0.7,
            max_size_delta: intensity,
            max_opaque_ratio: intensity * 0.5,
        },
        preserve_unknown_opcodes: true,
    };

    let result = obfuscate_bytecode(bytecode, config).await?;
    Ok(result)
}

/// Calculate deployment gas using EVM formula: 21000 + 4*zeros + 16*nonzeros
fn calculate_deployment_gas(bytecode: &[u8]) -> u64 {
    let zero_bytes = bytecode.iter().filter(|&&b| b == 0).count() as u64;
    let non_zero_bytes = (bytecode.len() as u64) - zero_bytes;
    21_000 + (zero_bytes * 4) + (non_zero_bytes * 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_check() {
        let app = Router::new().route("/", get(health_check));
        let server = TestServer::new(app).unwrap();

        let response = server.get("/").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<serde_json::Value>();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["service"], "azoth-api");
    }

    #[tokio::test]
    async fn test_obfuscate_with_transforms_enabled() {
        // Initialize tracing for debugging
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init()
            .ok();

        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode_handler));
        let server = TestServer::new(app).unwrap();

        let bytecode = "0x6004565b60016000555b60026000555b6003600055";
        tracing::debug!(
            "Testing simple bytecode with transforms enabled: {}",
            bytecode
        );

        let request = ObfuscateRequest {
            bytecode: bytecode.to_string(),
            options: Some(ObfuscationOptions {
                shuffle: Some(true),            // Enable shuffle
                opaque_predicates: Some(false), // Keep others disabled for simpler test
                jump_address_transform: Some(false),
                seed: Some(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        .to_string(),
                ),
                intensity: Some(0.5),
            }),
        };

        tracing::debug!("Request options: {:?}", request.options);

        let response = server.post("/obfuscate").json(&request).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<ObfuscateResponse>();
        tracing::debug!("Response body: {:?}", body);

        assert!(body.obfuscated_bytecode.starts_with("0x"));
        assert!(body.original_size > 0);

        // With shuffle enabled, the bytecode should change (even without dispatcher)
        assert_ne!(
            body.obfuscated_bytecode, bytecode,
            "Bytecode should change when shuffle is enabled"
        );
    }

    #[tokio::test]
    async fn test_invalid_bytecode() {
        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode_handler));
        let server = TestServer::new(app).unwrap();

        let request = ObfuscateRequest {
            bytecode: "0xZZZZ".to_string(), // Invalid hex
            options: None,
        };

        let response = server.post("/obfuscate").json(&request).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        let body = response.json::<ErrorResponse>();
        assert!(body.error.contains("Invalid hex bytecode"));
    }

    #[tokio::test]
    async fn test_deterministic_obfuscation() {
        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode_handler));
        let server = TestServer::new(app).unwrap();

        let fixed_seed = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let request = ObfuscateRequest {
            bytecode: "0x6001600255".to_string(),
            options: Some(ObfuscationOptions {
                seed: Some(fixed_seed.to_string()), // Fixed seed
                ..Default::default()
            }),
        };

        // First obfuscation
        let response1 = server.post("/obfuscate").json(&request).await;
        assert_eq!(response1.status_code(), StatusCode::OK);
        let body1 = response1.json::<ObfuscateResponse>();

        // Second obfuscation with same seed
        let response2 = server.post("/obfuscate").json(&request).await;
        assert_eq!(response2.status_code(), StatusCode::OK);
        let body2 = response2.json::<ObfuscateResponse>();

        // Should produce identical results
        assert_eq!(body1.obfuscated_bytecode, body2.obfuscated_bytecode);
    }

    #[tokio::test]
    async fn test_invalid_seed_format() {
        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode_handler));
        let server = TestServer::new(app).unwrap();

        let request = ObfuscateRequest {
            bytecode: "0x6001600255".to_string(),
            options: Some(ObfuscationOptions {
                seed: Some("invalid_seed".to_string()),
                ..Default::default()
            }),
        };

        let response = server.post("/obfuscate").json(&request).await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.json::<ErrorResponse>();
        assert!(body
            .details
            .as_ref()
            .unwrap()
            .contains("Invalid seed format"));
    }
}
