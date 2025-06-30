// fn main() {
//     println!("Hello, superdev!");
// }


// use std::io;

// use rand::Rng;

// fn main() {
//     println!("Guess the number!");

//     let secret_number = rand::thread_rng().gen_range(1..=100);

//     println!("The secret number is: {secret_number}");

//     println!("Please input your guess.");

//     let mut guess = String::new();

//     io::stdin()
//         .read_line(&mut guess)
//         .expect("Failed to read line");

//     println!("You guessed: {guess}");
// }


use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair},
    signer::Signer,
    system_instruction,
    transaction::Transaction,
};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use anyhow::Error as AnyhowError;
use utoipa::{OpenApi, IntoParams};
use utoipa_swagger_ui::SwaggerUi;

// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        create_record,
        get_record,
        get_all_records,
        update_record,
        delete_record
    ),
    components(
        schemas(
            HealthResponse,
            RecordResponse,
            RecordListResponse,
            DeleteResponse,
            SolanaRecord,
            CreateRecordRequest,
            UpdateRecordRequest,
            QueryParams
        )
    ),
    tags(
        (name = "Solana Records API", description = "Solana blockchain record management endpoints")
    )
)]
struct ApiDoc;

// Application state
#[derive(Clone)]
pub struct AppState {
    solana_client: Arc<RpcClient>,
    keypair: Arc<Keypair>,
    // In-memory cache for faster reads (in production, use Redis or similar)
    cache: Arc<RwLock<HashMap<String, SolanaRecord>>>,
}

// Data structures
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct SolanaRecord {
    pub id: String,
    pub data: String,
    pub pubkey: Option<String>,
    pub signature: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateRecordRequest {
    pub data: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateRecordRequest {
    pub data: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[derive(IntoParams)]
pub struct QueryParams {
    /// Maximum number of records to return
    #[param(example = 10)]
    pub limit: Option<usize>,
    /// Number of records to skip
    #[param(example = 0)]
    pub offset: Option<usize>,
}

// Specific response types for OpenAPI documentation
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub success: bool,
    pub data: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RecordResponse {
    pub success: bool,
    pub data: Option<SolanaRecord>,
    pub message: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RecordListResponse {
    pub success: bool,
    pub data: Option<Vec<SolanaRecord>>,
    pub message: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeleteResponse {
    pub success: bool,
    pub data: Option<String>,
    pub message: String,
}

// Solana blockchain operations
impl AppState {
    pub fn new(rpc_url: &str, keypair: Keypair) -> Self {
        let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
        Self {
            solana_client: Arc::new(client),
            keypair: Arc::new(keypair),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // Store data on Solana (simplified - in practice you'd use a program)
    async fn store_on_solana(&self, data: &str) -> Result<(String, String), AnyhowError> {
        // Create a new account to store data
        let new_account = Keypair::new();
        let data_bytes = data.as_bytes();
        
        // Calculate minimum balance for rent exemption
        let rent = self.solana_client
            .get_minimum_balance_for_rent_exemption(data_bytes.len())?;

        // Create account instruction
        let create_account_ix = system_instruction::create_account(
            &self.keypair.pubkey(),
            &new_account.pubkey(),
            rent,
            data_bytes.len() as u64,
            &solana_sdk::system_program::id(),
        );

        // Create and send transaction
        let recent_blockhash = self.solana_client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[create_account_ix],
            Some(&self.keypair.pubkey()),
            &[&*self.keypair, &new_account],
            recent_blockhash,
        );

        let signature = self.solana_client
            .send_and_confirm_transaction(&transaction)?;

        Ok((new_account.pubkey().to_string(), signature.to_string()))
    }

    // Fetch account data from Solana
    async fn fetch_from_solana(&self, pubkey_str: &str) -> Result<Vec<u8>, AnyhowError> {
        let pubkey = Pubkey::from_str(pubkey_str)?;
        let account = self.solana_client.get_account(&pubkey)?;
        Ok(account.data)
    }

    // Update data on Solana (simplified - would need program support)
    async fn update_on_solana(&self, _pubkey_str: &str, _new_data: &str) -> Result<String, AnyhowError> {
        // Note: Direct account data updates require a program
        // This is a placeholder - in practice you'd call your program
        Err(AnyhowError::msg("Direct updates require a Solana program"))
    }
}

// API Handlers with OpenAPI documentation
/// Check the health of the service
#[utoipa::path(
    get,
    path = "/health",
    tag = "Solana Records API",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse)
    )
)]
#[axum::debug_handler]
async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    match state.solana_client.get_health() {
        Ok(_) => Json(HealthResponse {
            success: true,
            data: Some("Solana connection healthy".to_string()),
            message: "Service is healthy".to_string(),
        }),
        Err(e) => Json(HealthResponse {
            success: false,
            data: None,
            message: format!("Solana connection error: {}", e),
        }),
    }
}

/// Create a new record
#[utoipa::path(
    post,
    path = "/records",
    tag = "Solana Records API",
    request_body = CreateRecordRequest,
    responses(
        (status = 200, description = "Record created successfully", body = RecordResponse),
        (status = 500, description = "Internal server error")
    )
)]
#[axum::debug_handler]
async fn create_record(
    State(state): State<AppState>,
    Json(payload): Json<CreateRecordRequest>,
) -> Result<Json<RecordResponse>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    match state.store_on_solana(&payload.data).await {
        Ok((pubkey, signature)) => {
            let record = SolanaRecord {
                id: id.clone(),
                data: payload.data,
                pubkey: Some(pubkey),
                signature: Some(signature),
                created_at: timestamp,
                updated_at: timestamp,
            };

            state.cache.write().await.insert(id.clone(), record.clone());

            Ok(Json(RecordResponse {
                success: true,
                data: Some(record),
                message: "Record created successfully".to_string(),
            }))
        }
        Err(e) => {
            eprintln!("Error creating record: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get a specific record by ID
#[utoipa::path(
    get,
    path = "/records/{id}",
    tag = "Solana Records API",
    params(
        ("id" = String, Path, description = "Record identifier")
    ),
    responses(
        (status = 200, description = "Record found", body = RecordResponse),
        (status = 404, description = "Record not found")
    )
)]
#[axum::debug_handler]
async fn get_record(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<RecordResponse>, StatusCode> {
    if let Some(record) = state.cache.read().await.get(&id) {
        return Ok(Json(RecordResponse {
            success: true,
            data: Some(record.clone()),
            message: "Record found in cache".to_string(),
        }));
    }
    Err(StatusCode::NOT_FOUND)
}

/// Get all records with pagination
#[utoipa::path(
    get,
    path = "/records",
    tag = "Solana Records API",
    params(
        QueryParams
    ),
    responses(
        (status = 200, description = "List of records", body = RecordListResponse)
    )
)]
#[axum::debug_handler]
async fn get_all_records(
    Query(params): Query<QueryParams>,
    State(state): State<AppState>,
) -> Result<Json<RecordListResponse>, StatusCode> {
    let limit = params.limit.unwrap_or(10);
    let offset = params.offset.unwrap_or(0);
    
    let records = state.cache.read().await.values().cloned().collect::<Vec<_>>();
    let total = records.len();
    
    let paginated: Vec<SolanaRecord> = records
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    let len = paginated.len();
    
    Ok(Json(RecordListResponse {
        success: true,
        data: Some(paginated),
        message: format!("Retrieved {} records (total: {})", len, total),
    }))
}

/// Update a record
#[utoipa::path(
    put,
    path = "/records/{id}",
    tag = "Solana Records API",
    params(
        ("id" = String, Path, description = "Record identifier")
    ),
    request_body = UpdateRecordRequest,
    responses(
        (status = 200, description = "Record updated successfully", body = RecordResponse),
        (status = 404, description = "Record not found"),
        (status = 500, description = "Internal server error")
    )
)]
#[axum::debug_handler]
async fn update_record(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateRecordRequest>,
) -> Result<Json<RecordResponse>, StatusCode> {
    let mut cache = state.cache.write().await;
    
    if let Some(mut record) = cache.get(&id).cloned() {
        record.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        record.data = payload.data;
        cache.insert(id, record.clone());

        Ok(Json(RecordResponse {
            success: true,
            data: Some(record),
            message: "Record updated successfully".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Delete a record
#[utoipa::path(
    delete,
    path = "/records/{id}",
    tag = "Solana Records API",
    params(
        ("id" = String, Path, description = "Record identifier")
    ),
    responses(
        (status = 200, description = "Record deleted successfully", body = DeleteResponse),
        (status = 404, description = "Record not found")
    )
)]
#[axum::debug_handler]
async fn delete_record(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let mut cache = state.cache.write().await;
    
    if cache.remove(&id).is_some() {
        Ok(Json(DeleteResponse {
            success: true,
            data: Some(id),
            message: "Record deleted successfully".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // Load .env file if it exists
    dotenv::dotenv().ok();
    
    // Initialize Solana client and keypair
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    
    // Get port from environment variable or use default
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    
    // Initialize keypair from private key or generate new one
    let keypair = match std::env::var("SOLANA_PRIVATE_KEY") {
        Ok(private_key_base58) => {
            let private_key_bytes = bs58::decode(private_key_base58)
                .into_vec()
                .expect("Failed to decode private key");
            
            if private_key_bytes.len() != 64 {
                log::error!("Invalid private key length. Expected 64 bytes.");
                std::process::exit(1);
            }
            
            let keypair = Keypair::from_bytes(&private_key_bytes)
                .expect("Failed to create keypair from private key");
            
            log::info!("Successfully loaded wallet from private key");
            keypair
        }
        Err(_) => {
            log::warn!("No SOLANA_PRIVATE_KEY provided, generating new keypair");
            Keypair::new()
        }
    };
    
    log::info!("Server wallet public key: {}", keypair.pubkey());
    
    let app_state = AppState::new(&rpc_url, keypair);

    // Build the router with Swagger UI
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health_check))
        .route("/records", post(create_record))
        .route("/records", get(get_all_records))
        .route("/records/:id", get(get_record))
        .route("/records/:id", put(update_record))
        .route("/records/:id", delete(delete_record))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let addr = format!("{}:{}", host, port);
    log::info!("Server running on http://{}", addr);
    log::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app).await.unwrap();
}