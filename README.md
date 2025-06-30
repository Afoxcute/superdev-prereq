# Solana API Server

A Rust-based HTTP server providing Solana blockchain operations through RESTful endpoints.

## Features

- Generate Solana keypairs
- Create SPL token mint instructions
- Mint SPL tokens
- Sign and verify messages using Ed25519
- Create SOL transfer instructions
- Create SPL token transfer instructions
- Interactive Swagger UI documentation

## Quick Start now

### Prerequisites

- Rust (nightly toolchain)
- Cargo

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   cargo build --release
   ```

3. Run the server:
   ```bash
   cargo run
   ```

The server will start on `http://0.0.0.0:3000` by default.

### Environment Variables

- `PORT`: Server port (default: 3000)
- `HOST`: Server host (default: 0.0.0.0)
- `RUST_LOG`: Log level (default: info)

## API Endpoints

### 1. Generate Keypair
- **POST** `/keypair`
- Generates a new Solana keypair
- Returns public key and secret key in base58 format

### 2. Create Token
- **POST** `/token/create`
- Creates an SPL token mint instruction
- Requires: mint authority, mint address, decimals

### 3. Mint Token
- **POST** `/token/mint`
- Creates a mint-to instruction for SPL tokens
- Requires: mint address, destination, authority, amount

### 4. Sign Message
- **POST** `/message/sign`
- Signs a message using Ed25519
- Requires: message, secret key
- Returns: base64 signature, public key, message

### 5. Verify Message
- **POST** `/message/verify`
- Verifies a signed message
- Requires: message, signature, public key
- Returns: verification result

### 6. Send SOL
- **POST** `/send/sol`
- Creates a SOL transfer instruction
- Requires: from address, to address, lamports amount

### 7. Send Token
- **POST** `/send/token`
- Creates an SPL token transfer instruction
- Requires: destination, mint, owner, amount

## API Documentation

Interactive Swagger UI is available at: `http://localhost:3000/swagger-ui/`

## Response Format

All endpoints return JSON responses with the following structure:

### Success Response
```json
{
  "success": true,
  "data": { /* endpoint-specific result */ }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Description of error"
}
```

## Example Usage

### Generate a keypair
```bash
curl -X POST http://localhost:3000/keypair \
  -H "Content-Type: application/json"
```

### Sign a message
```bash
curl -X POST http://localhost:3000/message/sign \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello, Solana!",
    "secret": "your-base58-secret-key"
  }'
```

### Create SOL transfer instruction
```bash
curl -X POST http://localhost:3000/send/sol \
  -H "Content-Type: application/json" \
  -d '{
    "from": "sender-address",
    "to": "recipient-address",
    "lamports": 100000
  }'
```

## Deployment

### Railway Deployment

The application is configured for Railway deployment with:
- `Dockerfile` for containerization
- `Procfile` for process management
- Environment variable support

### Docker

Build and run with Docker:
```bash
docker build -t solana-api .
docker run -p 3000:3000 solana-api
```

## Security Considerations

- Private keys are never stored on the server
- All cryptographic operations use standard Solana libraries
- Input validation is performed on all endpoints
- CORS is enabled for cross-origin requests

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License. 