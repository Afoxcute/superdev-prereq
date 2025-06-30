FROM rust:1.75-slim-buster as builder

WORKDIR /usr/src/app
COPY . .

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install nightly toolchain
RUN rustup default nightly

# Set RUSTFLAGS for static linking of C dependencies
ENV RUSTFLAGS='-C target-feature=+crt-static'

# Build the application with specific target
RUN cargo build --release --target x86_64-unknown-linux-gnu

# Runtime stage
FROM debian:buster-slim

WORKDIR /usr/local/bin

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-gnu/release/hello_cargo .

# Expose the port
EXPOSE 3000

# Run the binary
CMD ["hello_cargo"] 