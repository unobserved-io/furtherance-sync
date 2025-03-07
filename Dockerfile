FROM rust:1.82-slim-bookworm AS builder

WORKDIR /usr/src/furtherance-sync
COPY . .

# Install required dependencies for building
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Build with self-hosted feature only
RUN cargo clean
ENV SQLX_OFFLINE=true
RUN cargo build --release --no-default-features --features self-hosted

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /usr/local/bin/furtherance-sync

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /usr/src/furtherance-sync/target/release/furtherance-sync ./

# Copy required files
COPY --from=builder /usr/src/furtherance-sync/templates ./templates
COPY --from=builder /usr/src/furtherance-sync/static ./static

# Create a non-root user
RUN useradd -r -s /bin/false furtherance && \
    chown -R furtherance:furtherance /usr/local/bin/furtherance-sync

USER furtherance

# Expose the port used by the server
EXPOSE 8662

CMD ["./furtherance-sync"]
