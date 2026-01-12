# Stage 1: Build
FROM rust:bookworm as builder
WORKDIR /app
COPY . .
# Install sqlite3 lib required for compilation
RUN apt-get update && apt-get install -y libsqlite3-dev
# Build release binary

RUN cargo build --release

# Stage 2: Runtime
# We use gcr.io/distroless/cc-debian12 because it includes glibc/sqlite libs
# simpler than fighting with musl/static sqlite for a quick project.
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/fileshare /app/fileshare
WORKDIR /app
CMD ["./fileshare"]
