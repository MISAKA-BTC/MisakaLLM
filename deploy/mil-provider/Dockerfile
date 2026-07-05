# Build the misaka-mil-provider sidecar image (design §16.1).
# Context is the workspace root (`docker build -f deploy/mil-provider/Dockerfile .`).
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
# Build only the provider binary (and its workspace deps).
RUN cargo build --release -p misaka-mil-provider --bin misaka-mil-provider

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/misaka-mil-provider /usr/local/bin/misaka-mil-provider
# /data holds the 0600 provider seed + the JSONL receipt store (bind-mounted).
VOLUME ["/data"]
EXPOSE 37110
ENTRYPOINT ["misaka-mil-provider"]
CMD ["--help"]
