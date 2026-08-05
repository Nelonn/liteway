FROM rust:slim-trixie AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin litewayd

FROM debian:trixie-slim
COPY --from=builder /build/target/release/litewayd /usr/local/bin/
ENTRYPOINT ["litewayd"]
CMD ["-c", "/liteway.toml"]
