FROM rust:1.98-alpine AS builder
WORKDIR /build
COPY web/Cargo.toml web/Cargo.lock ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs && cargo build --release --locked && rm -rf src
COPY web/src ./src
# The Web shell embeds the authoritative Desktop frontend assets at compile time.
COPY src/frontend /src/frontend
COPY web/index.html ./index.html
RUN cargo build --release --locked

FROM alpine:3.22
RUN addgroup -S -g 10001 pcapdoctor && adduser -S -D -H -u 10001 -G pcapdoctor pcapdoctor
COPY --from=builder /build/target/release/pcap-doctor-web /usr/local/bin/pcap-doctor-web
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pcap-doctor-web"]
