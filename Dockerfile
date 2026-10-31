FROM rust:1.89-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --bin waf-ingress

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --create-home waf

COPY --from=builder /build/target/release/waf-ingress /usr/local/bin/waf-ingress
COPY --from=builder /build/rules /opt/waf/rules
COPY config.toml /etc/waf/config.toml

USER 1000
EXPOSE 8080 8081
ENV RUST_LOG=info WAF_CONFIG_FILE=/etc/waf/config.toml

ENTRYPOINT ["/usr/local/bin/waf-ingress"]
