FROM rust:1.89-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --bin waf-ingress --features http3,webtransport

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --create-home waf \
    && mkdir -p /var/lib/waf/data /var/lib/waf/logs \
    && chown -R 1000:1000 /var/lib/waf

COPY --from=builder /build/target/release/waf-ingress /usr/local/bin/waf-ingress
COPY --from=builder /build/rules /opt/waf/rules
COPY config.docker.toml /etc/waf/config.toml

WORKDIR /var/lib/waf
USER 1000
EXPOSE 8080 8081
ENV RUST_LOG=info WAF_CONFIG_FILE=/etc/waf/config.toml
ENV WAF_UPSTREAM_URI=http://127.0.0.1:3000

ENTRYPOINT ["/usr/local/bin/waf-ingress"]
