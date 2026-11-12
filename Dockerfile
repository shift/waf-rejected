FROM rust:1.99-bookworm AS builder

WORKDIR /build
COPY . .
# `coraza-native` enables the opt-in native sidecar backend and `rust-engine`
# is the default request-inspection engine. Coraza remains selectable with
# `waf.coraza.backend = "wasm"` and is the explicit fallback.
RUN cargo build --release --bin waf-ingress --features http3,webtransport,wasm-reactor,coraza-native,rust-engine

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --create-home waf \
    && mkdir -p /var/lib/waf/data /var/lib/waf/logs \
    && chown -R 1000:1000 /var/lib/waf

COPY --from=builder /build/target/release/waf-ingress /usr/local/bin/waf-ingress
COPY --from=builder /build/rules /opt/waf/rules
COPY wasm/coraza_reactor/rules/crs /usr/share/waf/rules/crs
COPY wasm/coraza_reactor/coraza_reactor.wasm \
     wasm/coraza_reactor/LICENSE-CRS \
     wasm/coraza_reactor/PROVENANCE.md \
     wasm/coraza_reactor/SHA256SUMS \
     /usr/share/waf/wasm/
COPY config.docker.toml /etc/waf/config.toml

# Release guard: the module must be present, have a matching digest, and stay
# within the 32 MiB budget (the current build is about 18 MiB).
RUN test -s /usr/share/waf/wasm/coraza_reactor.wasm \
    && test -s /usr/share/waf/rules/crs/crs.conf \
    && test "$(stat -c%s /usr/share/waf/wasm/coraza_reactor.wasm)" -le 33554432 \
    && cd /usr/share/waf/wasm \
    && sha256sum --check SHA256SUMS

WORKDIR /var/lib/waf
USER 1000
EXPOSE 8080 8081
ENV RUST_LOG=info WAF_CONFIG_FILE=/etc/waf/config.toml
ENV WAF_UPSTREAM_URI=http://127.0.0.1:3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8081/health/ready"]

ENTRYPOINT ["/usr/local/bin/waf-ingress"]
