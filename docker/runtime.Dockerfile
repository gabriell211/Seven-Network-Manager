FROM rust:1.88.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps/backend ./apps/backend
COPY apps/site-runtime ./apps/site-runtime
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release -p snm-site-runtime

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 --create-home snm-runtime
COPY --from=build /src/target/release/snm-site-runtime /usr/local/bin/snm-site-runtime
USER 10002:10002
ENV SNM_RUNTIME_BIND=0.0.0.0:9765
EXPOSE 9765
ENTRYPOINT ["/usr/local/bin/snm-site-runtime"]
