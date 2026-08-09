FROM rust:1.88.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps/backend ./apps/backend
COPY apps/site-runtime ./apps/site-runtime
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release -p snm-backend

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home snm
COPY --from=build /src/target/release/snm-backend /usr/local/bin/snm-backend
USER 10001:10001
ENV SNM_BACKEND_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/snm-backend"]
