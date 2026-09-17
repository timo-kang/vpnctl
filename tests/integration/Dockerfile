FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 wireguard-tools ca-certificates nftables conntrack && \
    rm -rf /var/lib/apt/lists/*
# Binaries are built from the current checkout by scripts/test-netns.sh.
ENTRYPOINT ["/test/integration.test"]
