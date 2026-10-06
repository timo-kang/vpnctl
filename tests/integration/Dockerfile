FROM debian:bookworm-slim
# A stalled package mirror must fail setup with evidence, not consume the entire
# network-test job. These bounds do not change any product/test safety deadline.
RUN timeout --kill-after=5s 180s apt-get \
        -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
        -o APT::Update::Error-Mode=any update && \
    timeout --kill-after=5s 180s apt-get \
        -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
        install -y --no-install-recommends \
        iproute2 wireguard-tools ca-certificates nftables conntrack && \
    rm -rf /var/lib/apt/lists/*
# Binaries are built from the current checkout by scripts/test-netns.sh.
ENTRYPOINT ["/test/integration.test"]
