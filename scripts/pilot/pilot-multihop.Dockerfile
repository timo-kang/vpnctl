# Manual pilot image — extends the integration test base with ping + procps.
# Build the base first: docker build -t vpnctl-pilot-multihop tests/integration
# Then:                 docker build -t vpnctl-pilot-multihop:v2 -f scripts/pilot/pilot-multihop.Dockerfile .
FROM vpnctl-pilot-multihop
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping procps && rm -rf /var/lib/apt/lists/*
