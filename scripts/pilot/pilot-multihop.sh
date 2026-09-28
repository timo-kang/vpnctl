#!/usr/bin/env bash
# Throwaway pilot: verify vpnctl netns harness can host multi-hop WireGuard
# forwarding where node C forwards for A <-> B (no direct A<->B underlay path).
#
# Runs inside a NET_ADMIN container. Not wired into make test-netns.
set -euo pipefail

log()   { printf '[pilot %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail()  { log "FAIL: $*"; exit 1; }
pass()  { log "PASS: $*"; }

umask 077
tmpdir=$(mktemp -d)
trap 'cleanup' EXIT

cleanup() {
    for n in nA nB nC; do ip netns del "$n" 2>/dev/null || true; done
    rm -rf "$tmpdir"
}

for n in a b c; do
    wg genkey > "$tmpdir/$n.key"
    wg pubkey < "$tmpdir/$n.key" > "$tmpdir/$n.pub"
done
A_PUB=$(cat "$tmpdir/a.pub")
B_PUB=$(cat "$tmpdir/b.pub")
C_PUB=$(cat "$tmpdir/c.pub")

log "Creating namespaces and veth pairs (A<->C, B<->C, no A<->B)"
for n in nA nB nC; do ip netns add "$n"; done
ip link add veth-A type veth peer name veth-CA
ip link add veth-B type veth peer name veth-CB
ip link set veth-A  netns nA
ip link set veth-CA netns nC
ip link set veth-B  netns nB
ip link set veth-CB netns nC

ip -n nA addr add 10.100.12.1/24 dev veth-A
ip -n nC addr add 10.100.12.2/24 dev veth-CA
ip -n nB addr add 10.100.34.1/24 dev veth-B
ip -n nC addr add 10.100.34.2/24 dev veth-CB
for n in nA nB nC; do ip -n "$n" link set lo up; done
ip -n nA link set veth-A  up
ip -n nB link set veth-B  up
ip -n nC link set veth-CA up
ip -n nC link set veth-CB up

log "Baseline underlay: A cannot reach B (no direct veth, no route)"
if ip netns exec nA ping -c 2 -W 1 -q 10.100.34.1 >/dev/null 2>&1; then
    fail "underlay isolation broken: A reached B directly"
fi
pass "underlay isolation confirmed"

log "Configuring WireGuard overlay 10.7.0.0/24 (A=.1  B=.2  C=.3)"
for n in nA nB nC; do ip -n "$n" link add wg0 type wireguard; done

ip netns exec nA wg set wg0 private-key "$tmpdir/a.key" listen-port 51820
ip netns exec nA wg set wg0 peer "$C_PUB" endpoint 10.100.12.2:51820 \
    allowed-ips 10.7.0.3/32,10.7.0.2/32 persistent-keepalive 5
ip -n nA addr add 10.7.0.1/24 dev wg0
ip -n nA link set wg0 up

ip netns exec nB wg set wg0 private-key "$tmpdir/b.key" listen-port 51820
ip netns exec nB wg set wg0 peer "$C_PUB" endpoint 10.100.34.2:51820 \
    allowed-ips 10.7.0.3/32,10.7.0.1/32 persistent-keepalive 5
ip -n nB addr add 10.7.0.2/24 dev wg0
ip -n nB link set wg0 up

ip netns exec nC wg set wg0 private-key "$tmpdir/c.key" listen-port 51820
ip netns exec nC wg set wg0 peer "$A_PUB" endpoint 10.100.12.1:51820 \
    allowed-ips 10.7.0.1/32 persistent-keepalive 5
ip netns exec nC wg set wg0 peer "$B_PUB" endpoint 10.100.34.1:51820 \
    allowed-ips 10.7.0.2/32 persistent-keepalive 5
ip -n nC addr add 10.7.0.3/24 dev wg0
ip -n nC link set wg0 up

log "Enabling ip_forward=1 on C"
ip netns exec nC sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

log "Waiting 3s for initial handshakes"
sleep 3

echo
log "=== Test 1: A -> C (single hop, sanity) ==="
ip netns exec nA ping -c 10 -i 0.1 -W 2 10.7.0.3 | tail -3
echo

log "=== Test 2: A -> B (multi-hop via C), 100 pings @ 100ms ==="
BEFORE=$(ip netns exec nC wg show wg0 transfer)
log "wg on C transfer BEFORE:"
echo "$BEFORE"
if ! ip netns exec nA ping -c 100 -i 0.1 -W 2 -q 10.7.0.2 > "$tmpdir/ab_multihop.txt"; then
    cat "$tmpdir/ab_multihop.txt"
    fail "multi-hop A->B ping had failures"
fi
cat "$tmpdir/ab_multihop.txt"
AFTER=$(ip netns exec nC wg show wg0 transfer)
log "wg on C transfer AFTER:"
echo "$AFTER"

loss=$(awk '/packet loss/ {for(i=1;i<=NF;i++) if($i~/%/){sub("%","",$i); print $i; exit}}' "$tmpdir/ab_multihop.txt")
if [[ -z "$loss" ]] || [[ "$loss" != "0" ]]; then
    fail "expected 0% loss on multi-hop, got '$loss%'"
fi
pass "A->B 100 pings @ 0% loss"

echo
log "=== Test 3: B -> A reverse direction, 100 pings ==="
if ! ip netns exec nB ping -c 100 -i 0.1 -W 2 -q 10.7.0.1 > "$tmpdir/ba_multihop.txt"; then
    cat "$tmpdir/ba_multihop.txt"
    fail "multi-hop B->A ping had failures"
fi
cat "$tmpdir/ba_multihop.txt"
loss=$(awk '/packet loss/ {for(i=1;i<=NF;i++) if($i~/%/){sub("%","",$i); print $i; exit}}' "$tmpdir/ba_multihop.txt")
[[ "$loss" == "0" ]] || fail "expected 0% loss on B->A, got '$loss%'"
pass "B->A 100 pings @ 0% loss"

echo
log "=== Test 4: negative control - disable ip_forward on C ==="
ip netns exec nC sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
if ip netns exec nA ping -c 5 -W 1 -q 10.7.0.2 >/dev/null 2>&1; then
    fail "ping succeeded with ip_forward=0 - forwarding was NOT actually needed"
fi
pass "ip_forward=0 correctly blocks A->B (multi-hop truly depends on C forwarding)"

echo
log "=== Test 5: recovery - re-enable ip_forward, verify ping resumes ==="
ip netns exec nC sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sleep 1
if ! ip netns exec nA ping -c 20 -i 0.1 -W 2 -q 10.7.0.2 > "$tmpdir/recovery.txt"; then
    cat "$tmpdir/recovery.txt"
    fail "recovery ping had failures"
fi
cat "$tmpdir/recovery.txt"
loss=$(awk '/packet loss/ {for(i=1;i<=NF;i++) if($i~/%/){sub("%","",$i); print $i; exit}}' "$tmpdir/recovery.txt")
[[ "$loss" == "0" ]] || fail "expected 0% loss on recovery, got '$loss%'"
pass "A->B recovered after re-enabling ip_forward"

echo
log "=== Interface counters on C (should show non-zero rx/tx for BOTH peers) ==="
ip netns exec nC wg show wg0

echo
log "ALL TESTS PASSED"
