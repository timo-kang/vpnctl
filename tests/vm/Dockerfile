FROM ubuntu:24.04 AS guest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    linux-image-virtual initramfs-tools systemd-sysv udev dbus python3 iproute2 \
    wireguard-tools nftables ca-certificates kmod strace e2fsprogs && \
    rm -rf /var/lib/apt/lists/* && \
    systemctl mask systemd-timesyncd.service systemd-networkd-wait-online.service && \
    mkdir -p /opt/vpnctl-vm /var/lib/vpnctl-vm/results /var/lib/vpnctl-vm/work
# Managers are opt-in so the established lease/power image remains unchanged.
ARG VPNCTL_VM_MANAGERS=0
RUN if [ "$VPNCTL_VM_MANAGERS" = 1 ]; then \
      apt-get update && apt-get install -y --no-install-recommends network-manager netplan.io dnsmasq-base iptables && \
      rm -rf /var/lib/apt/lists/* && \
      systemctl mask NetworkManager.service systemd-networkd.service; \
    elif [ "$VPNCTL_VM_MANAGERS" != 0 ]; then exit 2; fi
COPY guest_agent.py /opt/vpnctl-vm/guest_agent.py
COPY manager_dhcp.py /opt/vpnctl-vm/manager_dhcp.py
COPY nft_delay.py /opt/vpnctl-vm/nft_delay.py
COPY fsync_fault.py /opt/vpnctl-vm/fsync_fault.py
COPY vpnctl-vm-agent.service /etc/systemd/system/vpnctl-vm-agent.service
RUN chmod 755 /opt/vpnctl-vm/nft_delay.py && rm -rf /home/ubuntu /var/cache/apt/archives/partial && systemctl enable vpnctl-vm-agent.service

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 qemu-utils python3 e2fsprogs && rm -rf /var/lib/apt/lists/*
COPY --from=guest / /guest-root/
RUN rm -rf /guest-root/run /guest-root/.dockerenv && mkdir /guest-root/run
COPY observer.py /opt/vpnctl-vm/observer.py
COPY make_image.py /opt/vpnctl-vm/make_image.py
ENTRYPOINT ["python3", "/opt/vpnctl-vm/observer.py"]
