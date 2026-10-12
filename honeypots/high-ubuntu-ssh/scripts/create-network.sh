#!/bin/sh
set -eu

network_name=hf-high-isolated
bridge=virbr-hfhigh
if virsh net-info "$network_name" >/dev/null 2>&1; then
  virsh net-start "$network_name" 2>/dev/null || true
else
  tmpfile=$(mktemp)
  trap 'rm -f "$tmpfile"' EXIT
  cat > "$tmpfile" <<'XML'
<network>
  <name>hf-high-isolated</name>
  <forward mode='none'/>
  <bridge name='virbr-hfhigh' stp='on' delay='0'/>
  <ip address='192.168.250.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.250.100' end='192.168.250.200'/>
    </dhcp>
  </ip>
</network>
XML
  virsh net-define "$tmpfile"
  virsh net-autostart "$network_name"
  virsh net-start "$network_name"
fi

# Guests need DHCP from libvirt but must not reach agent, SSH or management listeners bound on
# the host. The virtio telemetry channel does not traverse this bridge.
iptables -C INPUT -i "$bridge" -p udp --sport 68 --dport 67 -j ACCEPT 2>/dev/null ||
  iptables -I INPUT 1 -i "$bridge" -p udp --sport 68 --dport 67 -j ACCEPT
iptables -C INPUT -i "$bridge" -j DROP 2>/dev/null ||
  iptables -A INPUT -i "$bridge" -j DROP
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C INPUT -i "$bridge" -j DROP 2>/dev/null ||
    ip6tables -A INPUT -i "$bridge" -j DROP
fi
