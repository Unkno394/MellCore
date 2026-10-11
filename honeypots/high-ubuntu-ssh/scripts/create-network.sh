#!/bin/sh
set -eu

network_name=hf-high-isolated
if virsh net-info "$network_name" >/dev/null 2>&1; then
  virsh net-start "$network_name" 2>/dev/null || true
  exit 0
fi

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
