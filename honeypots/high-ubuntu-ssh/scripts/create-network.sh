#!/bin/sh
set -eu

network_name=hf-high-isolated
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
bridge=$HF_HIGH_BRIDGE
command -v python3 >/dev/null
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT INT TERM
if virsh net-info "$network_name" >/dev/null 2>&1; then
  virsh net-dumpxml "$network_name" > "$tmpfile"
  python3 - "$tmpfile" "$network_name" "$bridge" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, expected_name, expected_bridge = sys.argv[1:]
root = ET.parse(path).getroot()
forward = root.find("forward")
bridge = root.find("bridge")
addresses = root.findall("ip")
valid_address = len(addresses) == 1 and (
    addresses[0].get("family", "ipv4") == "ipv4"
    and addresses[0].get("address") == "192.168.250.1"
    and addresses[0].get("netmask") == "255.255.255.0"
)
dhcp_range = addresses[0].find("./dhcp/range") if valid_address else None
valid = (
    root.tag == "network"
    and root.findtext("name") == expected_name
    and (forward is None or forward.get("mode", "none") == "none")
    and bridge is not None
    and bridge.get("name") == expected_bridge
    and valid_address
    and dhcp_range is not None
    and dhcp_range.get("start") == "192.168.250.100"
    and dhcp_range.get("end") == "192.168.250.200"
    and not root.findall("route")
)
if not valid:
    raise SystemExit("existing hf-high-isolated libvirt network does not match the fail-closed profile")
PY
  if ! LC_ALL=C virsh net-info "$network_name" | grep -Eq '^Active:[[:space:]]+yes$'; then
    virsh net-start "$network_name"
  fi
else
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

# Guests need DHCP from libvirt but must not reach host/LAN/management services. Dedicated chains
# are deliberately reinserted at rule 1 so UFW, Docker and libvirt cannot bypass this boundary.
# The virtio telemetry channel does not traverse the bridge.
apply_high_firewall_base
