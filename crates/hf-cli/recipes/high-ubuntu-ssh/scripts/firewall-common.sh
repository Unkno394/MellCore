#!/bin/sh

# Shared iptables helpers for the High bridge. Ubuntu's iptables command normally targets the
# nftables backend, so these chains coexist with UFW, Docker and libvirt while running before
# their broad INPUT/FORWARD accepts.
case ${HF_HIGH_NETWORK_SCOPE:-production} in
  local)
    HF_HIGH_NETWORK_NAME=hf-local-high-isolated
    HF_HIGH_BRIDGE=virbr-hflocal
    HF_HIGH_NETWORK_ADDRESS=192.168.252.1
    HF_HIGH_DHCP_START=192.168.252.100
    HF_HIGH_DHCP_END=192.168.252.200
    HF_HIGH_INPUT_CHAIN=HF_LOCAL_INPUT
    HF_HIGH_FORWARD_CHAIN=HF_LOCAL_FORWARD
    HF_HIGH_DNAT_CHAIN=HF_LOCAL_DNAT
    HF_HIGH_INPUT6_CHAIN=HF_LOCAL_INPUT6
    HF_HIGH_FORWARD6_CHAIN=HF_LOCAL_FORWARD6
    ;;
  production)
    HF_HIGH_NETWORK_NAME=hf-high-isolated
    HF_HIGH_BRIDGE=${HF_HIGH_BRIDGE:-virbr-hfhigh}
    HF_HIGH_NETWORK_ADDRESS=192.168.250.1
    HF_HIGH_DHCP_START=192.168.250.100
    HF_HIGH_DHCP_END=192.168.250.200
    HF_HIGH_INPUT_CHAIN=HF_HIGH_INPUT
    HF_HIGH_FORWARD_CHAIN=HF_HIGH_FORWARD
    HF_HIGH_DNAT_CHAIN=HF_HIGH_DNAT
    HF_HIGH_INPUT6_CHAIN=HF_HIGH_INPUT6
    HF_HIGH_FORWARD6_CHAIN=HF_HIGH_FORWARD6
    ;;
  e2e)
    HF_HIGH_NETWORK_NAME=hf-high-iso-e2e
    HF_HIGH_BRIDGE=virbr-hfiso
    HF_HIGH_NETWORK_ADDRESS=192.168.251.1
    HF_HIGH_DHCP_START=192.168.251.100
    HF_HIGH_DHCP_END=192.168.251.200
    HF_HIGH_INPUT_CHAIN=HF_E2E_INPUT
    HF_HIGH_FORWARD_CHAIN=HF_E2E_FORWARD
    HF_HIGH_DNAT_CHAIN=HF_E2E_DNAT
    HF_HIGH_INPUT6_CHAIN=HF_E2E_INPUT6
    HF_HIGH_FORWARD6_CHAIN=HF_E2E_FORWARD6
    ;;
  *)
    echo "invalid HF_HIGH_NETWORK_SCOPE: ${HF_HIGH_NETWORK_SCOPE}" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

validate_instance_id() {
  value=$1
  if ! printf '%s\n' "$value" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
    echo "invalid High instance UUID: $value" >&2
    return 1
  fi
}

validate_publish_interface_name() {
  value=$1
  case "$value" in
    ''|*[!A-Za-z0-9_.:-]*)
      echo "invalid High publish interface: $value" >&2
      return 1
      ;;
  esac
  [ "${#value}" -le 15 ] || {
    echo "High publish interface name is too long: $value" >&2
    return 1
  }
  [ "$value" != lo ] && [ "$value" != "$HF_HIGH_BRIDGE" ] || {
    echo "refusing High publication on isolated or loopback interface: $value" >&2
    return 1
  }
}

resolve_high_publish_interface() {
  candidate=${HF_HIGH_PUBLISH_INTERFACE:-}
  if [ -z "$candidate" ]; then
    command -v ip >/dev/null
    candidate=$(ip -4 route show default | awk '
      $1 == "default" {
        for (i = 1; i < NF; i++) {
          if ($i == "dev" && !seen[$(i + 1)]++) {
            count++
            selected = $(i + 1)
          }
        }
      }
      END {
        if (count == 1) print selected
        else exit(count == 0 ? 1 : 2)
      }
    ') || {
      echo "cannot select one High publish interface; set HF_HIGH_PUBLISH_INTERFACE" >&2
      return 1
    }
  fi
  validate_publish_interface_name "$candidate"
  ip -o link show dev "$candidate" >/dev/null 2>&1 || {
    echo "High publish interface does not exist: $candidate" >&2
    return 1
  }
  printf '%s\n' "$candidate"
}

ipt() {
  iptables -w 5 "$@"
}

ip6t() {
  ip6tables -w 5 "$@"
}

ensure_chain() {
  table=$1
  chain=$2
  ipt -t "$table" -N "$chain" 2>/dev/null || ipt -t "$table" -L "$chain" -n >/dev/null
}

ensure_chain6() {
  table=$1
  chain=$2
  ip6t -t "$table" -N "$chain" 2>/dev/null || ip6t -t "$table" -L "$chain" -n >/dev/null
}

delete_all() {
  table=$1
  chain=$2
  shift 2
  while ipt -t "$table" -C "$chain" "$@" 2>/dev/null; do
    ipt -t "$table" -D "$chain" "$@"
  done
}

delete_all6() {
  table=$1
  chain=$2
  shift 2
  while ip6t -t "$table" -C "$chain" "$@" 2>/dev/null; do
    ip6t -t "$table" -D "$chain" "$@"
  done
}

ensure_jump_first() {
  table=$1
  chain=$2
  shift 2
  delete_all "$table" "$chain" "$@"
  ipt -t "$table" -I "$chain" 1 "$@"
}

ensure_jump_first6() {
  table=$1
  chain=$2
  shift 2
  delete_all6 "$table" "$chain" "$@"
  ip6t -t "$table" -I "$chain" 1 "$@"
}

apply_high_firewall_base() {
  bridge=$HF_HIGH_BRIDGE
  command -v ip6tables >/dev/null 2>&1 || {
    echo "ip6tables is required to keep High guest traffic isolated over IPv6" >&2
    return 1
  }

  ensure_chain filter "$HF_HIGH_INPUT_CHAIN"
  ipt -F "$HF_HIGH_INPUT_CHAIN"
  # Allow only replies to connections initiated by the KVM host. A guest cannot manufacture
  # ESTABLISHED state for a new guest-to-host flow, which still reaches the terminal DROP.
  ipt -A "$HF_HIGH_INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ipt -A "$HF_HIGH_INPUT_CHAIN" -p udp --sport 68 --dport 67 -j ACCEPT
  ipt -A "$HF_HIGH_INPUT_CHAIN" -j DROP
  ensure_jump_first filter INPUT -i "$bridge" -j "$HF_HIGH_INPUT_CHAIN"

  ensure_chain filter "$HF_HIGH_FORWARD_CHAIN"
  # Instance-specific SSH rules are inserted before this terminal deny by publish-ssh.sh.
  delete_all filter "$HF_HIGH_FORWARD_CHAIN" -j DROP
  ipt -A "$HF_HIGH_FORWARD_CHAIN" -j DROP
  ensure_jump_first filter FORWARD -i "$bridge" -j "$HF_HIGH_FORWARD_CHAIN"
  ensure_jump_first filter FORWARD -o "$bridge" -j "$HF_HIGH_FORWARD_CHAIN"

  ensure_chain nat "$HF_HIGH_DNAT_CHAIN"
  ensure_jump_first nat PREROUTING -j "$HF_HIGH_DNAT_CHAIN"

  # Remove rules written by the pre-chain implementation. They were order-dependent and could
  # sit after a broad UFW/libvirt ACCEPT.
  delete_all filter INPUT -i "$bridge" -p udp --sport 68 --dport 67 -j ACCEPT
  delete_all filter INPUT -i "$bridge" -j DROP

  ensure_chain6 filter "$HF_HIGH_INPUT6_CHAIN"
  ip6t -F "$HF_HIGH_INPUT6_CHAIN"
  ip6t -A "$HF_HIGH_INPUT6_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6t -A "$HF_HIGH_INPUT6_CHAIN" -j DROP
  ensure_jump_first6 filter INPUT -i "$bridge" -j "$HF_HIGH_INPUT6_CHAIN"

  ensure_chain6 filter "$HF_HIGH_FORWARD6_CHAIN"
  ip6t -F "$HF_HIGH_FORWARD6_CHAIN"
  ip6t -A "$HF_HIGH_FORWARD6_CHAIN" -j DROP
  ensure_jump_first6 filter FORWARD -i "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
  ensure_jump_first6 filter FORWARD -o "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
  delete_all6 filter INPUT -i "$bridge" -j DROP
}

is_protected_tcp_port() {
  candidate=$1
  # 2222 is the documented management SSH listener and must never be captured by High DNAT.
  for protected in ${HF_HIGH_PROTECTED_TCP_PORTS:-2222}; do
    [ "$candidate" = "$protected" ] && return 0
  done
  return 1
}

nat_port_is_claimed_elsewhere() {
  candidate=$1
  iptables-save -t nat 2>/dev/null | awk -v port="$candidate" '
    $1 == "-A" {
      for (i = 1; i <= NF; i++) {
        if ($i == "--dport" && $(i + 1) == port) found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  '
}

nat_port_has_only_expected_claim() {
  candidate=$1
  expected_chain=$2
  expected_interface=$3
  expected_destination=$4
  iptables-save -t nat 2>/dev/null | awk \
    -v port="$candidate" \
    -v chain="$expected_chain" \
    -v interface="$expected_interface" \
    -v destination="$expected_destination" '
    $1 == "-A" {
      rule_chain = $2
      rule_interface = ""
      rule_destination = ""
      rule_target = ""
      rule_port = ""
      for (i = 3; i <= NF; i++) {
        if ($i == "-i") rule_interface = $(i + 1)
        if ($i == "--dport") rule_port = $(i + 1)
        if ($i == "-j") rule_target = $(i + 1)
        if ($i == "--to-destination") rule_destination = $(i + 1)
      }
      if (rule_port == port) {
        claims++
        if (rule_chain == chain && rule_interface == interface &&
            rule_target == "DNAT" && rule_destination == destination) expected++
      }
    }
    END { exit(claims == 1 && expected == 1 ? 0 : 1) }
  '
}
