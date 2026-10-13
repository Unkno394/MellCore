#!/bin/sh

# Shared iptables helpers for the High bridge. Ubuntu's iptables command normally targets the
# nftables backend, so these chains coexist with UFW, Docker and libvirt while running before
# their broad INPUT/FORWARD accepts.
HF_HIGH_BRIDGE=${HF_HIGH_BRIDGE:-virbr-hfhigh}
HF_HIGH_INPUT_CHAIN=HF_HIGH_INPUT
HF_HIGH_FORWARD_CHAIN=HF_HIGH_FORWARD
HF_HIGH_DNAT_CHAIN=HF_HIGH_DNAT
HF_HIGH_INPUT6_CHAIN=HF_HIGH_INPUT6
HF_HIGH_FORWARD6_CHAIN=HF_HIGH_FORWARD6

validate_instance_id() {
  value=$1
  if ! printf '%s\n' "$value" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
    echo "invalid High instance UUID: $value" >&2
    return 1
  fi
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

  ensure_chain filter "$HF_HIGH_INPUT_CHAIN"
  ipt -F "$HF_HIGH_INPUT_CHAIN"
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

  if command -v ip6tables >/dev/null 2>&1; then
    ensure_chain6 filter "$HF_HIGH_INPUT6_CHAIN"
    ip6t -F "$HF_HIGH_INPUT6_CHAIN"
    ip6t -A "$HF_HIGH_INPUT6_CHAIN" -j DROP
    ensure_jump_first6 filter INPUT -i "$bridge" -j "$HF_HIGH_INPUT6_CHAIN"

    ensure_chain6 filter "$HF_HIGH_FORWARD6_CHAIN"
    ip6t -F "$HF_HIGH_FORWARD6_CHAIN"
    ip6t -A "$HF_HIGH_FORWARD6_CHAIN" -j DROP
    ensure_jump_first6 filter FORWARD -i "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
    ensure_jump_first6 filter FORWARD -o "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
    delete_all6 filter INPUT -i "$bridge" -j DROP
  fi
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
