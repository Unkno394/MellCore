#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
vm_name="hf-high-$instance_id"
instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
validate_instance_id "$instance_id"

cleanup_failed=0
if ! sh "$script_dir/unpublish-ssh.sh" "$instance_id"; then
  echo "could not remove High port-forwarding rules for $instance_id" >&2
  cleanup_failed=1
fi

if domains=$(virsh list --all --name 2>/dev/null); then
  domain_list_ok=1
else
  echo "could not inspect libvirt domains while removing $instance_id" >&2
  cleanup_failed=1
  domain_list_ok=0
  domains=
fi

if [ "$domain_list_ok" -eq 1 ] && printf '%s\n' "$domains" | grep -Fxq "$vm_name"; then
  vm_state=$(virsh domstate "$vm_name" 2>/dev/null || true)
  if [ "$vm_state" != "shut off" ]; then
    virsh destroy "$vm_name" >/dev/null 2>&1 || true
    vm_state=$(virsh domstate "$vm_name" 2>/dev/null || true)
  fi
  if [ "$vm_state" = "shut off" ]; then
    if virsh undefine "$vm_name" --nvram >/dev/null 2>&1; then
      :
    elif virsh undefine "$vm_name" >/dev/null 2>&1; then
      :
    else
      echo "could not undefine High VM $vm_name" >&2
      cleanup_failed=1
    fi
  else
    echo "could not stop High VM $vm_name (state: ${vm_state:-unknown})" >&2
    cleanup_failed=1
  fi
fi

if domains=$(virsh list --all --name 2>/dev/null); then
  if printf '%s\n' "$domains" | grep -Fxq "$vm_name"; then
    echo "High VM $vm_name remains defined; preserving $instance_dir" >&2
    cleanup_failed=1
  fi
else
  echo "could not confirm whether High VM $vm_name remains defined; preserving $instance_dir" >&2
  cleanup_failed=1
fi

if [ "$cleanup_failed" -eq 0 ]; then
  rm -rf -- "$instance_dir" || {
    echo "could not remove High instance files at $instance_dir" >&2
    exit 1
  }
else
  echo "High cleanup was incomplete; instance files were kept so cleanup can be retried" >&2
  exit 1
fi
