#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
vm_name="hf-high-$instance_id"
sh "$(dirname "$0")/unpublish-ssh.sh" "$instance_id"

if ! virsh dominfo "$vm_name" >/dev/null 2>&1; then
  exit 0
fi
state=$(virsh domstate "$vm_name" 2>/dev/null | tr '[:upper:]' '[:lower:]')
case "$state" in
  *running*|*paused*|*blocked*|*crashed*)
    virsh shutdown "$vm_name" >/dev/null 2>&1 || true
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      state=$(virsh domstate "$vm_name" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
      case "$state" in *shut*|*off*) exit 0 ;; esac
      sleep 3
    done
    virsh destroy "$vm_name" >/dev/null
    ;;
esac
