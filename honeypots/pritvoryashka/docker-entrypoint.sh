#!/bin/sh
set -eu

state_dir=/var/lib/pritvoryashka
key="$state_dir/host_ed25519"
mkdir -p "$state_dir"
if [ ! -f "$key" ]; then
  umask 077
  ssh-keygen -q -t ed25519 -N '' -f "$key"
fi
exec /usr/local/bin/pritvoryashka "$@"
