#!/bin/sh
exec sh "$(CDPATH= cd -- "$(dirname "$0")/../../high-ubuntu-ssh/scripts" && pwd)/stop.sh" "$@"
