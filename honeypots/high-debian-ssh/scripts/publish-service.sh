#!/bin/sh
exec sh "$(CDPATH= cd -- "$(dirname "$0")/../../high-ubuntu-ssh/scripts" && pwd)/publish-ssh.sh" "$1" "$2" 22
