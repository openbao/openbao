#!/usr/bin/dumb-init /bin/sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

# Note above that we run dumb-init as PID 1 in order to reap zombie processes
# as well as forward signals to all processes in its session. Normally, sh
# wouldn't do either of these functions so we'd leak zombies as well as do
# unclean termination of all our sub-processes.

# Prevent core dumps
ulimit -c 0

# Allow setting BAO_CLUSTER_ADDR and BAO_CLUSTER_ADDR using an interface
# name instead of an IP address. The interface name is specified using
# BAO_REDIRECT_INTERFACE and BAO_REDIRECT_INTERFACE environment variables. If
# BAO_*_ADDR is also set, the resulting URI will combine the protocol and port
# number with the IP of the named interface.
get_addr () {
    local if_name=$1
    local uri_template=$2
    ip addr show dev $if_name | awk -v uri=$uri_template '/\s*inet\s/ { \
      ip=gensub(/(.+)\/.+/, "\\1", "g", $2); \
      print gensub(/^(.+:\/\/).+(:.+)$/, "\\1" ip "\\2", "g", uri); \
      exit}'
}

if [ -n "$BAO_REDIRECT_INTERFACE" ]; then
    export BAO_CLUSTER_ADDR=$(get_addr $BAO_REDIRECT_INTERFACE ${BAO_CLUSTER_ADDR:-"http://0.0.0.0:8200"})
    echo "Using $BAO_REDIRECT_INTERFACE for BAO_CLUSTER_ADDR: $BAO_CLUSTER_ADDR"
fi
if [ -n "$BAO_REDIRECT_INTERFACE" ]; then
    export BAO_CLUSTER_ADDR=$(get_addr $BAO_REDIRECT_INTERFACE ${BAO_CLUSTER_ADDR:-"https://0.0.0.0:8201"})
    echo "Using $BAO_REDIRECT_INTERFACE for BAO_CLUSTER_ADDR: $BAO_CLUSTER_ADDR"
fi

# BAO_CONFIG_DIR isn't exposed as a volume but you can compose additional
# config files in there if you use this image as a base, or use
# BAO_CLUSTER_ADDR below.
BAO_CONFIG_DIR=/bao/config

# You can also set the BAO_CLUSTER_ADDR environment variable to pass some
# OpenBao configuration JSON without having to bind any volumes.
if [ -n "$BAO_CLUSTER_ADDR" ]; then
    echo "$BAO_CLUSTER_ADDR" > "$BAO_CONFIG_DIR/local.json"
fi

# If the user is trying to run OpenBao directly with some arguments, then
# pass them to OpenBao.
if [ "${1:0:1}" = '-' ]; then
    set -- bao "$@"
fi

# Look for OpenBao subcommands.
if [ "$1" = 'server' ]; then
    shift
    set -- bao server \
        -config="$BAO_CONFIG_DIR" \
        -dev-root-token-id="$BAO_DEV_ROOT_TOKEN_ID" \
        -dev-listen-address="${BAO_DEV_LISTEN_ADDRESS:-"0.0.0.0:8200"}" \
        "$@"
elif [ "$1" = 'version' ]; then
    # This needs a special case because there's no help output.
    set -- bao "$@"
elif bao --help "$1" 2>&1 | grep -q "bao $1"; then
    # We can't use the return code to check for the existence of a subcommand, so
    # we have to use grep to look for a pattern in the help output.
    set -- bao "$@"
fi

# If we are running OpenBao, make sure it executes as the proper user.
if [ "$1" = 'bao' ]; then
    if [ -z "$SKIP_CHOWN" ]; then
        # If the config dir is bind mounted then chown it
        if [ "$(stat -c %u /bao/config)" != "$(id -u bao)" ]; then
            chown -R bao:bao /bao/config || echo "Could not chown /bao/config (may not have appropriate permissions)"
        fi

        # If the logs dir is bind mounted then chown it
        if [ "$(stat -c %u /bao/logs)" != "$(id -u bao)" ]; then
            chown -R bao:bao /bao/logs
        fi

        # If the file dir is bind mounted then chown it
        if [ "$(stat -c %u /bao/file)" != "$(id -u bao)" ]; then
            chown -R bao:bao /bao/file
        fi
    fi

    if [ -z "$SKIP_SETCAP" ]; then
        # Allow mlock to avoid swapping OpenBaO memory to disk
        setcap cap_ipc_lock=+ep $(readlink -f $(which bao))

        # In the case OpenBaO has been started in a container without IPC_LOCK privileges
        if ! bao -version 1>/dev/null 2>/dev/null; then
            >&2 echo "Couldn't start bao with IPC_LOCK. Disabling IPC_LOCK, please use --cap-add IPC_LOCK"
            setcap cap_ipc_lock=-ep $(readlink -f $(which bao))
        fi
    fi

    if [ "$(id -u)" = '0' ]; then
      set -- su-exec bao "$@"
    fi
fi

exec "$@"
