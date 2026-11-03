#!/bin/sh
# Disposable smoke fixture: model a kernel rejecting the nftables backend.
printf '%s\n' 'iptables: simulated unsupported nftables kernel (test fixture)' >&2
exit 4
