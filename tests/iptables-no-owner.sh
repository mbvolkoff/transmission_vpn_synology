#!/bin/sh
# Simulate a NAS without xt_owner, while using a real firewall for all tests.
for argument do
  case "$argument" in owner|--uid-owner|--gid-owner) echo 'owner match unavailable in this test' >&2; exit 3 ;; esac
done
case "${0##*/}" in
  iptables-legacy) exec /usr/sbin/iptables-legacy "$@" ;;
  *) exec /usr/sbin/iptables "$@" ;;
esac
