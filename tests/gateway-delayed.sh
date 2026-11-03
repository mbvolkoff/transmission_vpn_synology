#!/bin/sh
# Test-only: expose the fresh-namespace startup window before Python installs
# any firewall. A valid old daemon lease must not permit physical forwarding.
sleep 5
exec python3 -m app.gateway
