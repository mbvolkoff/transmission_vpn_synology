import sys
from urllib.request import urlopen

from .common import UserError, service_token

def healthy(target):
    try:
        if target == "transmission":
            from .transmission import supervisor_healthy
            ready = supervisor_healthy("/run/transmission-vpn/supervisor.json", "/control", service_token("/control"))
        else:
            with urlopen(target, timeout=3) as response:
                ready = response.status == 200
        if not ready:
            print("Health check failed: service is not ready", file=sys.stderr)
        return ready
    except (OSError, UserError) as exc:
        # Health output is available through Docker inspect. Do not print
        # request credentials, response bodies or service tokens there.
        reason = f"HTTP {exc.code}" if hasattr(exc, "code") else type(exc).__name__
        print("Health check failed: " + reason, file=sys.stderr)
        return False


if __name__ == "__main__":
    sys.exit(0 if healthy(sys.argv[1]) else 1)
