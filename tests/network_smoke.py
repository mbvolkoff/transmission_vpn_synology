"""Real routed TCP/UDP and outage tests; isolated tvpn-smoke project only.

The fixture interface called tun0 is an Ethernet test interface, not a real VPN.
It tests the kernel forwarding/guard/NAT path without any external network.
"""
import json
import select
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-p", "tvpn-smoke", "-f", str(ROOT / "compose.yaml"),
           "-f", str(ROOT / "tests/compose.smoke.yaml")]
FIXTURE = "tvpn-smoke-vpn-fixture"
SINK = "tvpn-smoke-sink"


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError("docker " + " ".join(args[:3]) + ": " + result.stderr)
    return result


def compose(*args, check=True):
    return subprocess.run([*COMPOSE, *args], capture_output=True, text=True, check=check)


def execute(service, code):
    return compose("exec", "-T", service, "python3", "-c", code).stdout.strip()


def protected(*args, check=True):
    return compose("exec", "-T", "--user", "1000:1000", "transmission", *args, check=check)


def curl(service, url, check=True):
    return compose("exec", "-T", service, "curl", "--noproxy", "*", "--fail", "--silent",
                   "--max-time", "2", url, check=check)


def client(url, allowed):
    response = protected("curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "2", url, check=False)
    assert (response.returncode == 0) == allowed, f"unexpected route result: {url} {response.returncode}"
    return response.stdout


SERVER = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket, socketserver, threading
class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write((self.client_address[0] if self.path == '/ip' else 'ok').encode())
    def log_message(self, *_): pass
class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        while line := self.rfile.readline():
            self.wfile.write(line)
            self.wfile.flush()
tcp = socketserver.ThreadingTCPServer(('0.0.0.0', 18083), Echo)
tcp.daemon_threads = True
threading.Thread(target=tcp.serve_forever, daemon=True).start()
def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 18084))
    while True:
        data, peer = sock.recvfrom(1024)
        sock.sendto(data, peer)
threading.Thread(target=udp, daemon=True).start()
ThreadingHTTPServer(('0.0.0.0', 18082), HTTP).serve_forever()
'''
UDP = r'''
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(b'probe', ('198.18.86.2', 18084))
try:
    assert s.recv(128) == b'probe'
except TimeoutError:
    sys.exit(43)
'''


def gate(allowed):
    execute("gateway", f'''
from app.common import read_json
from app.gateway import Controller
state = read_json('/vpn/firewall.json')
c = Controller.__new__(Controller)
c.guard_ready, c.traffic_allowed = True, {not allowed!r}
c.network = {{'inside': state['interface']}}
c.firewall_binary, c.tunnel_chain = state['binary'], state['gate']
c._set_traffic({allowed!r}, force=True)
''')


def publish(allowed):
    execute("gateway", f'''
from app.common import service_token
from app.permit import publish
publish('/control', service_token('/control'), {allowed!r}, 'routed-smoke', '198.18.86.3')
''')


def wait_state(expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        state = json.loads(execute("transmission", "from pathlib import Path; print(Path('/run/transmission-vpn/supervisor.json').read_text())"))
        if state["state"] == expected:
            return
        time.sleep(0.25)
    raise AssertionError(f"Supervisor did not reach {expected}")


gateway = compose("ps", "-q", "gateway").stdout.strip()
assert gateway
live = None
try:
    gate(False)
    publish(False)
    wait_state("waiting_for_vpn")
    docker("network", "create", "--internal", "--subnet", "198.18.86.0/24", FIXTURE)
    docker("run", "--rm", "-d", "--name", SINK, "--network", FIXTURE, "--ip", "198.18.86.2",
           "--entrypoint", "python3", "transmission-vpn:local", "-u", "-c", SERVER)
    docker("network", "connect", "tvpn-smoke_control", SINK)
    docker("network", "connect", "tvpn-smoke_torrent", SINK)
    docker("network", "connect", "--ip", "198.18.86.3", FIXTURE, gateway)
    network = json.loads(docker("inspect", SINK).stdout)[0]["NetworkSettings"]["Networks"]
    physical_peer = network["tvpn-smoke_control"]["IPAddress"]
    direct_peer = network["tvpn-smoke_torrent"]["IPAddress"]
    execute("gateway", '''
import json, subprocess
interfaces = json.loads(subprocess.check_output(['ip','-j','-4','address']))
name = next(i['ifname'] for i in interfaces if any(a.get('local') == '198.18.86.3' for a in i.get('addr_info', [])))
subprocess.run(['ip','link','set',name,'down'], check=True)
subprocess.run(['ip','link','set',name,'name','tun0'], check=True)
subprocess.run(['ip','link','set','tun0','up'], check=True)
''')
    target = "http://198.18.86.2:18082"
    assert curl("gateway", target).stdout == "ok"
    publish(True)
    wait_state("running")
    client(target, False)  # Even a valid lease cannot bypass the closed gate.
    gate(True)
    assert client(target, True) == "ok"
    assert client(target + "/ip", True) == "198.18.86.3", "VPN-side source NAT failed"
    protected("python3", "-c", UDP)
    client(f"http://{direct_peer}:18082", False)
    # Private agent/RPC relay initiation from the torrent bridge is forbidden.
    router = json.loads(execute("gateway", "from app.common import read_json; print(__import__('json').dumps(read_json('/control/router.json')['router']))"))
    for port in (8081, 9091):
        client(f"http://{router['address']}:{port}/health", False)
    # Explicit Docker DNS requests are blocked, not just /etc/resolv.conf usage.
    dns = r'''
import errno, socket, sys
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(bytes.fromhex('abcd01000001000000000000') + b'\x03web\0\0\x01\0\x01', ('127.0.0.11',53))
    s.recv(512)
except TimeoutError: sys.exit(43)
except OSError as exc:
    if exc.errno in (errno.EPERM, errno.EACCES): sys.exit(43)
    raise
sys.exit(0)
'''
    blocked_dns = protected("python3", "-c", dns, check=False)
    assert blocked_dns.returncode == 43, "Docker DNS bypass was not blocked"
    # The supervisor and its daemon cannot change routes or use raw sockets.
    execute("transmission", '''
from pathlib import Path
lines=Path('/proc/1/status').read_text().splitlines()
for field in ('CapEff:', 'CapPrm:', 'CapBnd:'):
    cap=int(next(line.split()[1] for line in lines if line.startswith(field)), 16)
    assert not cap & ((1<<12)|(1<<13)), 'Network capability retained'
''')
    code = r'''
import socket, sys
s=socket.create_connection(('198.18.86.2',18083),timeout=2)
for line in sys.stdin:
    try:
        s.sendall(line.encode()); data=s.recv(1024)
        print('OK' if data == line.encode() else 'BLOCKED', flush=True)
    except OSError: print('BLOCKED',flush=True)
'''
    live = subprocess.Popen([*COMPOSE, "exec", "-T", "--user", "1000:1000", "transmission", "python3", "-u", "-c", code],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    def stream_reply():
        assert select.select([live.stdout], [], [], 8)[0], "TCP fixture did not respond"
        return live.stdout.readline().strip()
    live.stdin.write("before\n"); live.stdin.flush()
    assert stream_reply() == "OK"
    outside = router["outside"]
    compose("exec", "-T", "gateway", "ip", "route", "replace", "198.18.86.2/32", "via", physical_peer, "dev", outside)
    # The SAME destination is reachable through the ordinary physical interface.
    assert curl("gateway", target).stdout == "ok"
    live.stdin.write("fallback\n"); live.stdin.flush()
    assert stream_reply() == "BLOCKED", "Established TCP session leaked on route fallback"
    client(target, False)
    assert protected("python3", "-c", UDP, check=False).returncode == 43
    compose("exec", "-T", "gateway", "ip", "route", "del", "198.18.86.2/32")
    assert client(target, True) == "ok"
    gate(False)
    client(target, False)
    assert curl("gateway", target).stdout == "ok"
    # Crash without revocation while the real daemon still has a valid lease.
    # The fixture delays Python by five seconds: no firewall exists yet in the
    # new namespace, so its initial per-interface forwarding MUST remain off.
    gate(True)
    publish(True)
    wait_state("running")
    compose("kill", "-s", "KILL", "gateway")
    compose("start", "gateway")
    execute("gateway", '''
from pathlib import Path
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '0'
for path in Path('/proc/sys/net/ipv4/conf').glob('eth*/forwarding'):
    assert path.read_text().strip() == '0', 'Fresh namespace forwards before the guard'
''')
    state = json.loads(execute("transmission", "from pathlib import Path; print(Path('/run/transmission-vpn/supervisor.json').read_text())"))
    assert state["state"] == "running", "Crash test did not retain a live old daemon lease"
    client(target, False)
    wait_state("waiting_for_vpn")
    assert curl("gateway", target).stdout == "ok", "Physical control path disappeared"
    print("Routed smoke passed: real TCP/UDP forwarding and NAT; closed gate; DNS/bridge/API blocking; dropped capabilities; established TCP route fallback with working physical control; recovery; explicit close; gateway restart. VPN transport was simulated.")
finally:
    if live:
        live.communicate(timeout=5)
    try:
        gate(False)
        publish(False)
    except subprocess.SubprocessError:
        pass
    compose("exec", "-T", "gateway", "ip", "route", "del", "198.18.86.2/32", check=False)
    # Restore Docker's endpoint name before detaching the simulated tunnel.
    # Docker stores its original interface name independently of ip-link rename.
    compose("exec", "-T", "gateway", "ip", "link", "set", "tun0", "down", check=False)
    compose("exec", "-T", "gateway", "ip", "link", "set", "tun0", "name", "eth2", check=False)
    docker("network", "disconnect", "-f", FIXTURE, gateway, check=False)
    docker("rm", "-f", SINK, check=False)
    docker("network", "rm", FIXTURE, check=False)
