"""Bounded RPC transport from the control bridge to the isolated torrent bridge."""
import selectors
import socket
import socketserver
import time


def serve(address):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(("transmission", 9091), timeout=3) as upstream:
                    peers = (self.request, upstream)
                    with selectors.DefaultSelector() as events:
                        for peer in peers:
                            peer.settimeout(3)
                            events.register(peer, selectors.EVENT_READ)
                        deadline = time.monotonic() + 30
                        while time.monotonic() < deadline:
                            for key, _ in events.select(timeout=1):
                                data = key.fileobj.recv(65536)
                                if not data:
                                    return
                                peers[1 if key.fileobj is peers[0] else 0].sendall(data)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        def handle_error(self, *_):
            pass
    return Server((address, 9091), Handler)
