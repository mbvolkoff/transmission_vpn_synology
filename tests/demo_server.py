"""UI-only test server with fake VPN/RPC services; never used in the image."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.storage import Storage
from app.web import Application, serve
from test_app import FakeGateway, FakeRPC

root = Path(tempfile.mkdtemp(prefix="transmission-ui-test-"))
downloads = root / "downloads"
for name in ("Movies", "Music", "Software"):
    (downloads / name).mkdir(parents=True)
os.environ["PUID"] = str(os.getuid())
os.environ["PGID"] = str(os.getgid())
app = Application(root / "web", Storage(downloads), FakeGateway(), FakeRPC())
# A known setup code for local browser tests only. This server isn't in Docker.
app.accounts.setup_code = "browser-test-code"
print("UI test server: http://127.0.0.1:8765", flush=True)
serve(app, ("127.0.0.1", 8765)).serve_forever()
