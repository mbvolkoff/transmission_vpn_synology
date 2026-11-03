import json
import os
from pathlib import Path
import subprocess
import sys

from .common import UserError, storage_ids


class Storage:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def resolve(self, relative):
        if not isinstance(relative, str) or "\0" in relative or Path(relative).is_absolute():
            raise UserError("Choose a folder from the folder picker.")
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root) or not path.is_dir():
            raise UserError("That folder is outside the storage available to this app.")
        return path

    def list(self, relative=""):
        path = self.resolve(relative)
        try:
            directories = sorted(
                entry.name for entry in path.iterdir()
                if not entry.name.startswith(".") and entry.is_dir()
                and entry.resolve().is_relative_to(self.root)
            )[:200]
        except PermissionError:
            raise UserError("This folder cannot be opened. Ask your DSM administrator to grant access.") from None
        return {"path": str(path.relative_to(self.root)), "folders": directories}

    def _as_download_user(self, script, path):
        uid, gid = storage_ids()
        arguments = {}
        if os.geteuid() == 0:
            arguments = {"user": uid, "group": gid, "extra_groups": []}
        result = subprocess.run([sys.executable, "-c", script, str(path)], capture_output=True, timeout=10, **arguments)
        if result.returncode:
            raise UserError("The download user cannot write here. Ask your DSM administrator to grant this app read/write access to the folder.")

    def check_writable(self, relative):
        path = self.resolve(relative)
        self._as_download_user(
            "import sys,tempfile; f=tempfile.TemporaryFile(dir=sys.argv[1]); f.write(b'ok'); f.close()", path
        )
        return str(path.relative_to(self.root))

    def create(self, relative, name):
        if not isinstance(name, str) or not name.strip() or name in (".", "..") or any(c in name for c in "/\\\0") or len(name) > 100:
            raise UserError("Enter a folder name without slashes.")
        path = self.resolve(relative) / name
        if path.exists():
            raise UserError("A folder with that name already exists.")
        self._as_download_user("import os,sys; os.umask(0o002); os.mkdir(sys.argv[1],0o775)", path)
        return self.list(str(path.relative_to(self.root)))
