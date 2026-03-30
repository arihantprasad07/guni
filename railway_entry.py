import importlib
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CANDIDATES = [
    ("api.main", ROOT / "api" / "main.py"),
    ("api.app", ROOT / "api" / "app.py"),
    ("main", ROOT / "main.py"),
    ("app", ROOT / "app.py"),
]


def _looks_like_wrapper(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        return "AUTO_DETECT_SHIM = True" in path.read_text(encoding="utf-8")
    except OSError:
        return False


def load_application():
    for module_name, module_path in CANDIDATES:
        if not module_path.exists() or _looks_like_wrapper(module_path):
            continue

        module = importlib.import_module(module_name)
        app = getattr(module, "app", None)
        if app is None:
            continue

        app_type = app.__class__.__name__.lower()
        if "fastapi" in app_type:
            return module_name, app, "fastapi"
        if "flask" in app_type:
            return module_name, app, "flask"

    raise RuntimeError("Could not detect a Flask or FastAPI app entrypoint.")


def run_dev_server(module_name: str, app, app_type: str):
    port = int(os.environ.get("PORT", "8000"))
    if app_type == "flask" and hasattr(app, "run"):
        app.run(host="0.0.0.0", port=port)
        return

    import uvicorn
    uvicorn.run(f"{module_name}:app", host="0.0.0.0", port=port)
