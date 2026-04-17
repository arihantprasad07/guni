import os
import subprocess
import sys

from railway_entry import load_application


def main() -> int:
    entry_module, app, app_kind = load_application()
    port = os.environ.get("PORT", "8000")

    if app_kind == "flask":
        if hasattr(app, "run"):
            app.run(host="0.0.0.0", port=int(port))
            return 0
        raise RuntimeError("Detected Flask app without a run method.")

    command = [
        "gunicorn",
        f"{entry_module}:app",
        "-k",
        "uvicorn.workers.UvicornWorker",
        "--bind",
        f"0.0.0.0:{port}",
    ]
    return subprocess.call(command)


if __name__ == "__main__":
    sys.exit(main())
