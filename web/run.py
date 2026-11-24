import os

from app import app


if __name__ == "__main__":
    flask_app = app.create_app()
    debug_mode = os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}
    flask_app.run(host="0.0.0.0", port=8000, debug=debug_mode)
