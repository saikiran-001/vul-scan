"""
run.py -- the one command that starts everything.

    python run.py                 # http://127.0.0.1:8000, opens your browser
    python run.py --no-open       # do not open a browser
    python run.py --port 9000     # different port
    python run.py --reload        # auto-restart when you edit a .py file (dev mode)

Under the hood this starts Flask's built-in server with threading enabled,
which is enough for local use and a demo deployment. For a public server put
waitress (Windows) or gunicorn (Linux) in front of api.main:app instead.
"""

import argparse                     # command line flags
import os                           # PORT / HOST environment variables (Render sets PORT)
import threading                    # used to open the browser shortly after start
import webbrowser                   # opens the default browser
from pathlib import Path            # to check that web/index.html exists

BANNER = r"""
 __     __    _       ____                  _     _     _ _
 \ \   / /   | |     / ___|  ___ __ _ _ __ | |   (_) __| (_)
  \ \ / /   _| |    \___ \ / __/ _` | '_ \| |   | |/ _` | |_
   \ V /  |_| |     ___) | (_| (_| | | | | |___| | (_| |  _|
    \_/    \__|_|   |____/ \___\__,_|_| |_|_____|_|\__,_|_|
"""

DISCLAIMER = "Only scan websites you own. This tool performs passive analysis only."


def main() -> None:
    """Parse arguments and start the Flask server."""

    parser = argparse.ArgumentParser(description="Start the VulnScan Lite web app.")
    # HOST/PORT are read from the environment so hosting platforms that inject
    # PORT (Render, Railway, Fly.io) can start this file directly.
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"),
                        help="interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")),
                        help="port to listen on (default 8000, or $PORT)")
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    parser.add_argument("--no-open", action="store_true", help="do not open the browser")
    args = parser.parse_args()

    index_file = Path(__file__).parent / "web" / "index.html"    # sanity check
    if not index_file.exists():
        print("web/index.html is missing -- the API will run but the UI will not load.")

    url = f"http://{args.host}:{args.port}"                      # what the user should open

    print(BANNER)
    print(f"  {DISCLAIMER}")
    print("")
    print(f"  Local URL   : {url}")
    print(f"  API health  : {url}/api/health")
    print("")
    print("  Press Ctrl+C to stop the server.")
    print("")

    if not args.no_open:                                         # open the browser for them
        # Wait ~1.2s so the server has a chance to bind the port first.
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()

    # Import AFTER the banner so the first import errors are readable.
    from api.main import app

    # threaded=True is important: while one request polls a scan, another
    # request must still be able to reach the API.
    app.run(
        host=args.host,
        port=args.port,
        debug=args.reload,          # debug mode also enables the auto-reloader
        use_reloader=args.reload,
        threaded=True,
    )


if __name__ == "__main__":
    main()
